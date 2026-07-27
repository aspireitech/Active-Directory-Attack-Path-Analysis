#Requires -Version 5.1
<#
.SYNOPSIS
    Standalone scanner that finds Active Directory security gaps across four areas:
    ACL/inheritance exposure, password-not-required/weak password controls, privilege
    escalation paths to Domain Admin equivalence, and protected-container (Tier-0)
    misconfiguration.

.DESCRIPTION
    Read-only scan. Each category is written to its own CSV ("source") in -OutputPath.
    Run New-SecurityGapsDashboard.ps1 afterwards (or any time later) against the same
    folder to merge every CSV it finds into a single ranked Top-N dashboard.

    Categories and output files:
      - ACL_Inheritance_Gaps.csv        Inheritance state + risky ACEs on Tier-0 objects/OUs
      - Password_Security_Gaps.csv      PasswordNotRequired, AS-REP roastable, never-expires, etc.
      - Privilege_Escalation_Paths.csv  Non-admins who can reach Domain Admin equivalence
      - Protected_Container_Misconfig.csv  AdminSDHolder / Tier-0 container issues

.PARAMETER OutputPath
    Folder to write the category CSVs to. Defaults to .\Output next to this script.

.PARAMETER Server
    Specific domain controller to query. Defaults to the discoverable DC for the current context.

.PARAMETER Credential
    PSCredential to use for AD queries. Defaults to the current user context.

.PARAMETER StaleDays
    Days since last password change before a privileged account is considered stale. Default 180.

.PARAMETER MaxOUsToScan
    Safety cap on how many OUs are pulled for the ACL-inheritance sweep. Default 500.

.EXAMPLE
    .\Find-TopADSecurityGaps.ps1

.EXAMPLE
    .\Find-TopADSecurityGaps.ps1 -OutputPath D:\ADScan -Server dc01.contoso.com

.EXAMPLE
    $cred = Get-Credential
    .\Find-TopADSecurityGaps.ps1 -Credential $cred -OutputPath D:\ADScan
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Output'),
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$StaleDays = 180,
    [int]$MaxOUsToScan = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Bootstrap

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory PowerShell module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 (or Install-WindowsFeature RSAT-AD-PowerShell on a server)."
}
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$adParams = @{}
if ($Server)     { $adParams['Server']     = $Server }
if ($Credential) { $adParams['Credential'] = $Credential }

function Write-Status {
    param([string]$Message, [ValidateSet('Info','Ok','Warn')] [string]$Level = 'Info')
    $color = switch ($Level) { 'Ok' { 'Green' } 'Warn' { 'Yellow' } default { 'Cyan' } }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $color
}

Write-Status "Connecting to Active Directory..."
$domain    = Get-ADDomain @adParams
$domainDN  = $domain.DistinguishedName
$netbios   = $domain.NetBIOSName
$dnsRoot   = $domain.DNSRoot
$scanDate  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Status "Domain: $dnsRoot  ($domainDN)" -Level Ok

#endregion

#region Shared helpers

# Well-known / expected trustees on Tier-0 objects. Anything outside this list showing up
# with write-ish rights on a protected object is worth a human looking at.
$script:SafePrincipals = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators',
    "$netbios\Domain Admins",
    "$netbios\Enterprise Admins",
    "$netbios\Schema Admins",
    'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
    'CREATOR OWNER'
)

# Rights that matter for "who can take over this object" style checks.
$script:DangerousRights = [System.DirectoryServices.ActiveDirectoryRights]'GenericAll,GenericWrite,WriteDacl,WriteOwner'

# Extended-right GUIDs worth naming explicitly instead of lumping under "ExtendedRight".
$script:ExtendedRightNames = @{
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All (DCSync)'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes (DCSync)'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set (DCSync)'
}

$script:PrivilegedGroupNames = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
    'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
    'DnsAdmins', 'Group Policy Creator Owners', 'Cert Publishers',
    'Key Admins', 'Enterprise Key Admins'
)

function Get-Severity {
    param([int]$Score)
    if ($Score -ge 90) { return 'Critical' }
    if ($Score -ge 70) { return 'High' }
    if ($Score -ge 40) { return 'Medium' }
    return 'Low'
}

function New-GapFinding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$AffectedObject,
        [string]$ObjectType,
        [string]$Details,
        [string]$Recommendation,
        [int]$RiskScore,
        [string]$MitreID = ''
    )
    $score = [Math]::Min(100, [Math]::Max(0, $RiskScore))
    [PSCustomObject]@{
        Category       = $Category
        Severity       = Get-Severity -Score $score
        RiskScore      = $score
        Finding        = $Finding
        AffectedObject = $AffectedObject
        ObjectType     = $ObjectType
        Details        = $Details
        Recommendation = $Recommendation
        MitreID        = $MitreID
        DomainName     = $dnsRoot
        ScanDate       = $scanDate
    }
}

function Test-SafePrincipal {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $true }
    return ($script:SafePrincipals -contains $Identity)
}

function Get-ObjectAcl {
    param([string]$DistinguishedName)
    try {
        return Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    } catch {
        Write-Status "Could not read ACL for $DistinguishedName : $($_.Exception.Message)" -Level Warn
        return $null
    }
}

#endregion

#region Category 1: ACL Inheritance Gaps

Write-Status "Scanning ACL inheritance on Tier-0 objects..."
$aclFindings = [System.Collections.Generic.List[object]]::new()

# Tier-0 objects that should have inheritance BLOCKED. If inheritance is enabled on one of
# these, it can silently pick up permissive ACEs from a parent OU/container.
$tier0Targets = [System.Collections.Generic.List[object]]::new()
$tier0Targets.Add([pscustomobject]@{ Name = 'Domain Root'; DN = $domainDN; Type = 'Domain' })
try {
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    $tier0Targets.Add([pscustomobject]@{ Name = 'AdminSDHolder'; DN = $adminSDHolderDN; Type = 'Container' })
} catch {}

try {
    Get-ADOrganizationalUnit -Filter "Name -eq 'Domain Controllers'" @adParams | ForEach-Object {
        $tier0Targets.Add([pscustomobject]@{ Name = $_.Name; DN = $_.DistinguishedName; Type = 'OU' })
    }
} catch {}

foreach ($groupName in $script:PrivilegedGroupNames) {
    try {
        $g = Get-ADGroup -Identity $groupName @adParams -ErrorAction Stop
        $tier0Targets.Add([pscustomobject]@{ Name = $groupName; DN = $g.DistinguishedName; Type = 'Group' })
    } catch { }
}

foreach ($target in $tier0Targets) {
    $acl = Get-ObjectAcl -DistinguishedName $target.DN
    if (-not $acl) { continue }

    if (-not $acl.AreAccessRulesProtected) {
        $aclFindings.Add((New-GapFinding -Category 'ACL Inheritance' `
            -Finding 'Inheritance enabled on Tier-0 object' `
            -AffectedObject $target.Name -ObjectType $target.Type `
            -Details "'$($target.Name)' ($($target.DN)) inherits ACEs from its parent container instead of using a protected/explicit ACL." `
            -Recommendation 'Tier-0 objects (AdminSDHolder, privileged groups, Domain Controllers OU, domain root) should block inheritance so a permissive change higher in the tree cannot silently grant access here. Verify SDProp is running and investigate why inheritance was re-enabled.' `
            -RiskScore 72 -MitreID 'T1484.001'))
    }

    foreach ($ace in $acl.Access) {
        $identity = $ace.IdentityReference.Value
        if (Test-SafePrincipal -Identity $identity) { continue }
        if ($ace.AccessControlType -ne 'Allow') { continue }

        $rightsHit = $ace.ActiveDirectoryRights -band $script:DangerousRights
        $extRightName = $null
        if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight') {
            $guid = $ace.ObjectType.ToString()
            if ($script:ExtendedRightNames.ContainsKey($guid)) { $extRightName = $script:ExtendedRightNames[$guid] }
        }

        if ($rightsHit -ne 0 -or $extRightName) {
            $rightDesc = if ($extRightName) { $extRightName } else { $rightsHit.ToString() }
            $isDcSync = $extRightName -like '*DCSync*'
            $score = if ($isDcSync) { 96 } elseif ($rightsHit -band [System.DirectoryServices.ActiveDirectoryRights]'GenericAll') { 90 } else { 78 }
            $aclFindings.Add((New-GapFinding -Category 'ACL Inheritance' `
                -Finding "Unexpected '$rightDesc' grant on Tier-0 object" `
                -AffectedObject $target.Name -ObjectType $target.Type `
                -Details "'$identity' holds '$rightDesc' on '$($target.Name)' ($($target.DN)). Inherited=$($ace.IsInherited)." `
                -Recommendation "Confirm '$identity' should hold this right on a Tier-0 object. If not required, remove the ACE. This principal may be able to take over the object and, from it, Domain Admin equivalence." `
                -RiskScore $score -MitreID $(if ($isDcSync) { 'T1003.006' } else { 'T1222' })))
        }
    }
}

# Broader sweep: OUs that inherit dangerous rights down to low-privilege identities
# (Domain Users / Authenticated Users / Everyone with write-ish rights).
Write-Status "Scanning OU delegation for over-permissive inherited ACEs..."
$broadIdentities = @("$netbios\Domain Users", 'Everyone', 'NT AUTHORITY\Authenticated Users', "$netbios\Domain Computers")
try {
    $allOUs = Get-ADOrganizationalUnit -Filter * @adParams -Properties DistinguishedName
    if ($allOUs.Count -gt $MaxOUsToScan) {
        Write-Status "Domain has $($allOUs.Count) OUs, exceeding -MaxOUsToScan ($MaxOUsToScan). Scanning the first $MaxOUsToScan only." -Level Warn
        $allOUs = $allOUs | Select-Object -First $MaxOUsToScan
    }
    foreach ($ou in $allOUs) {
        $acl = Get-ObjectAcl -DistinguishedName $ou.DistinguishedName
        if (-not $acl) { continue }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($broadIdentities -notcontains $ace.IdentityReference.Value) { continue }
            $rightsHit = $ace.ActiveDirectoryRights -band $script:DangerousRights
            if ($rightsHit -eq 0) { continue }
            $aclFindings.Add((New-GapFinding -Category 'ACL Inheritance' `
                -Finding "Broad identity holds '$rightsHit' on OU" `
                -AffectedObject $ou.DistinguishedName -ObjectType 'OU' `
                -Details "'$($ace.IdentityReference.Value)' has '$rightsHit' on '$($ou.DistinguishedName)'. Inherited=$($ace.IsInherited). Any object created under this OU inherits the exposure." `
                -Recommendation 'Broad/default identities (Domain Users, Authenticated Users, Everyone, Domain Computers) should not hold write-ish rights on an OU. Scope delegation to a specific admin group instead.' `
                -RiskScore 65 -MitreID 'T1484.001'))
        }
    }
} catch {
    Write-Status "OU sweep skipped: $($_.Exception.Message)" -Level Warn
}

Write-Status "ACL inheritance findings: $($aclFindings.Count)" -Level Ok

#endregion

#region Category 2: Password Security Gaps

Write-Status "Scanning password controls..."
$pwdFindings = [System.Collections.Generic.List[object]]::new()

$userProps = @('PasswordNotRequired','PasswordNeverExpires','Enabled','AdminCount','DoesNotRequirePreAuth',
               'AllowReversiblePasswordEncryption','PasswordLastSet','LastLogonDate','ServicePrincipalName')
$allUsers = Get-ADUser -Filter * -Properties $userProps @adParams

foreach ($u in $allUsers) {
    $isPriv = $u.AdminCount -eq 1

    if ($u.PasswordNotRequired -and $u.Enabled) {
        $pwdFindings.Add((New-GapFinding -Category 'Password Security' `
            -Finding 'Password not required' `
            -AffectedObject $u.SamAccountName -ObjectType 'User' `
            -Details "PASSWD_NOTREQD flag is set on an enabled account. An empty password may be accepted." `
            -Recommendation 'Clear the "Password not required" flag and force a compliant password reset.' `
            -RiskScore $(if ($isPriv) { 97 } else { 80 }) -MitreID 'T1110'))
    }

    if ($u.DoesNotRequirePreAuth -and $u.Enabled) {
        $pwdFindings.Add((New-GapFinding -Category 'Password Security' `
            -Finding 'Kerberos pre-authentication disabled (AS-REP roastable)' `
            -AffectedObject $u.SamAccountName -ObjectType 'User' `
            -Details 'DONT_REQ_PREAUTH is set. An attacker can request a TGT for this account with no credentials and crack the returned hash offline.' `
            -Recommendation 'Re-enable Kerberos pre-authentication unless there is a documented, reviewed reason it is disabled.' `
            -RiskScore $(if ($isPriv) { 95 } else { 78 }) -MitreID 'T1558.004'))
    }

    if ($u.AllowReversiblePasswordEncryption -and $u.Enabled) {
        $pwdFindings.Add((New-GapFinding -Category 'Password Security' `
            -Finding 'Reversible password encryption enabled' `
            -AffectedObject $u.SamAccountName -ObjectType 'User' `
            -Details 'Password is stored using reversible (effectively plaintext-equivalent) encryption.' `
            -Recommendation 'Disable "Store password using reversible encryption" and rotate the account password.' `
            -RiskScore $(if ($isPriv) { 88 } else { 70 }) -MitreID 'T1003'))
    }

    if ($u.PasswordNeverExpires -and $u.Enabled) {
        $pwdFindings.Add((New-GapFinding -Category 'Password Security' `
            -Finding 'Password never expires' `
            -AffectedObject $u.SamAccountName -ObjectType 'User' `
            -Details 'Account password has no expiration; a compromised credential remains valid indefinitely.' `
            -Recommendation 'Remove the never-expires flag and bring the account under the standard password/rotation policy, or move it to a managed service account (gMSA).' `
            -RiskScore $(if ($isPriv) { 68 } else { 35 }) -MitreID 'T1078'))
    }

    if ($u.Enabled -and $u.PasswordLastSet -and $isPriv) {
        $ageDays = (New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days
        if ($ageDays -ge $StaleDays) {
            $pwdFindings.Add((New-GapFinding -Category 'Password Security' `
                -Finding 'Stale privileged account password' `
                -AffectedObject $u.SamAccountName -ObjectType 'User' `
                -Details "Privileged account (AdminCount=1) password last changed $ageDays days ago (threshold: $StaleDays)." `
                -Recommendation 'Rotate privileged account credentials on a short cycle; consider tiered/PAW admin accounts with a break-glass rotation policy.' `
                -RiskScore 55 -MitreID 'T1078.002'))
        }
    }

    if ($u.ServicePrincipalName -and $u.ServicePrincipalName.Count -gt 0 -and $u.Enabled -and $isPriv) {
        $pwdFindings.Add((New-GapFinding -Category 'Password Security' `
            -Finding 'Kerberoastable privileged account' `
            -AffectedObject $u.SamAccountName -ObjectType 'User' `
            -Details "Privileged account (AdminCount=1) has SPN(s) set: $($u.ServicePrincipalName -join '; '). Any authenticated user can request a service ticket and crack it offline." `
            -Recommendation 'Move the SPN to a dedicated non-privileged service account, or use a gMSA. If it must stay, enforce a long random password and AES-only Kerberos encryption.' `
            -RiskScore 93 -MitreID 'T1558.003'))
    }
}

Write-Status "Password security findings: $($pwdFindings.Count)" -Level Ok

#endregion

#region Category 3: Privilege Escalation Paths

Write-Status "Scanning privilege escalation paths to Domain Admin equivalence..."
$privFindings = [System.Collections.Generic.List[object]]::new()

foreach ($groupName in $script:PrivilegedGroupNames) {
    $group = $null
    try { $group = Get-ADGroup -Identity $groupName -Properties Members @adParams } catch { continue }

    # Direct membership: flag nested groups (indirect grant, easy to lose track of).
    foreach ($memberDN in $group.Members) {
        try {
            $obj = Get-ADObject -Identity $memberDN -Properties objectClass @adParams
        } catch { continue }
        if ($obj.ObjectClass -eq 'group') {
            $nestedCount = 0
            try { $nestedCount = (Get-ADGroupMember -Identity $memberDN -Recursive @adParams -ErrorAction SilentlyContinue | Measure-Object).Count } catch {}
            $privFindings.Add((New-GapFinding -Category 'Privilege Escalation' `
                -Finding "Nested group grants '$groupName' equivalence" `
                -AffectedObject $obj.Name -ObjectType 'Group' `
                -Details "Group '$($obj.Name)' is a direct member of '$groupName', granting its $nestedCount effective member(s) Domain Admin-tier rights indirectly." `
                -Recommendation "Avoid nesting groups inside $groupName. Add individually reviewed accounts directly, or restructure so membership stays auditable." `
                -RiskScore 80 -MitreID 'T1078.002'))
        }
    }

    # ACL on the privileged group object itself: who can add members / take it over?
    $acl = Get-ObjectAcl -DistinguishedName $group.DistinguishedName
    if ($acl) {
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.Value
            if (Test-SafePrincipal -Identity $identity) { continue }
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $canWriteMembers = ($ace.ActiveDirectoryRights -band $script:DangerousRights) -ne 0
            $isSelfMembership = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]'Self') -ne 0

            if ($canWriteMembers -or $isSelfMembership) {
                $rightDesc = $ace.ActiveDirectoryRights.ToString()
                $privFindings.Add((New-GapFinding -Category 'Privilege Escalation' `
                    -Finding "Non-privileged principal can modify '$groupName'" `
                    -AffectedObject $groupName -ObjectType 'Group' `
                    -Details "'$identity' holds '$rightDesc' on '$groupName'. This can allow adding an arbitrary account (including itself) directly into a Domain Admin-tier group." `
                    -Recommendation "Remove this ACE unless it is an explicitly approved delegation. A regular user or low-privilege service account should never be able to write to $groupName." `
                    -RiskScore 98 -MitreID 'T1098.007'))
            }
        }
    }
}

# Privileged user objects: who can compromise the account directly (reset password / own it)?
$privUsers = Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } -Properties AdminCount, MemberOf @adParams
foreach ($pu in $privUsers) {
    $acl = Get-ObjectAcl -DistinguishedName $pu.DistinguishedName
    if (-not $acl) { continue }
    foreach ($ace in $acl.Access) {
        $identity = $ace.IdentityReference.Value
        if (Test-SafePrincipal -Identity $identity) { continue }
        if ($identity -eq $pu.SamAccountName) { continue }
        if ($ace.AccessControlType -ne 'Allow') { continue }

        $rightsHit = $ace.ActiveDirectoryRights -band $script:DangerousRights
        $forceChangePwd = $false
        if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight') {
            $guid = $ace.ObjectType.ToString()
            if ($script:ExtendedRightNames.ContainsKey($guid) -and $script:ExtendedRightNames[$guid] -like 'User-Force-Change-Password*') {
                $forceChangePwd = $true
            }
        }

        if ($rightsHit -ne 0 -or $forceChangePwd) {
            $rightDesc = if ($forceChangePwd) { 'Reset Password' } else { $rightsHit.ToString() }
            $privFindings.Add((New-GapFinding -Category 'Privilege Escalation' `
                -Finding "Non-privileged principal can compromise privileged account" `
                -AffectedObject $pu.SamAccountName -ObjectType 'User' `
                -Details "'$identity' holds '$rightDesc' on privileged user '$($pu.SamAccountName)' (AdminCount=1). This is a direct one-hop path to Domain Admin equivalence." `
                -Recommendation "Remove this ACE. Privileged accounts should only be modifiable by Tier-0 administrators / AdminSDHolder-protected groups." `
                -RiskScore 96 -MitreID 'T1098'))
        }
    }
}

# Unconstrained delegation on non-DC computers.
try {
    $uncDComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, PrimaryGroupID @adParams
    foreach ($c in $uncDComputers) {
        if ($c.PrimaryGroupID -eq 516) { continue } # Domain Controllers
        $privFindings.Add((New-GapFinding -Category 'Privilege Escalation' `
            -Finding 'Unconstrained delegation on non-DC computer' `
            -AffectedObject $c.Name -ObjectType 'Computer' `
            -Details "'$($c.Name)' is trusted for unconstrained delegation. If a privileged account authenticates to it, its TGT can be extracted and replayed as that account." `
            -Recommendation 'Switch to constrained delegation (or resource-based constrained delegation) and remove the unconstrained delegation flag.' `
            -RiskScore 89 -MitreID 'T1558.001'))
    }
} catch {
    Write-Status "Unconstrained delegation sweep skipped: $($_.Exception.Message)" -Level Warn
}

Write-Status "Privilege escalation findings: $($privFindings.Count)" -Level Ok

#endregion

#region Category 4: Protected Container Misconfiguration

Write-Status "Scanning protected/Tier-0 container configuration..."
$containerFindings = [System.Collections.Generic.List[object]]::new()

# AdminSDHolder ACE audit against the safe allowlist (the template every protected account inherits from).
try {
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    $acl = Get-ObjectAcl -DistinguishedName $adminSDHolderDN
    if ($acl) {
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.Value
            if (Test-SafePrincipal -Identity $identity) { continue }
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $rightsHit = $ace.ActiveDirectoryRights -band $script:DangerousRights
            if ($rightsHit -eq 0) { continue }
            $containerFindings.Add((New-GapFinding -Category 'Protected Container' `
                -Finding "Unexpected trustee on AdminSDHolder" `
                -AffectedObject 'AdminSDHolder' -ObjectType 'Container' `
                -Details "'$identity' holds '$rightsHit' on AdminSDHolder. Every protected (AdminCount=1) account inherits this template via SDProp roughly every 60 minutes -- this is a domain-wide backdoor if unauthorized." `
                -Recommendation 'Remove the ACE immediately and review SDProp/AdminSDHolder change history. This is one of the highest-impact misconfigurations possible in AD.' `
                -RiskScore 99 -MitreID 'T1098'))
        }
    }
} catch {
    Write-Status "AdminSDHolder audit skipped: $($_.Exception.Message)" -Level Warn
}

# Orphaned AdminCount=1 objects: previously protected, no longer in a privileged group,
# still carrying the protected ACL/inheritance-blocked state.
try {
    $privilegedMemberDNs = New-Object System.Collections.Generic.HashSet[string]
    foreach ($groupName in $script:PrivilegedGroupNames) {
        try {
            Get-ADGroupMember -Identity $groupName -Recursive @adParams -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$privilegedMemberDNs.Add($_.DistinguishedName) }
        } catch {}
    }

    $adminCountUsers = Get-ADUser -Filter { AdminCount -eq 1 } -Properties AdminCount @adParams
    foreach ($u in $adminCountUsers) {
        if (-not $privilegedMemberDNs.Contains($u.DistinguishedName)) {
            $containerFindings.Add((New-GapFinding -Category 'Protected Container' `
                -Finding 'Orphaned AdminCount=1 account' `
                -AffectedObject $u.SamAccountName -ObjectType 'User' `
                -Details "Account carries AdminCount=1 (protected ACL, inheritance blocked) but is not currently a member -- direct or nested -- of any privileged group." `
                -Recommendation 'Reset AdminCount to 0 (or let SDProp -Fix logic clear it) and re-enable ACL inheritance once confirmed the account no longer needs Tier-0 protection.' `
                -RiskScore 42 -MitreID 'T1078.002'))
        }
    }
} catch {
    Write-Status "Orphaned AdminCount sweep skipped: $($_.Exception.Message)" -Level Warn
}

# Legacy "Pre-Windows 2000 Compatible Access" group containing Everyone/Anonymous.
try {
    $preW2K = Get-ADGroup -Identity 'Pre-Windows 2000 Compatible Access' -Properties Members @adParams -ErrorAction Stop
    foreach ($memberDN in $preW2K.Members) {
        if ($memberDN -match 'Anonymous|Everyone') {
            $containerFindings.Add((New-GapFinding -Category 'Protected Container' `
                -Finding 'Anonymous/Everyone in Pre-Windows 2000 Compatible Access' `
                -AffectedObject 'Pre-Windows 2000 Compatible Access' -ObjectType 'Group' `
                -Details "'$memberDN' is a member. This legacy compatibility group can allow anonymous/unauthenticated enumeration of user and group attributes." `
                -Recommendation 'Remove Anonymous Logon / Everyone from this group unless a legacy NT4 application explicitly requires it.' `
                -RiskScore 60 -MitreID 'T1087.002'))
        }
    }
} catch {}

# Domain Controllers OU: confirm no delegation beyond the safe allowlist.
try {
    $dcOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Domain Controllers'" @adParams | Select-Object -First 1
    if ($dcOU) {
        $acl = Get-ObjectAcl -DistinguishedName $dcOU.DistinguishedName
        if ($acl) {
            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                if (Test-SafePrincipal -Identity $identity) { continue }
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $rightsHit = $ace.ActiveDirectoryRights -band $script:DangerousRights
                if ($rightsHit -eq 0) { continue }
                $containerFindings.Add((New-GapFinding -Category 'Protected Container' `
                    -Finding 'Unexpected delegation on Domain Controllers OU' `
                    -AffectedObject 'Domain Controllers' -ObjectType 'OU' `
                    -Details "'$identity' holds '$rightsHit' on the Domain Controllers OU. This can allow tampering with DC computer objects, GPO links, or delegation settings." `
                    -Recommendation 'Remove the delegation unless explicitly documented and required. Only Tier-0 admin groups should manage this OU.' `
                    -RiskScore 91 -MitreID 'T1484'))
            }
        }
    }
} catch {
    Write-Status "Domain Controllers OU audit skipped: $($_.Exception.Message)" -Level Warn
}

Write-Status "Protected container findings: $($containerFindings.Count)" -Level Ok

#endregion

#region Export

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$exports = @(
    @{ Name = 'ACL_Inheritance_Gaps';           Data = $aclFindings }
    @{ Name = 'Password_Security_Gaps';         Data = $pwdFindings }
    @{ Name = 'Privilege_Escalation_Paths';     Data = $privFindings }
    @{ Name = 'Protected_Container_Misconfig';  Data = $containerFindings }
)

Write-Host ''
Write-Status "Writing CSV output to $OutputPath" -Level Ok
foreach ($e in $exports) {
    $path = Join-Path $OutputPath "$($e.Name)_$timestamp.csv"
    if ($e.Data.Count -gt 0) {
        $e.Data | Sort-Object RiskScore -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    } else {
        # Still emit a header-only file (Export-Csv writes nothing at all for zero input objects)
        # so the file list / dashboard ingestion sees a consistent source with a known schema.
        'Category,Severity,RiskScore,Finding,AffectedObject,ObjectType,Details,Recommendation,MitreID,DomainName,ScanDate' |
            Set-Content -Path $path -Encoding UTF8
    }
    Write-Status "  $($e.Name): $($e.Data.Count) findings -> $path"
}

$totalFindings = $aclFindings.Count + $pwdFindings.Count + $privFindings.Count + $containerFindings.Count
$criticalTotal = @($aclFindings + $pwdFindings + $privFindings + $containerFindings | Where-Object { $_.Severity -eq 'Critical' }).Count

Write-Host ''
Write-Status "Scan complete. $totalFindings total findings ($criticalTotal Critical) across 4 sources." -Level Ok
Write-Status "Next step: .\New-SecurityGapsDashboard.ps1 -InputPath `"$OutputPath`" -TopN 30" -Level Ok

#endregion
