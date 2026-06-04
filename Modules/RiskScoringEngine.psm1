#Requires -Version 5.1
<#
.SYNOPSIS
    Risk scoring engine for the AD Attack Path Analysis Platform.
    Calculates per-finding and aggregate domain risk scores (0-100).
#>

#region MITRE Mappings

$script:MitreMap = @{
    'Kerberoasting'              = @{ ID = 'T1558.003'; Name = 'Kerberoasting';                   Tactic = 'Credential Access' }
    'ASREPRoasting'              = @{ ID = 'T1558.004'; Name = 'AS-REP Roasting';                 Tactic = 'Credential Access' }
    'DCSync'                     = @{ ID = 'T1003.006'; Name = 'DCSync';                          Tactic = 'Credential Access' }
    'UnconstrainedDelegation'    = @{ ID = 'T1558.001'; Name = 'Kerberos Delegation';             Tactic = 'Credential Access' }
    'ConstrainedDelegation'      = @{ ID = 'T1558.001'; Name = 'Kerberos Delegation';             Tactic = 'Credential Access' }
    'ResourceBasedConstrained'   = @{ ID = 'T1558.001'; Name = 'RBCD Attack';                     Tactic = 'Credential Access' }
    'GenericAll'                 = @{ ID = 'T1484.001'; Name = 'Group Policy Modification';       Tactic = 'Defense Evasion' }
    'GenericWrite'               = @{ ID = 'T1098';     Name = 'Account Manipulation';            Tactic = 'Persistence' }
    'WriteDACL'                  = @{ ID = 'T1222';     Name = 'File and Directory Permissions';  Tactic = 'Defense Evasion' }
    'WriteOwner'                 = @{ ID = 'T1222';     Name = 'File and Directory Permissions';  Tactic = 'Defense Evasion' }
    'SIDHistory'                 = @{ ID = 'T1134.005'; Name = 'SID-History Injection';           Tactic = 'Privilege Escalation' }
    'ShadowAdmin'                = @{ ID = 'T1078.002'; Name = 'Valid Accounts: Domain Accounts'; Tactic = 'Initial Access' }
    'DormantPrivileged'          = @{ ID = 'T1078.002'; Name = 'Valid Accounts: Domain Accounts'; Tactic = 'Initial Access' }
    'PasswordNeverExpires'       = @{ ID = 'T1078';     Name = 'Valid Accounts';                  Tactic = 'Initial Access' }
    'PasswordNotRequired'        = @{ ID = 'T1110';     Name = 'Brute Force';                     Tactic = 'Credential Access' }
    'AddMember'                  = @{ ID = 'T1098.007'; Name = 'Additional Cloud Roles';          Tactic = 'Persistence' }
    'ForceChangePassword'        = @{ ID = 'T1098';     Name = 'Account Manipulation';            Tactic = 'Persistence' }
    'GPODelegation'              = @{ ID = 'T1484.001'; Name = 'Domain Policy Modification';      Tactic = 'Defense Evasion' }
    'OUDelegation'               = @{ ID = 'T1484';     Name = 'Domain Policy Modification';      Tactic = 'Defense Evasion' }
    'PathToDA'                   = @{ ID = 'T1078.002'; Name = 'Valid Accounts: Domain Accounts'; Tactic = 'Privilege Escalation' }
    'PathToEA'                   = @{ ID = 'T1078.002'; Name = 'Valid Accounts: Domain Accounts'; Tactic = 'Privilege Escalation' }
    'CircularGroup'              = @{ ID = 'T1078.002'; Name = 'Valid Accounts';                  Tactic = 'Privilege Escalation' }
    'OrphanedSID'                = @{ ID = 'T1134';     Name = 'Access Token Manipulation';       Tactic = 'Privilege Escalation' }
    'ReversiblePasswordEncryption' = @{ ID = 'T1003';  Name = 'OS Credential Dumping';            Tactic = 'Credential Access' }
}

#endregion

#region Scoring Constants

$script:RiskWeights = @{
    DCSync                        = 95
    DCShadow                      = 95
    PathToDA                      = 92
    PathToEA                      = 90
    Tier0Exposure                 = 88
    GenericAll                    = 85
    UnconstrainedDelegation       = 82
    GenericWrite                  = 78
    WriteDACL                     = 75
    WriteOwner                    = 72
    SIDHistory                    = 70
    ShadowAdmin                   = 68
    Kerberoasting_Privileged      = 65
    ASREPRoasting_Privileged      = 65
    ConstrainedDelegation         = 60
    ResourceBasedConstrained      = 58
    Kerberoasting_Standard        = 50
    ASREPRoasting_Standard        = 50
    DormantPrivilegedAccount      = 48
    AddMember                     = 45
    ForceChangePassword           = 45
    GPODelegation                 = 45
    OUDelegation                  = 42
    Tier1Exposure                 = 40
    PasswordNeverExpires_Priv     = 40
    PasswordNotRequired           = 38
    ReversiblePasswordEncryption  = 38
    StalePrivilegedAccount        = 35
    OrphanedSID                   = 35
    PasswordNeverExpires_Standard = 20
    CircularGroupMembership       = 25
    AdminCountOrphan              = 45
}

#endregion

#region Per-Finding Score

function Get-FindingRiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingType,

        [hashtable]$Context = @{}
    )

    $baseScore = $script:RiskWeights[$FindingType]
    if ($null -eq $baseScore) { $baseScore = 20 }

    # Context multipliers
    $multiplier = 1.0

    if ($Context.IsPrivileged -eq $true)     { $multiplier += 0.15 }
    if ($Context.IsEnabled    -eq $true)     { $multiplier += 0.05 }
    if ($Context.HasSPN       -eq $true)     { $multiplier += 0.10 }
    if ($Context.HasSIDHistory -eq $true)    { $multiplier += 0.10 }
    if ($Context.AdminCount   -eq 1)         { $multiplier += 0.15 }
    if ($Context.IsNew        -eq $true)     { $multiplier += 0.10 }

    $finalScore = [Math]::Min(100, [int]($baseScore * $multiplier))
    return $finalScore
}

#endregion

#region Severity Classification

function Get-RiskSeverity {
    [CmdletBinding()]
    param([int]$Score)

    if ($Score -ge 90) { return 'Critical' }
    if ($Score -ge 70) { return 'High'     }
    if ($Score -ge 40) { return 'Medium'   }
    return 'Low'
}

function Get-RiskColor {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return '#dc3545' }
        'High'     { return '#fd7e14' }
        'Medium'   { return '#ffc107' }
        'Low'      { return '#28a745' }
        default    { return '#6c757d' }
    }
}

function Get-RiskBadgeClass {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { return 'badge-critical'  }
        'High'     { return 'badge-high'      }
        'Medium'   { return 'badge-medium'    }
        'Low'      { return 'badge-low'       }
        default    { return 'badge-secondary' }
    }
}

#endregion

#region MITRE ATT&CK Mapping

function Get-MitreMapping {
    [CmdletBinding()]
    param([string]$FindingType)

    if ($script:MitreMap.ContainsKey($FindingType)) {
        return $script:MitreMap[$FindingType]
    }
    return @{ ID = 'T1078'; Name = 'Valid Accounts'; Tactic = 'Initial Access' }
}

#endregion

#region Domain Risk Score

function Invoke-RiskScoring {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ADData,

        [hashtable]$Config
    )

    $findings = [System.Collections.Generic.List[hashtable]]::new()
    $domainScore = 0
    $scoreFactors = @()

    # --- DCSync ---
    foreach ($account in $ADData.DCSyncAccounts) {
        $score = Get-FindingRiskScore -FindingType 'DCSync'
        $mitre = Get-MitreMapping -FindingType 'DCSync'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'DCSync'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "DCSync Rights: $($account.Identity)"
            Description     = "The identity '$($account.Identity)' has DCSync replication rights on the domain. $($account.Description)"
            SourceIdentity  = $account.Identity
            TargetObject    = 'Domain'
            ExploitMethod   = 'Use mimikatz lsadump::dcsync or Impacket secretsdump.py to replicate all domain credentials including krbtgt hash'
            Remediation     = 'Remove DS-Replication-Get-Changes-All right from non-DC accounts. Use Active Directory ACL editor or PowerShell: Remove-ADObjectAcl. Verify only Domain Controllers and Azure AD Connect (if applicable) have these rights.'
            RemediationRisk = 'Low'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = "The DS-Replication-Get-Changes-All right was explicitly granted to '$($account.Identity)'. This is commonly introduced by Azure AD Connect misconfiguration, legacy Exchange installs, or overly permissive delegation."
            NewFinding      = $false
        })
        $scoreFactors += @{ Name = 'DCSync'; Score = $score }
    }

    # --- Kerberoastable ---
    foreach ($account in $ADData.KerberoastableAccounts) {
        $isPriv = $account.AdminCount -eq 1
        $ft     = if ($isPriv) { 'Kerberoasting_Privileged' } else { 'Kerberoasting_Standard' }
        $score  = Get-FindingRiskScore -FindingType $ft -Context @{ IsPrivileged = $isPriv; IsEnabled = $true }
        $mitre  = Get-MitreMapping -FindingType 'Kerberoasting'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'Kerberoasting'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "Kerberoastable Account: $($account.SamAccountName)"
            Description     = "Account has Service Principal Names (SPNs) and a Kerberos TGS ticket can be requested and offline-cracked. $(if($isPriv){'This is a HIGH PRIVILEGE account (AdminCount=1).'})"
            SourceIdentity  = 'Any Authenticated User'
            TargetObject    = $account.SamAccountName
            ExploitMethod   = 'Request TGS: Rubeus.exe kerberoast /user:' + $account.SamAccountName + ' /nowrap — then crack offline with Hashcat mode 13100'
            Remediation     = "1) Use Group Managed Service Accounts (gMSA) instead of user accounts with SPNs. 2) If the account must remain, ensure a long complex password (25+ chars). 3) Enable AES encryption: Set-ADUser $($account.SamAccountName) -KerberosEncryptionType AES256. 4) Consider adding to Protected Users group. 5) Monitor for TGS requests in Event ID 4769."
            RemediationRisk = 'Low - changing encryption type requires service restart'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = "Service Principal Name registered on user account. SPNs: $($account.SPNs -join ', ')"
            NewFinding      = $false
        })
        $scoreFactors += @{ Name = "Kerberoasting_$($account.SamAccountName)"; Score = $score }
    }

    # --- AS-REP Roastable ---
    foreach ($account in $ADData.ASREPRoastableAccounts) {
        $isPriv = $account.AdminCount -eq 1
        $ft     = if ($isPriv) { 'ASREPRoasting_Privileged' } else { 'ASREPRoasting_Standard' }
        $score  = Get-FindingRiskScore -FindingType $ft -Context @{ IsPrivileged = $isPriv }
        $mitre  = Get-MitreMapping -FindingType 'ASREPRoasting'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'ASREPRoasting'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "AS-REP Roastable: $($account.SamAccountName)"
            Description     = "Kerberos pre-authentication is disabled. An attacker can request an encrypted AS-REP without credentials and crack it offline. $(if($isPriv){'This is a privileged account.'})"
            SourceIdentity  = 'Unauthenticated / Any User'
            TargetObject    = $account.SamAccountName
            ExploitMethod   = 'Rubeus.exe asreproast /user:' + $account.SamAccountName + ' /nowrap — crack with Hashcat mode 18200'
            Remediation     = "1) Enable Kerberos pre-authentication: Set-ADAccountControl -Identity $($account.SamAccountName) -DoesNotRequirePreAuth `$false. 2) No legitimate use case exists for disabling pre-auth on modern accounts. 3) If pre-auth cannot be enabled, use a strong password (25+ chars) and monitor Event ID 4768 for RC4 AS-REP requests."
            RemediationRisk = 'Low - re-enabling pre-auth has no service impact'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = "DoesNotRequirePreAuth flag set on account. Often set accidentally or to support legacy applications."
            NewFinding      = $false
        })
        $scoreFactors += @{ Name = "ASREPRoast_$($account.SamAccountName)"; Score = $score }
    }

    # --- Unconstrained Delegation ---
    foreach ($finding in ($ADData.DelegationFindings | Where-Object { $_.Type -eq 'UnconstrainedDelegation' })) {
        $score = Get-FindingRiskScore -FindingType 'UnconstrainedDelegation'
        $mitre = Get-MitreMapping -FindingType 'UnconstrainedDelegation'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'UnconstrainedDelegation'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "Unconstrained Delegation: $($finding.ObjectName)"
            Description     = "$($finding.Description)"
            SourceIdentity  = $finding.ObjectName
            TargetObject    = 'Any Service'
            ExploitMethod   = 'Compromise the server, use Rubeus.exe monitor /interval:5 /nowrap to capture incoming TGTs, then pass-the-ticket for lateral movement. Can force DC to authenticate with MS-RPRN printer bug (printerbug.py).'
            Remediation     = "1) Replace with Constrained Delegation: Clear TrustedForDelegation, set specific AllowedToDelegateTo services. 2) If unconstrained delegation is truly needed, add to Protected Users group is NOT possible (breaks delegation). Instead: enable 'Account is sensitive and cannot be delegated' on DA/EA accounts. 3) Use PowerShell: Set-ADComputer '$($finding.ObjectName)' -TrustedForDelegation `$false"
            RemediationRisk = 'Medium - requires identifying all services using delegation'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = "TrustedForDelegation=True on $($finding.ObjectType). This allows the machine to impersonate ANY user to ANY service."
            NewFinding      = $false
        })
    }

    # --- Shadow Admins ---
    foreach ($account in $ADData.ShadowAdmins) {
        $score = Get-FindingRiskScore -FindingType 'ShadowAdmin' -Context @{ AdminCount = 1 }
        $mitre = Get-MitreMapping -FindingType 'ShadowAdmin'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'ShadowAdmin'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "Shadow Admin: $($account.SamAccountName)"
            Description     = "$($account.Reason)"
            SourceIdentity  = $account.SamAccountName
            TargetObject    = 'Privileged Resources'
            ExploitMethod   = 'Account has AdminCount=1 with inherited SDProp protections but no clear group membership. May have direct ACE grants or inherited access through removed group. Attempt lateral movement as this account.'
            Remediation     = "1) Investigate why AdminCount=1 is set: check AdminSDHolder ACL history. 2) If account no longer needs privilege: Set-ADUser '$($account.SamAccountName)' -Clear adminCount, then manually reset inherited ACLs. 3) Remove any direct ACE grants on privileged objects. 4) Review LAPS and tiering model compliance."
            RemediationRisk = 'Medium - verify access before revoking'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = $account.Reason
            NewFinding      = $false
        })
    }

    # --- ACL Findings ---
    foreach ($acl in $ADData.ACLFindings) {
        $score = Get-FindingRiskScore -FindingType $acl.FindingType
        $mitre = Get-MitreMapping -FindingType $acl.FindingType
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = $acl.FindingType
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "$($acl.FindingType) on $($acl.TargetObjectType): $($acl.SourceIdentity)"
            Description     = "Identity '$($acl.SourceIdentity)' has $($acl.FindingType) rights on $($acl.TargetObject)"
            SourceIdentity  = $acl.SourceIdentity
            TargetObject    = $acl.TargetObject
            ExploitMethod   = Get-ACLExploitMethod -FindingType $acl.FindingType -Target $acl.TargetObject
            Remediation     = Get-ACLRemediation -FindingType $acl.FindingType -Identity $acl.SourceIdentity -Target $acl.TargetObject
            RemediationRisk = 'Low - ACL removal is reversible'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = "ACE grants '$($acl.Rights)' rights. Inherited: $($acl.Inherited)"
            NewFinding      = $false
        })
    }

    # --- SID History ---
    foreach ($account in $ADData.SIDHistoryAccounts) {
        $score = Get-FindingRiskScore -FindingType 'SIDHistory'
        $mitre = Get-MitreMapping -FindingType 'SIDHistory'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'SIDHistory'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "SID History: $($account.SamAccountName)"
            Description     = "Account contains SID History values: $($account.SIDHistory -join ', '). If any SID belongs to a privileged group in any domain, this account may have elevated access."
            SourceIdentity  = $account.SamAccountName
            TargetObject    = 'Cross-Domain Resources'
            ExploitMethod   = 'Authenticate as this user. Kerberos tickets will include SID History SIDs, granting access to resources in the source domain. Use mimikatz to view current privileges.'
            Remediation     = "1) Audit each SID in the SIDHistory attribute: verify the source SID and target group/resource. 2) If migration is complete and SID History is no longer needed: Set-ADUser '$($account.SamAccountName)' -Remove @{SIDHistory='<SID>'}. 3) Enable SID Filtering on trusts to prevent cross-domain SID History exploitation."
            RemediationRisk = 'Medium - removing SID History may break resource access if migration is incomplete'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = "SIDHistory populated, possibly from domain migration. Values: $($account.SIDHistory -join ', ')"
            NewFinding      = $false
        })
    }

    # --- Password Findings ---
    foreach ($finding in $ADData.PasswordFindings) {
        $isPriv = $finding.IsPrivileged -eq $true
        $ft     = if ($finding.FindingType -eq 'PasswordNeverExpires' -and $isPriv) { 'PasswordNeverExpires_Priv' }
                  elseif ($finding.FindingType -eq 'PasswordNeverExpires') { 'PasswordNeverExpires_Standard' }
                  else { $finding.FindingType }
        $score  = Get-FindingRiskScore -FindingType $ft -Context @{ IsPrivileged = $isPriv }
        $mitre  = Get-MitreMapping -FindingType 'PasswordNeverExpires'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = $finding.FindingType
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "$($finding.FindingType): $($finding.SamAccountName)"
            Description     = "Account $($finding.SamAccountName) has $($finding.FindingType) configured. $(if($isPriv){'This is a PRIVILEGED account.'})"
            SourceIdentity  = $finding.SamAccountName
            TargetObject    = $finding.SamAccountName
            ExploitMethod   = Get-PasswordFindingExploit -FindingType $finding.FindingType
            Remediation     = Get-PasswordFindingRemediation -FindingType $finding.FindingType -Account $finding.SamAccountName
            RemediationRisk = 'Low'
            MitreID         = $mitre.ID
            MitreName       = $mitre.Name
            MitreTactic     = $mitre.Tactic
            RootCause       = "Account attribute set to $($finding.FindingType). Last password set: $($finding.PasswordLastSet)"
            NewFinding      = $false
        })
    }

    # --- Stale Privileged Accounts ---
    foreach ($account in ($ADData.StaleAccounts | Where-Object { $_.IsPrivileged })) {
        $score = Get-FindingRiskScore -FindingType 'StalePrivilegedAccount'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'StalePrivilegedAccount'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "Stale Privileged Account: $($account.SamAccountName)"
            Description     = "Privileged account has not logged in for $($account.DaysSinceLogin) days. Last logon: $($account.LastLogonDate)"
            SourceIdentity  = $account.SamAccountName
            TargetObject    = 'Privileged Resources'
            ExploitMethod   = 'Stale accounts are often unmonitored. Use credential stuffing, password spray, or if password is old/weak, brute force. Account will still have full privileges when compromised.'
            Remediation     = "1) Disable immediately if no business justification: Disable-ADAccount '$($account.SamAccountName)'. 2) Contact account owner to confirm if still needed. 3) If permanently unused, remove from all privileged groups then delete after 30 days. 4) Implement a quarterly access review process for all privileged accounts."
            RemediationRisk = 'Low - disable before delete; can re-enable if needed'
            MitreID         = 'T1078.002'
            MitreName       = 'Valid Accounts: Domain Accounts'
            MitreTactic     = 'Initial Access'
            RootCause       = "Account not used for $($account.DaysSinceLogin) days but retains AdminCount=1 protected status with privileged access."
            NewFinding      = $false
        })
    }

    # --- Circular Groups ---
    foreach ($circular in $ADData.CircularGroups) {
        $score = Get-FindingRiskScore -FindingType 'CircularGroupMembership'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'CircularGroupMembership'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "Circular Group Membership: $($circular.Group)"
            Description     = "Group '$($circular.Group)' has a circular membership chain. This can cause unexpected privilege escalation and AD processing errors."
            SourceIdentity  = $circular.Group
            TargetObject    = $circular.Group
            ExploitMethod   = 'Circular memberships can cause unpredictable effective permission calculations. May allow privilege escalation if a low-priv group circles back through a privileged group.'
            Remediation     = "1) Map the full membership chain using Get-ADGroupMember -Recursive. 2) Identify which group link creates the cycle. 3) Remove the circular membership: Remove-ADGroupMember. 4) Implement group nesting governance policy."
            RemediationRisk = 'Low'
            MitreID         = 'T1078.002'
            MitreName       = 'Valid Accounts'
            MitreTactic     = 'Privilege Escalation'
            RootCause       = 'Circular group membership detected during recursive traversal.'
            NewFinding      = $false
        })
    }

    # --- DCSync and Orphaned SIDs ---
    foreach ($sid in $ADData.OrphanedSIDs) {
        $score = Get-FindingRiskScore -FindingType 'OrphanedSID'
        $findings.Add([ordered]@{
            ID              = [System.Guid]::NewGuid().ToString()
            FindingType     = 'OrphanedSID'
            Severity        = Get-RiskSeverity -Score $score
            Score           = $score
            Title           = "Orphaned SID ACE: $($sid.SID)"
            Description     = "An unresolvable SID has an ACE on '$($sid.TargetPath)' with rights: $($sid.Rights)"
            SourceIdentity  = $sid.SID
            TargetObject    = $sid.TargetPath
            ExploitMethod   = 'Orphaned SIDs indicate a deleted account that still has access. If the SID can be re-created (e.g., in a trusted domain or by re-creating the account), the ACE would be restored.'
            Remediation     = "1) Remove orphaned ACE: Use ADSI Edit or PowerShell: `$acl = Get-Acl 'AD:\\$($sid.TargetPath)'; `$acl.Access | Where SID eq '$($sid.SID)' | ForEach { `$acl.RemoveAccessRule(`$_) }; Set-Acl. 2) Run quarterly ACL cleanup scripts."
            RemediationRisk = 'Low'
            MitreID         = 'T1134'
            MitreName       = 'Access Token Manipulation'
            MitreTactic     = 'Privilege Escalation'
            RootCause       = "SID $($sid.SID) no longer maps to a valid principal but retains ACE on AD object."
            NewFinding      = $false
        })
    }

    # Compute domain aggregate score
    if ($findings.Count -gt 0) {
        $critCount = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highCount  = @($findings | Where-Object { $_.Severity -eq 'High'     }).Count
        $medCount   = @($findings | Where-Object { $_.Severity -eq 'Medium'   }).Count

        $domainScore = [Math]::Min(100, [int](
            ($critCount * 15) +
            ($highCount * 8)  +
            ($medCount  * 3)  +
            [Math]::Min(30, ($findings | Measure-Object -Property Score -Maximum).Maximum * 0.3)
        ))
    }

    return [ordered]@{
        DomainRiskScore   = $domainScore
        DomainSeverity    = Get-RiskSeverity -Score $domainScore
        TotalFindings     = $findings.Count
        CriticalCount     = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        HighCount         = @($findings | Where-Object { $_.Severity -eq 'High'     }).Count
        MediumCount       = @($findings | Where-Object { $_.Severity -eq 'Medium'   }).Count
        LowCount          = @($findings | Where-Object { $_.Severity -eq 'Low'      }).Count
        Findings          = @($findings)
    }
}

#endregion

#region Helper Exploit / Remediation Text

function Get-ACLExploitMethod {
    param([string]$FindingType, [string]$Target)
    switch ($FindingType) {
        'GenericAll'   { "Full control over '$Target'. Reset password, modify group membership, set SPNs, or take ownership." }
        'GenericWrite' { "Write any non-protected attribute on '$Target'. Set SPNs for Kerberoasting, modify logon scripts, or set msDS-KeyCredentialLink for shadow credentials." }
        'WriteDACL'    { "Modify the DACL of '$Target'. Grant yourself GenericAll, then perform any action." }
        'WriteOwner'   { "Take ownership of '$Target' using Set-ADObject, then modify the DACL." }
        'DCSyncRight'  { "Use DCSync to replicate all credential hashes from the domain, including krbtgt." }
        'WriteProperty' { "Write specific property on '$Target'. May allow SPN addition for Kerberoasting or group member manipulation." }
        default        { "Abuse ACE to gain elevated access to '$Target'." }
    }
}

function Get-ACLRemediation {
    param([string]$FindingType, [string]$Identity, [string]$Target)
    "1) Identify business justification for this ACE. 2) If not justified, remove: Use ADSI Edit > navigate to '$Target' > Security > remove entry for '$Identity'. 3) Audit who granted this permission by reviewing event log ID 5136 (directory service changes). 4) Implement a process to review privileged ACEs quarterly. 5) Consider using AD tiering to structurally prevent these paths."
}

function Get-PasswordFindingExploit {
    param([string]$FindingType)
    switch ($FindingType) {
        'PasswordNeverExpires'          { 'If the password is old or weak, conduct offline brute force or credential stuffing without time pressure.' }
        'PasswordNotRequired'           { 'Authentication possible with empty password. Attempt net use or psexec with blank password.' }
        'ReversiblePasswordEncryption'  { 'Extract reversible-encrypted password from AD using Domain Admin rights: Get-ADUser ... -Properties "ms-DS-UnifiedId". Password stored in reversible form in NTDS.dit.' }
        default                         { 'Password policy weakness enables credential attacks.' }
    }
}

function Get-PasswordFindingRemediation {
    param([string]$FindingType, [string]$Account)
    switch ($FindingType) {
        'PasswordNeverExpires' {
            "1) Enable password expiration: Set-ADUser '$Account' -PasswordNeverExpires `$false. 2) Force immediate password change: Set-ADAccountPassword '$Account' -Reset; Set-ADUser '$Account' -ChangePasswordAtLogon `$true. 3) Consider Fine-Grained Password Policy for service accounts if expiration is operationally impractical."
        }
        'PasswordNotRequired' {
            "1) Require a password: Set-ADAccountControl '$Account' -PasswordNotRequired `$false. 2) Set a strong password immediately. 3) This setting has almost no legitimate use case in modern environments."
        }
        'ReversiblePasswordEncryption' {
            "1) Disable reversible encryption: Set-ADUser '$Account' -AllowReversiblePasswordEncryption `$false. 2) Force password reset to clear stored reversible hash. 3) Audit all applications that required this setting (typically used for legacy CHAP authentication)."
        }
        default { "Review and correct the password policy configuration for '$Account'." }
    }
}

#endregion

Export-ModuleMember -Function Invoke-RiskScoring, Get-FindingRiskScore, Get-RiskSeverity,
    Get-RiskColor, Get-RiskBadgeClass, Get-MitreMapping
