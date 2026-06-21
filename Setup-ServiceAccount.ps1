#Requires -Version 5.1
<#
.SYNOPSIS
    Sets up the least-privilege service account for the AD Attack Path Analysis Platform.
    Supports both traditional service accounts and Group Managed Service Accounts (gMSA).

.DESCRIPTION
    This script creates the AD service account, delegates the minimum required read
    permissions, stores credentials in Windows Credential Manager, and registers
    the scheduled task under the new account.

    Two modes supported:
      A) Traditional service account (password-based)
      B) Group Managed Service Account / gMSA (preferred — no password management)

.PARAMETER AccountName
    SAM name for the new service account. Default: svc-adsecurity

.PARAMETER AccountOU
    OU where the account will be created. Default: CN=Service Accounts,DC=...

.PARAMETER UseGMSA
    Create a Group Managed Service Account instead of a regular account.

.PARAMETER TargetComputer
    The computer that will run the scheduled task (used for gMSA principal).
    Required when UseGMSA is specified.

.PARAMETER StoreCredential
    Store an existing account's credentials in Windows Credential Manager
    for headless scheduled task execution.

.PARAMETER CredentialTarget
    Credential Manager target name. Must match config.json CredentialManagerTarget.
    Default: ADAttackPathAnalysis

.PARAMETER DomainFQDN
    Fully qualified domain name e.g. contoso.local. Auto-detected if not specified.

.EXAMPLE
    # Create least-privilege service account (traditional)
    .\Setup-ServiceAccount.ps1 -AccountName svc-adsecurity

.EXAMPLE
    # Create Group Managed Service Account (no password needed - preferred)
    .\Setup-ServiceAccount.ps1 -AccountName svc-adsecurity -UseGMSA -TargetComputer REPORT-SRV01

.EXAMPLE
    # Store credential for existing account in Credential Manager
    .\Setup-ServiceAccount.ps1 -StoreCredential -AccountName svc-adsecurity

.EXAMPLE
    # Full end-to-end: create gMSA, delegate permissions, register scheduled task
    .\Setup-ServiceAccount.ps1 -UseGMSA -TargetComputer REPORT-SRV01 -RegisterTask
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Traditional')]
param(
    [string]$AccountName      = 'svc-adsecurity',
    [string]$AccountOU        = '',
    [Parameter(ParameterSetName = 'GMSA')]
    [switch]$UseGMSA,
    [Parameter(ParameterSetName = 'GMSA', Mandatory)]
    [string]$TargetComputer,
    [Parameter(ParameterSetName = 'StoreOnly')]
    [switch]$StoreCredential,
    [string]$CredentialTarget = 'ADAttackPathAnalysis',
    [string]$DomainFQDN       = '',
    [switch]$RegisterTask,
    [string]$PlatformPath     = 'C:\ADAttackPathPlatform'
)

Import-Module ActiveDirectory -ErrorAction Stop
$ErrorActionPreference = 'Stop'

function Write-Step   { param($M) Write-Host "[STEP]  $M" -ForegroundColor Cyan    }
function Write-Ok     { param($M) Write-Host "  [OK]  $M" -ForegroundColor Green   }
function Write-Warn   { param($M) Write-Host " [WARN] $M" -ForegroundColor Yellow  }
function Write-Fail   { param($M) Write-Host " [FAIL] $M" -ForegroundColor Red     }
function Write-Info   { param($M) Write-Host "  [>>]  $M" -ForegroundColor Gray    }
function Write-Cmd    { param($M) Write-Host "        $M" -ForegroundColor DarkCyan }

# ── Resolve domain ────────────────────────────────────────────────────────────
if (-not $DomainFQDN) {
    $DomainFQDN = (Get-ADDomain).DNSRoot
}
$domainDN = (Get-ADDomain -Identity $DomainFQDN).DistinguishedName
$domainNetBIOS = (Get-ADDomain -Identity $DomainFQDN).NetBIOSName

if (-not $AccountOU) {
    # Try to find a Service Accounts OU; fall back to CN=Users
    $svcOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Service Accounts'" -ErrorAction SilentlyContinue | Select-Object -First 1
    $AccountOU = if ($svcOU) { $svcOU.DistinguishedName } else { "CN=Users,$domainDN" }
}

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host '   AD Attack Path Platform — Service Account Setup'           -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host ''
Write-Info "Domain        : $DomainFQDN"
Write-Info "Account Name  : $AccountName"
Write-Info "Account OU    : $AccountOU"
Write-Info "Mode          : $(if($UseGMSA){'Group Managed Service Account (gMSA)'}elseif($StoreCredential){'Store Credential Only'}else{'Traditional Service Account'})"
Write-Host ''

# ============================================================
# MODE: STORE CREDENTIAL ONLY
# ============================================================
if ($StoreCredential) {
    Write-Step "Storing credentials in Windows Credential Manager..."
    Write-Info "You will be prompted for the service account password."
    Write-Info "This is stored encrypted with DPAPI — never in plaintext."
    Write-Host ''

    $cred = Get-Credential -Message "Enter credentials for $domainNetBIOS\$AccountName" -UserName "$domainNetBIOS\$AccountName"
    if (-not $cred) { Write-Fail "No credential provided."; exit 1 }

    $pw = $cred.GetNetworkCredential().Password

    if ($PSCmdlet.ShouldProcess($CredentialTarget, 'Store credential in Windows Credential Manager')) {
        # Use cmdkey for reliable Credential Manager storage
        $result = cmdkey /add:$CredentialTarget /user:"$domainNetBIOS\$AccountName" /pass:"$pw" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Credential stored: cmdkey target='$CredentialTarget'"
        } else {
            Write-Fail "cmdkey failed: $result"
            exit 1
        }
    }

    Write-Host ''
    Write-Ok "Credential stored. Verify with: cmdkey /list:$CredentialTarget"
    Write-Info "Set config.json: Credentials.UseCurrentContext = false"
    Write-Info "Set config.json: Credentials.CredentialManagerTarget = '$CredentialTarget'"
    exit 0
}

# ============================================================
# MODE: GROUP MANAGED SERVICE ACCOUNT (gMSA)
# ============================================================
if ($UseGMSA) {
    Write-Step "Creating Group Managed Service Account (gMSA)..."

    # Verify KDS Root Key exists (required for gMSA)
    $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue
    if (-not $kdsKey) {
        Write-Warn "No KDS Root Key found. Creating one (takes 10 hours to replicate in production)."
        Write-Warn "For a lab/test environment, use -EffectiveTime (Subtract(10h)) to make it immediately effective:"
        Write-Cmd  "Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)  # LAB ONLY"
        Write-Cmd  "Add-KdsRootKey -EffectiveImmediately                     # Production (waits 10h)"
        Write-Host ''
        if ($PSCmdlet.ShouldProcess('KDS Root Key', 'Create')) {
            Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
            Write-Ok 'KDS Root Key created (effective immediately for lab).'
        }
    } else {
        Write-Ok "KDS Root Key present: effective $($kdsKey.EffectiveTime)"
    }

    # Resolve the computer account that will run the task
    $computerAccount = Get-ADComputer -Identity $TargetComputer -ErrorAction Stop
    Write-Ok "Target computer: $($computerAccount.SamAccountName) ($($computerAccount.DNSHostName))"

    # Create the gMSA
    $gmsaName = "$AccountName"
    $existing = Get-ADServiceAccount -Filter "SamAccountName -eq '$gmsaName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "gMSA '$gmsaName' already exists. Skipping creation."
    } else {
        if ($PSCmdlet.ShouldProcess($gmsaName, 'Create gMSA')) {
            New-ADServiceAccount `
                -Name                    $gmsaName `
                -DNSHostName             "$gmsaName.$DomainFQDN" `
                -PrincipalsAllowedToRetrieveManagedPassword $computerAccount `
                -KerberosEncryptionType  AES256 `
                -Path                    $AccountOU `
                -Description             'AD Attack Path Analysis Platform — read-only AD analysis account. Managed by Setup-ServiceAccount.ps1.'
            Write-Ok "gMSA created: $gmsaName.$DomainFQDN"
        }
    }

    # Install gMSA on the target computer (run this on the target or via remoting)
    Write-Host ''
    Write-Step "Installing gMSA on target computer: $TargetComputer"
    Write-Info "Run this command ON $TargetComputer (or use Invoke-Command):"
    Write-Cmd  "Install-ADServiceAccount -Identity '$gmsaName'"
    Write-Cmd  "Test-ADServiceAccount    -Identity '$gmsaName'  # Should return True"
    Write-Host ''

    # Grant Logon-As-Service right (needed for Task Scheduler)
    Write-Info "Grant 'Log on as a service' right to ${gmsaName}$ on $TargetComputer via Group Policy or secedit."
    Write-Cmd  "# Via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment"
    Write-Cmd  "# > Log on as a service > Add '$domainNetBIOS\${gmsaName}$'"

    # Delegate AD permissions (same as traditional — see below)
    Write-Host ''
    Write-Step "Delegating minimum AD read permissions to gMSA..."
    Grant-ADReadPermissions -AccountDN "CN=${gmsaName},$AccountOU" -DomainDN $domainDN -IsGMSA

    # Update config
    Write-Host ''
    Write-Step "Configuration updates required:"
    Write-Info "Set config.json: Credentials.UseCurrentContext = true"
    Write-Info "Set config.json: Credentials.RunAsGMSA = true"
    Write-Info "Scheduled task RunAs: '$domainNetBIOS\${gmsaName}$' (include the trailing dollar sign)"
    Write-Cmd  "# Register task under gMSA:"
    Write-Cmd  ".\Install-ADAttackPathPlatform.ps1 -ConfigureScheduler -RunAsUser '$domainNetBIOS\${gmsaName}$'"

    if ($RegisterTask) {
        Import-Module (Join-Path $PlatformPath 'Modules\SchedulerModule.psm1') -Force
        Install-ADAttackPathSchedule `
            -ScriptPath  (Join-Path $PlatformPath 'Invoke-ADAttackPathAnalysis.ps1') `
            -ConfigPath  (Join-Path $PlatformPath 'Config\config.json') `
            -RunAsUser   "$domainNetBIOS\${gmsaName}$" `
            -Frequency   'Weekly' -DayOfWeek 'Monday' -TimeOfDay '06:00'
        Write-Ok "Scheduled task registered under gMSA account."
    }

    exit 0
}

# ============================================================
# MODE: TRADITIONAL SERVICE ACCOUNT
# ============================================================
Write-Step "Creating traditional service account: $AccountName..."

$existingUser = Get-ADUser -Filter "SamAccountName -eq '$AccountName'" -ErrorAction SilentlyContinue
if ($existingUser) {
    Write-Warn "Account '$AccountName' already exists. Skipping creation."
    $newAccount = $existingUser
} else {
    # Generate a strong random password
    $charSet    = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
    $rng        = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes      = [byte[]]::new(32)
    $rng.GetBytes($bytes)
    $password   = -join ($bytes | ForEach-Object { $charSet[$_ % $charSet.Length] })
    $secPassword = ConvertTo-SecureString $password -AsPlainText -Force

    if ($PSCmdlet.ShouldProcess($AccountName, 'Create AD user')) {
        $newAccount = New-ADUser `
            -Name                  $AccountName `
            -SamAccountName        $AccountName `
            -UserPrincipalName     "$AccountName@$DomainFQDN" `
            -AccountPassword       $secPassword `
            -Enabled               $true `
            -PasswordNeverExpires  $true `
            -CannotChangePassword  $true `
            -Path                  $AccountOU `
            -Description           'AD Attack Path Analysis Platform — read-only AD analysis. Managed by Setup-ServiceAccount.ps1.' `
            -PassThru

        Write-Ok "Account created: $domainNetBIOS\$AccountName"
        Write-Warn "Generated password (store this securely and then store in Credential Manager):"
        Write-Warn "  Password: $password"
        Write-Host ''
        Write-Info "Store in Credential Manager now:"
        Write-Cmd  ".\Setup-ServiceAccount.ps1 -StoreCredential -AccountName $AccountName"
    }
}

# ── Delegate minimum read permissions ─────────────────────────────────────────
$accountDN = (Get-ADUser -Identity $AccountName).DistinguishedName
Write-Host ''
Write-Step "Delegating minimum AD read permissions to $AccountName..."
Grant-ADReadPermissions -AccountDN $accountDN -DomainDN $domainDN

# ── Grant local rights ─────────────────────────────────────────────────────────
Write-Host ''
Write-Step "Local rights required on the server running the scheduled task:"
Write-Info "Grant 'Log on as a service' and 'Log on as a batch job' rights to $domainNetBIOS\$AccountName"
Write-Cmd  "# Via GPO: Computer Config > Security Settings > Local Policies > User Rights Assignment"
Write-Cmd  "# Or secedit (run on the target server):"
Write-Cmd  "secedit /import /cfg service_rights.inf /db secedit.sdb"

# ── Update Credential Manager ─────────────────────────────────────────────────
Write-Host ''
Write-Step "Storing credentials in Windows Credential Manager..."
Write-Info "Run this on the server that will execute the scheduled task:"
Write-Cmd  "cmdkey /add:$CredentialTarget /user:$domainNetBIOS\$AccountName /pass:<password>"
Write-Cmd  "# Or interactively: .\Setup-ServiceAccount.ps1 -StoreCredential -AccountName $AccountName"

# ── Register scheduled task ───────────────────────────────────────────────────
if ($RegisterTask) {
    Write-Host ''
    Write-Step "Registering scheduled task under $AccountName..."
    $taskPwd = Read-Host "Enter password for $AccountName (for Task Scheduler)" -AsSecureString
    $taskPwdPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskPwd))

    Import-Module (Join-Path $PlatformPath 'Modules\SchedulerModule.psm1') -Force
    $task = Install-ADAttackPathSchedule `
        -ScriptPath  (Join-Path $PlatformPath 'Invoke-ADAttackPathAnalysis.ps1') `
        -ConfigPath  (Join-Path $PlatformPath 'Config\config.json') `
        -RunAsUser   "$domainNetBIOS\$AccountName" `
        -Frequency   'Weekly' -DayOfWeek 'Monday' -TimeOfDay '06:00'

    # Task Scheduler needs the password stored separately
    $task | Set-ScheduledTask -User "$domainNetBIOS\$AccountName" -Password $taskPwdPlain | Out-Null
    Write-Ok "Scheduled task registered under $domainNetBIOS\$AccountName"
}

Write-Host ''
Write-Ok "Service account setup complete."

# ============================================================
# PERMISSION DELEGATION FUNCTION
# ============================================================
function Grant-ADReadPermissions {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$AccountDN,
        [string]$DomainDN,
        [switch]$IsGMSA
    )

    $accountSID = if ($IsGMSA) {
        (Get-ADServiceAccount -Filter "DistinguishedName -eq '$AccountDN'").SID
    } else {
        (Get-ADUser -Filter "DistinguishedName -eq '$AccountDN'").SID
    }

    if (-not $accountSID) {
        Write-Warn "Could not resolve SID for account DN: $AccountDN"
        return
    }

    $identity = [System.Security.Principal.SecurityIdentifier]$accountSID

    # ── 1. Read all AD objects (already granted to Domain Users — just confirm) ──
    Write-Info "Read access to AD objects: inherited from Domain Users (no change needed)"

    # ── 2. Read Security Descriptors for ACL analysis ────────────────────────────
    Write-Step "Granting 'Read Security Descriptor' on domain root for ACL analysis..."
    if ($PSCmdlet.ShouldProcess($DomainDN, "Grant Read Security Descriptor")) {
        try {
            $domainPath  = "AD:\$DomainDN"
            $acl         = Get-Acl -Path $domainPath
            $adRights    = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
            $inheritType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'
            $ace         = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $identity, $adRights, 'Allow', $inheritType)
            $acl.AddAccessRule($ace)
            Set-Acl -Path $domainPath -AclObject $acl
            Write-Ok "ReadControl granted on domain root (inherits to all objects)."
        } catch {
            Write-Warn "Could not set ACL on domain root: $_"
            Write-Warn "Grant manually: ADSI Edit > domain root > Properties > Security > Add $AccountDN > Read."
        }
    }

    # ── 3. Grant 'Replicate Directory Changes' (read-only, NOT Get-Changes-All) ──
    # This is needed ONLY if you want DCSync detection. Optional — remove if not needed.
    Write-Step "Granting DS-Replication-Get-Changes (read-only audit — NOT Get-Changes-All)..."
    if ($PSCmdlet.ShouldProcess($DomainDN, "Grant DS-Replication-Get-Changes")) {
        try {
            $domainPath  = "AD:\$DomainDN"
            $acl         = Get-Acl -Path $domainPath
            $replicGuid  = [System.Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes ONLY
            $adRights    = [System.DirectoryServices.ActiveDirectoryRights]'ExtendedRight'
            $inheritType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'None'
            $ace         = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $identity, $adRights, 'Allow', $replicGuid, $inheritType, [System.Guid]::Empty)
            $acl.AddAccessRule($ace)
            Set-Acl -Path $domainPath -AclObject $acl
            Write-Ok "DS-Replication-Get-Changes granted (read-only; cannot dump credentials)."
        } catch {
            Write-Warn "Could not grant replication right: $_"
            Write-Warn "Grant manually via ADSI Edit if ACL analysis is required."
        }
    }

    # ── 4. Report path for output directory ──────────────────────────────────────
    Write-Step "Granting NTFS write access to reports output directory..."
    $reportPath = 'C:\ADAttackPathReports'
    if (Test-Path $reportPath) {
        if ($PSCmdlet.ShouldProcess($reportPath, "Grant Modify NTFS permission")) {
            try {
                $acl        = Get-Acl $reportPath
                $accountRef = if ($IsGMSA) {
                    $identity.Translate([System.Security.Principal.NTAccount]).Value
                } else {
                    (Get-ADUser -Filter "DistinguishedName -eq '$AccountDN'").UserPrincipalName
                }
                $fileRule   = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                    $accountRef, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                $acl.AddAccessRule($fileRule)
                Set-Acl $reportPath $acl
                Write-Ok "Modify access granted on $reportPath"
            } catch {
                Write-Warn "Could not set NTFS ACL: $_. Grant manually via Explorer > Security."
            }
        }
    } else {
        Write-Info "Report directory $reportPath not yet created. Will be created on first run."
    }

    Write-Host ''
    Write-Ok "Permission delegation complete."
    Write-Host ''
    Write-Info "Summary of permissions granted:"
    Write-Cmd  "  ✓ Domain Users — Read all AD objects (inherited)"
    Write-Cmd  "  ✓ ReadControl on domain root — Read ACLs for ACL analysis"
    Write-Cmd  "  ✓ DS-Replication-Get-Changes — Detect DCSync-capable accounts"
    Write-Cmd  "  ✓ NTFS Modify on $reportPath — Write reports and logs"
    Write-Host ''
    Write-Warn "Permissions NOT granted (not needed):"
    Write-Cmd  "  ✗ DS-Replication-Get-Changes-All — would enable credential dumping (NOT granted)"
    Write-Cmd  "  ✗ Domain Admin — not required"
    Write-Cmd  "  ✗ Schema Admin / Enterprise Admin — not required"
}
