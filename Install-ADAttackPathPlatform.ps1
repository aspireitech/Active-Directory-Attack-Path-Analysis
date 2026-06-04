#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installation and setup script for the AD Attack Path Analysis Platform.

.DESCRIPTION
    Performs prerequisite checks, installs required PowerShell modules,
    configures output directories, and optionally registers a Windows
    Scheduled Task for weekly execution.

.PARAMETER InstallPath
    Destination path for the platform. Defaults to C:\ADAttackPathPlatform.

.PARAMETER ConfigureScheduler
    Also register a Windows Scheduled Task.

.PARAMETER ScheduleFrequency
    Weekly or Daily. Defaults to Weekly.

.PARAMETER ScheduleDay
    Day of week for weekly schedule. Defaults to Monday.

.PARAMETER ScheduleTime
    Time of day (HH:mm). Defaults to 06:00.

.PARAMETER RunAsUser
    Account to run the scheduled task. Defaults to SYSTEM.

.EXAMPLE
    .\Install-ADAttackPathPlatform.ps1

.EXAMPLE
    .\Install-ADAttackPathPlatform.ps1 -ConfigureScheduler -RunAsUser 'DOMAIN\svc-adsecurity'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallPath         = 'C:\ADAttackPathPlatform',
    [switch]$ConfigureScheduler,
    [ValidateSet('Weekly','Daily')]
    [string]$ScheduleFrequency   = 'Weekly',
    [ValidateSet('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')]
    [string]$ScheduleDay         = 'Monday',
    [string]$ScheduleTime        = '06:00',
    [string]$RunAsUser           = 'SYSTEM',
    [switch]$SkipModuleInstall
)

$ErrorActionPreference = 'Stop'

function Write-Step  { param($Msg) Write-Host "[STEP]  $Msg" -ForegroundColor Cyan   }
function Write-Ok    { param($Msg) Write-Host "  [OK]  $Msg" -ForegroundColor Green  }
function Write-Warn  { param($Msg) Write-Host " [WARN] $Msg" -ForegroundColor Yellow }
function Write-Fail  { param($Msg) Write-Host " [FAIL] $Msg" -ForegroundColor Red    }
function Write-Info  { param($Msg) Write-Host "  [>>]  $Msg" -ForegroundColor Gray   }

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host '   AD Attack Path Analysis Platform - Installer'               -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host ''

# ============================================================
# SECTION 1: Prerequisites Check
# ============================================================
Write-Step 'Checking prerequisites...'

# PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Fail "PowerShell 5.1 or later required. Current: $($PSVersionTable.PSVersion)"
    exit 1
}
Write-Ok "PowerShell $($PSVersionTable.PSVersion)"

# Windows OS
if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Warn "PowerShell Core detected. Some AD cmdlets require Windows PowerShell 5.1."
}

# RSAT Active Directory
Write-Step 'Checking RSAT (Active Directory module)...'
$adModule = Get-Module -Name ActiveDirectory -ListAvailable
if (-not $adModule) {
    Write-Warn 'ActiveDirectory module not found. Attempting to install RSAT...'
    try {
        if ((Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0').State -ne 'Installed') {
            Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' | Out-Null
            Write-Ok 'RSAT Active Directory tools installed.'
        }
    } catch {
        Write-Warn "Could not auto-install RSAT. Install manually: Install-WindowsFeature RSAT-AD-PowerShell"
    }
} else {
    Write-Ok "ActiveDirectory module: $($adModule.ModuleBase)"
}

# GroupPolicy module (optional)
$gpModule = Get-Module -Name GroupPolicy -ListAvailable
if (-not $gpModule) {
    Write-Warn 'GroupPolicy module not found. GPO collection will be limited.'
} else {
    Write-Ok 'GroupPolicy module found.'
}

# Execution policy
Write-Step 'Checking PowerShell execution policy...'
$policy = Get-ExecutionPolicy
if ($policy -eq 'Restricted') {
    Write-Warn "Execution policy is Restricted. Setting to RemoteSigned for LocalMachine."
    if ($PSCmdlet.ShouldProcess('ExecutionPolicy', 'Set to RemoteSigned')) {
        Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
        Write-Ok 'Execution policy set to RemoteSigned.'
    }
} else {
    Write-Ok "Execution policy: $policy"
}

# ============================================================
# SECTION 2: Required PowerShell Modules
# ============================================================
if (-not $SkipModuleInstall) {
    Write-Step 'Installing required PowerShell modules...'

    $requiredModules = @(
        @{ Name = 'ImportExcel'; MinVersion = '7.0.0'; Description = 'Excel export without Office' }
    )

    $optionalModules = @(
        @{ Name = 'MSAL.PS';    MinVersion = '4.0.0'; Description = 'Microsoft Graph authentication' }
        @{ Name = 'PSWriteHTML'; MinVersion = '0.0.1'; Description = 'Enhanced HTML generation (optional)' }
    )

    # Ensure NuGet provider
    try {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [version]'2.8.5.201') {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
            Write-Ok 'NuGet provider installed.'
        }
    } catch { Write-Warn "NuGet provider issue: $_" }

    foreach ($mod in $requiredModules) {
        $installed = Get-Module -Name $mod.Name -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $installed -or $installed.Version -lt [version]$mod.MinVersion) {
            Write-Info "Installing $($mod.Name) ($($mod.Description))..."
            try {
                Install-Module -Name $mod.Name -MinimumVersion $mod.MinVersion -Scope CurrentUser -Force -AllowClobber
                Write-Ok "$($mod.Name) installed."
            } catch {
                Write-Warn "Failed to install $($mod.Name): $_"
            }
        } else {
            Write-Ok "$($mod.Name) v$($installed.Version) already installed."
        }
    }

    foreach ($mod in $optionalModules) {
        $installed = Get-Module -Name $mod.Name -ListAvailable | Select-Object -First 1
        if (-not $installed) {
            Write-Info "Optional: Installing $($mod.Name) ($($mod.Description))..."
            try {
                Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction SilentlyContinue
                Write-Ok "$($mod.Name) installed."
            } catch {
                Write-Warn "Optional module $($mod.Name) not installed: $_"
            }
        }
    }
}

# ============================================================
# SECTION 3: Copy Platform Files
# ============================================================
Write-Step 'Deploying platform files...'

$sourceRoot = $PSScriptRoot

if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Ok "Created: $InstallPath"
}

$dirsToCreate = @('Config','Modules','Templates','Baselines','Reports','Logs')
foreach ($d in $dirsToCreate) {
    $dest = Join-Path $InstallPath $d
    if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
}

# Copy all ps1/psm1/json/html files
$filesToCopy = Get-ChildItem -Path $sourceRoot -Recurse -Include '*.ps1','*.psm1','*.json','*.html' |
               Where-Object { $_.FullName -notlike '*.git*' }

foreach ($file in $filesToCopy) {
    $relativePath = $file.FullName.Substring($sourceRoot.Length).TrimStart('\','/')
    $destPath     = Join-Path $InstallPath $relativePath
    $destDir      = Split-Path $destPath -Parent
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    Copy-Item $file.FullName -Destination $destPath -Force
}
Write-Ok "Platform files deployed to $InstallPath"

# ============================================================
# SECTION 4: Configuration
# ============================================================
Write-Step 'Configuring platform...'

$configDest = Join-Path $InstallPath 'Config\config.json'
if (Test-Path $configDest) {
    Write-Ok "Configuration file: $configDest"
    Write-Info "Edit this file to configure SMTP, recipients, BloodHound, and analysis settings."
} else {
    Write-Warn "Configuration file not found at $configDest. Copy from source manually."
}

# Update ReportStoragePath in config to use InstallPath
try {
    $configContent = Get-Content $configDest -Raw | ConvertFrom-Json -AsHashtable
    $configContent.General.ReportStoragePath   = Join-Path $InstallPath 'Reports'
    $configContent.General.BaselineStoragePath = Join-Path $InstallPath 'Baselines'
    $configContent.General.LogStoragePath      = Join-Path $InstallPath 'Logs'
    $configContent | ConvertTo-Json -Depth 10 | Out-File $configDest -Encoding UTF8
    Write-Ok 'Configuration paths updated.'
} catch {
    Write-Warn "Could not auto-update config paths: $_"
}

# ============================================================
# SECTION 5: Scheduled Task
# ============================================================
if ($ConfigureScheduler) {
    Write-Step 'Registering scheduled task...'
    Import-Module (Join-Path $InstallPath 'Modules\SchedulerModule.psm1') -Force

    $mainScript = Join-Path $InstallPath 'Invoke-ADAttackPathAnalysis.ps1'
    $configFile = Join-Path $InstallPath 'Config\config.json'

    try {
        Install-ADAttackPathSchedule `
            -ScriptPath       $mainScript `
            -ConfigPath       $configFile `
            -Frequency        $ScheduleFrequency `
            -DayOfWeek        $ScheduleDay `
            -TimeOfDay        $ScheduleTime `
            -RunAsUser        $RunAsUser `
            -TaskName         'AD-AttackPath-WeeklyReport' `
            -TaskPath         '\SecurityAutomation\'

        Write-Ok "Scheduled task registered: \SecurityAutomation\AD-AttackPath-WeeklyReport"
        Write-Info "Frequency: $ScheduleFrequency on $ScheduleDay at $ScheduleTime"
        Write-Info "Run as: $RunAsUser"
    } catch {
        Write-Fail "Failed to register scheduled task: $_"
    }
}

# ============================================================
# SECTION 6: Verification
# ============================================================
Write-Step 'Verifying installation...'

$checks = @(
    @{ Path = Join-Path $InstallPath 'Invoke-ADAttackPathAnalysis.ps1'; Name = 'Main script' }
    @{ Path = Join-Path $InstallPath 'Config\config.json'; Name = 'Configuration file' }
    @{ Path = Join-Path $InstallPath 'Modules\ADDataCollector.psm1'; Name = 'AD Collector module' }
    @{ Path = Join-Path $InstallPath 'Modules\HTMLReportGenerator.psm1'; Name = 'HTML Report module' }
    @{ Path = Join-Path $InstallPath 'Modules\RiskScoringEngine.psm1'; Name = 'Risk Scoring module' }
    @{ Path = Join-Path $InstallPath 'Modules\AttackPathEngine.psm1'; Name = 'Attack Path Engine module' }
    @{ Path = Join-Path $InstallPath 'Modules\BaselineManager.psm1'; Name = 'Baseline Manager module' }
    @{ Path = Join-Path $InstallPath 'Modules\EmailModule.psm1'; Name = 'Email module' }
)

$allOk = $true
foreach ($check in $checks) {
    if (Test-Path $check.Path) {
        Write-Ok "$($check.Name)"
    } else {
        Write-Fail "$($check.Name) - NOT FOUND: $($check.Path)"
        $allOk = $false
    }
}

# ============================================================
# SECTION 7: Post-Install Instructions
# ============================================================
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host '   Installation Complete!' -ForegroundColor Green
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '  NEXT STEPS:' -ForegroundColor White
Write-Host ''
Write-Host "  1. Edit configuration:" -ForegroundColor Yellow
Write-Host "     notepad `"$configDest`""
Write-Host ''
Write-Host "  2. Configure email (if desired):" -ForegroundColor Yellow
Write-Host '     Set Email.Enabled = true, SmtpServer, ToRecipients in config.json'
Write-Host ''
Write-Host "  3. Run your first analysis:" -ForegroundColor Yellow
Write-Host "     powershell -File `"$(Join-Path $InstallPath 'Invoke-ADAttackPathAnalysis.ps1')`""
Write-Host ''
Write-Host "  4. View the HTML report in:" -ForegroundColor Yellow
Write-Host "     $(Join-Path $InstallPath 'Reports')"
Write-Host ''
if ($ConfigureScheduler) {
    Write-Host "  5. Scheduled task configured:" -ForegroundColor Yellow
    Write-Host "     Task Scheduler > \SecurityAutomation\AD-AttackPath-WeeklyReport"
    Write-Host ''
}
Write-Host "  Log file: $(Join-Path $InstallPath 'Logs')" -ForegroundColor Gray
Write-Host ''

if (-not $allOk) {
    Write-Warn 'Some verification checks failed. Review the output above.'
    exit 1
}
