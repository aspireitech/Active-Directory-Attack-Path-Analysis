#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Main entry point for the AD Attack Path Analysis and Identity Exposure Reporting Platform.

.DESCRIPTION
    Orchestrates full Active Directory security analysis including:
    - Data collection from all AD objects, ACLs, and delegations
    - Graph-based attack path discovery
    - Risk scoring with MITRE ATT&CK mapping
    - Baseline comparison and change detection
    - BloodHound integration (optional)
    - HTML/Excel/PDF/CSV report generation
    - Automated email delivery

.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to .\Config\config.json.

.PARAMETER OutputPath
    Directory where reports will be saved. Overrides config setting.

.PARAMETER Credential
    PSCredential to use for AD queries. Defaults to current user context.

.PARAMETER AutoRun
    Switch to suppress interactive prompts (for scheduled task execution).

.PARAMETER SkipEmail
    Override config and skip email sending.

.PARAMETER SkipBloodHound
    Override config and skip BloodHound integration.

.PARAMETER GenerateBaseline
    Generate a new baseline from current results only (no report).

.EXAMPLE
    .\Invoke-ADAttackPathAnalysis.ps1

.EXAMPLE
    .\Invoke-ADAttackPathAnalysis.ps1 -ConfigPath D:\Config\prod-config.json -OutputPath D:\Reports

.EXAMPLE
    .\Invoke-ADAttackPathAnalysis.ps1 -AutoRun -SkipEmail
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath  = "$PSScriptRoot\Config\config.json",
    [string]$OutputPath  = '',
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$AutoRun,
    [switch]$SkipEmail,
    [switch]$SkipBloodHound,
    [switch]$GenerateBaseline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Bootstrap

$script:StartTime    = Get-Date
$script:PlatformRoot = $PSScriptRoot
$script:ModuleDir    = Join-Path $PSScriptRoot 'Modules'

# Import all modules
$modules = @(
    'Logger',
    'ADDataCollector',
    'RiskScoringEngine',
    'AttackPathEngine',
    'BaselineManager',
    'BloodHoundIntegration',
    'HTMLReportGenerator',
    'ExcelExporter',
    'PDFExporter',
    'EmailModule',
    'SchedulerModule'
)

foreach ($mod in $modules) {
    $modPath = Join-Path $script:ModuleDir "$mod.psm1"
    if (Test-Path $modPath) {
        Import-Module $modPath -Force -ErrorAction Stop
    } else {
        Write-Warning "Module not found: $modPath"
    }
}

#endregion

#region Configuration

function Load-Config {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path"
    }
    $json = Get-Content $Path -Raw -Encoding UTF8
    return $json | ConvertFrom-Json -AsHashtable
}

$config = Load-Config -Path $ConfigPath

# Apply parameter overrides
if ($OutputPath) {
    $config.General.ReportStoragePath  = $OutputPath
    $config.General.BaselineStoragePath = Join-Path $OutputPath 'Baselines'
    $config.General.LogStoragePath      = Join-Path $OutputPath 'Logs'
}

# Ensure output directories exist
foreach ($dir in @($config.General.ReportStoragePath, $config.General.BaselineStoragePath, $config.General.LogStoragePath)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

#endregion

#region Initialize Logger

Initialize-Logger `
    -LogDirectory $config.General.LogStoragePath `
    -MinLevel     $config.General.LogLevel

Write-LogSeparator -Title "AD Attack Path Analysis Platform - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Platform root: $script:PlatformRoot" -Level INFO
Write-Log "Config: $ConfigPath"                 -Level INFO
Write-Log "Output: $($config.General.ReportStoragePath)" -Level INFO
Write-Log "Domain: $($config.General.OrganizationName)"  -Level INFO

#endregion

#region Execution Context

if (-not $AutoRun) {
    $adModule = Get-Module -Name ActiveDirectory -ListAvailable
    if (-not $adModule) {
        Write-Log "ActiveDirectory module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell" -Level CRITICAL
        throw "ActiveDirectory PowerShell module required."
    }
}

#endregion

try {
    # =========================================================
    # STEP 1: Collect Active Directory Data
    # =========================================================
    Write-LogSeparator -Title 'Step 1: Active Directory Data Collection'

    $adData = Invoke-ADDataCollection -Config $config -Credential $Credential

    Write-Log "Collection complete: $($adData.Users.Count) users, $($adData.Groups.Count) groups, $($adData.Computers.Count) computers" -Level SUCCESS

    if ($GenerateBaseline) {
        Write-Log "Baseline-only mode: generating baseline and exiting." -Level INFO
        $tempResults = @{ DomainRiskScore = 0; DomainSeverity = 'Unknown'; TotalFindings = 0; CriticalCount = 0; HighCount = 0; MediumCount = 0; LowCount = 0; Findings = @() }
        Save-Baseline -RiskResults $tempResults -ADData $adData -BaselineDirectory $config.General.BaselineStoragePath
        Write-Log "Baseline saved." -Level SUCCESS
        return
    }

    # =========================================================
    # STEP 2: BloodHound Integration (if enabled)
    # =========================================================
    $bloodHoundData = $null
    if ($config.BloodHound.Enabled -and -not $SkipBloodHound) {
        Write-LogSeparator -Title 'Step 2: BloodHound Integration'
        try {
            $bhConnected = $false
            if ($config.BloodHound.Edition -eq 'Enterprise') {
                $bhConnected = Connect-BloodHoundEnterprise `
                    -ServerUrl $config.BloodHound.ServerUrl `
                    -ApiKey    $config.BloodHound.ApiKey
            } else {
                $bhSec = if ($config.BloodHound.Password) { ConvertTo-SecureString $config.BloodHound.Password -AsPlainText -Force } else { $null }
                $bhConnected = Connect-BloodHoundCE `
                    -ServerUrl $config.BloodHound.ServerUrl `
                    -Username  $config.BloodHound.Username `
                    -Password  $bhSec `
                    -ApiKey    $config.BloodHound.ApiKey
            }

            if ($bhConnected) {
                $bhPaths = Get-BloodHoundAttackPaths -DomainSID $adData.Domain.DomainSID
                $bhKerb  = Get-BHKerberoastableUsers
                $bloodHoundData = @{ AttackPaths = $bhPaths; KerberoastableUsers = $bhKerb }
                Write-Log "BloodHound: $($bhPaths.Count) paths, $($bhKerb.Count) Kerberoastable" -Level SUCCESS
            }
        } catch {
            Write-Log "BloodHound integration error: $_" -Level WARNING
        }
    } else {
        Write-Log "BloodHound integration: disabled" -Level INFO
    }

    # =========================================================
    # STEP 3: Risk Scoring
    # =========================================================
    Write-LogSeparator -Title 'Step 3: Risk Scoring Engine'

    $riskResults = Invoke-RiskScoring -ADData $adData -Config $config

    Write-Log "Risk scoring: score=$($riskResults.DomainRiskScore) ($($riskResults.DomainSeverity)), findings=$($riskResults.TotalFindings) [C:$($riskResults.CriticalCount) H:$($riskResults.HighCount) M:$($riskResults.MediumCount) L:$($riskResults.LowCount)]" -Level SUCCESS

    # =========================================================
    # STEP 4: Attack Path Analysis
    # =========================================================
    $attackPathData = $null
    if ($config.Analysis.EnableAttackPaths) {
        Write-LogSeparator -Title 'Step 4: Attack Path Analysis'
        try {
            $graph         = Build-ADGraph -ADData $adData
            $paths         = Find-AttackPaths -GraphData $graph -Config $config
            $pathStats     = Get-AttackPathStats -AttackPaths $paths
            $attackPathData = @{ Paths = $paths; Stats = $pathStats }

            # Merge BloodHound paths
            if ($bloodHoundData -and $bloodHoundData.AttackPaths.Count -gt 0) {
                foreach ($bhPath in $bloodHoundData.AttackPaths) {
                    $paths += $bhPath
                }
            }

            $riskResults.AttackPathCount = $paths.Count
            Write-Log "Attack paths: $($paths.Count) total [C:$($pathStats.CriticalPaths) H:$($pathStats.HighPaths)]" -Level SUCCESS
        } catch {
            Write-Log "Attack path analysis error: $_" -Level WARNING
        }
    }

    # =========================================================
    # STEP 5: Baseline Comparison
    # =========================================================
    Write-LogSeparator -Title 'Step 5: Baseline Comparison'

    $baselineFile = Save-Baseline `
        -RiskResults       $riskResults `
        -ADData            $adData `
        -BaselineDirectory $config.General.BaselineStoragePath

    $previousBaseline = Load-LatestBaseline -BaselineDirectory $config.General.BaselineStoragePath
    $comparison = Compare-WithBaseline -CurrentResults $riskResults -PreviousBaseline $previousBaseline

    if ($comparison.HasPreviousBaseline) {
        Write-Log "Comparison: $($comparison.Summary)" -Level INFO
        # Mark new findings
        foreach ($f in $comparison.NewFindings) {
            $match = $riskResults.Findings | Where-Object { $_.ID -eq $f.ID }
            if ($match) { $match.NewFinding = $true }
        }
    }

    Remove-OldBaselines -BaselineDirectory $config.General.BaselineStoragePath -RetentionDays $config.General.RetentionDays

    # =========================================================
    # STEP 6: Generate Reports
    # =========================================================
    Write-LogSeparator -Title 'Step 6: Report Generation'

    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $reportBase  = Join-Path $config.General.ReportStoragePath "ADAttackPath_$timestamp"
    $htmlPath    = "$reportBase.html"
    $excelPath   = "$reportBase.xlsx"
    $pdfPath     = "$reportBase.pdf"
    $csvPath     = "$reportBase.csv"

    # HTML Report
    Write-Log "Generating HTML report..." -Level INFO
    New-HTMLReport `
        -ADData        $adData `
        -RiskResults   $riskResults `
        -AttackPaths   $attackPathData `
        -Comparison    $comparison `
        -Config        $config `
        -OutputPath    $htmlPath

    # Excel Export
    Write-Log "Generating Excel workbook..." -Level INFO
    try {
        Export-ToExcel `
            -RiskResults  $riskResults `
            -ADData       $adData `
            -AttackPaths  $attackPathData `
            -Comparison   $comparison `
            -OutputPath   $excelPath
    } catch {
        Write-Log "Excel export failed (ImportExcel may not be installed): $_" -Level WARNING
        # CSV fallback
        Export-FallbackCSV -RiskResults $riskResults -OutputPath $csvPath
    }

    # PDF Export
    Write-Log "Generating PDF report..." -Level INFO
    try {
        Export-ToPDF `
            -HtmlReportPath $htmlPath `
            -OutputPdfPath  $pdfPath `
            -RiskResults    $riskResults `
            -Config         $config
    } catch {
        Write-Log "PDF export failed: $_" -Level WARNING
    }

    # CSV Export (always)
    $riskResults.Findings | ForEach-Object {
        [PSCustomObject]@{
            Severity       = $_.Severity
            Score          = $_.Score
            FindingType    = $_.FindingType
            Title          = $_.Title
            SourceIdentity = $_.SourceIdentity
            TargetObject   = $_.TargetObject
            MitreID        = $_.MitreID
            NewFinding     = $_.NewFinding
            Remediation    = $_.Remediation
        }
    } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV exported: $csvPath" -Level SUCCESS

    # =========================================================
    # STEP 7: Email Report
    # =========================================================
    if ($config.Email.Enabled -and -not $SkipEmail) {
        Write-LogSeparator -Title 'Step 7: Email Delivery'
        try {
            $attachments = @()
            if (Test-Path $htmlPath)  { $attachments += $htmlPath  }
            if (Test-Path $excelPath) { $attachments += $excelPath }
            if (Test-Path $csvPath)   { $attachments += $csvPath   }
            if (Test-Path $pdfPath)   { $attachments += $pdfPath   }
            if (Test-Path $baselineFile) { $attachments += $baselineFile }

            Send-ADSecurityReport `
                -RiskResults      $riskResults `
                -Comparison       $comparison `
                -AttachmentPaths  $attachments `
                -Config           $config

        } catch {
            Write-Log "Email delivery failed: $_" -Level ERROR
        }
    } else {
        Write-Log "Email: disabled or skipped." -Level INFO
    }

    # =========================================================
    # STEP 8: Summary
    # =========================================================
    Write-LogSeparator -Title 'Execution Summary'

    $elapsed = (Get-Date) - $script:StartTime
    Write-Log "Completed in $([Math]::Round($elapsed.TotalMinutes,1)) minutes" -Level SUCCESS
    Write-Log "Domain Risk Score : $($riskResults.DomainRiskScore) / 100 ($($riskResults.DomainSeverity))" -Level $(if($riskResults.DomainSeverity -eq 'Critical'){'CRITICAL'} elseif($riskResults.DomainSeverity -eq 'High'){'WARNING'} else {'SUCCESS'})
    Write-Log "Total Findings    : $($riskResults.TotalFindings) [Critical:$($riskResults.CriticalCount) High:$($riskResults.HighCount) Medium:$($riskResults.MediumCount) Low:$($riskResults.LowCount)]" -Level INFO
    if ($attackPathData) {
        Write-Log "Attack Paths      : $($attackPathData.Paths.Count) [Critical:$($attackPathData.Stats.CriticalPaths) High:$($attackPathData.Stats.HighPaths)]" -Level INFO
    }
    Write-Log "HTML Report       : $htmlPath"  -Level INFO
    Write-Log "Excel Report      : $excelPath" -Level INFO
    Write-Log "CSV Report        : $csvPath"   -Level INFO
    if (Test-Path $pdfPath) { Write-Log "PDF Report        : $pdfPath" -Level INFO }
    Write-Log "Baseline          : $baselineFile" -Level INFO
    Write-Log "Log File          : $(Get-LogPath)" -Level INFO

    # Return results for pipeline use
    return [ordered]@{
        DomainRiskScore = $riskResults.DomainRiskScore
        DomainSeverity  = $riskResults.DomainSeverity
        TotalFindings   = $riskResults.TotalFindings
        CriticalCount   = $riskResults.CriticalCount
        HighCount       = $riskResults.HighCount
        HTMLReport      = $htmlPath
        ExcelReport     = $excelPath
        BaselineFile    = $baselineFile
        LogFile         = Get-LogPath
    }

} catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level CRITICAL
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    if (-not $AutoRun) { throw }
    exit 1
}
