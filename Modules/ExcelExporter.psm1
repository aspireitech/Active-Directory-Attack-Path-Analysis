#Requires -Version 5.1
<#
.SYNOPSIS
    Excel export module using ImportExcel module (no Office required).
    Generates multi-worksheet workbooks with conditional formatting.
#>

function Export-ToExcel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RiskResults,

        [Parameter(Mandatory)]
        [hashtable]$ADData,

        [hashtable]$AttackPaths,

        [hashtable]$Comparison,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # Ensure ImportExcel is available
    if (-not (Get-Module -Name ImportExcel -ListAvailable)) {
        Write-Log "ImportExcel module not found. Attempting install..." -Level WARNING -Component Excel
        try {
            Install-Module -Name ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
        } catch {
            Write-Log "Cannot install ImportExcel. Falling back to CSV export." -Level ERROR -Component Excel
            Export-FallbackCSV -RiskResults $RiskResults -OutputPath ($OutputPath -replace '\.xlsx$','.csv')
            return $null
        }
    }

    Import-Module ImportExcel -ErrorAction Stop

    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

    # --- Sheet 1: Executive Summary ---
    $execSummary = @(
        [PSCustomObject]@{ Metric = 'Domain Risk Score';         Value = $RiskResults.DomainRiskScore; Category = 'Risk Overview' }
        [PSCustomObject]@{ Metric = 'Domain Risk Severity';      Value = $RiskResults.DomainSeverity;  Category = 'Risk Overview' }
        [PSCustomObject]@{ Metric = 'Total Findings';            Value = $RiskResults.TotalFindings;   Category = 'Findings' }
        [PSCustomObject]@{ Metric = 'Critical Findings';         Value = $RiskResults.CriticalCount;   Category = 'Findings' }
        [PSCustomObject]@{ Metric = 'High Findings';             Value = $RiskResults.HighCount;       Category = 'Findings' }
        [PSCustomObject]@{ Metric = 'Medium Findings';           Value = $RiskResults.MediumCount;     Category = 'Findings' }
        [PSCustomObject]@{ Metric = 'Low Findings';              Value = $RiskResults.LowCount;        Category = 'Findings' }
        [PSCustomObject]@{ Metric = 'Total Users';               Value = $ADData.Users.Count;          Category = 'AD Statistics' }
        [PSCustomObject]@{ Metric = 'Total Groups';              Value = $ADData.Groups.Count;         Category = 'AD Statistics' }
        [PSCustomObject]@{ Metric = 'Total Computers';           Value = $ADData.Computers.Count;      Category = 'AD Statistics' }
        [PSCustomObject]@{ Metric = 'Kerberoastable Accounts';   Value = $ADData.KerberoastableAccounts.Count; Category = 'Attack Surface' }
        [PSCustomObject]@{ Metric = 'AS-REP Roastable Accounts'; Value = $ADData.ASREPRoastableAccounts.Count; Category = 'Attack Surface' }
        [PSCustomObject]@{ Metric = 'DCSync Capable Accounts';   Value = $ADData.DCSyncAccounts.Count; Category = 'Attack Surface' }
        [PSCustomObject]@{ Metric = 'Shadow Admins';             Value = $ADData.ShadowAdmins.Count;   Category = 'Attack Surface' }
        [PSCustomObject]@{ Metric = 'Delegation Findings';       Value = $ADData.DelegationFindings.Count; Category = 'Attack Surface' }
        [PSCustomObject]@{ Metric = 'ACL Findings';              Value = $ADData.ACLFindings.Count;    Category = 'Attack Surface' }
        [PSCustomObject]@{ Metric = 'Report Generated';          Value = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Category = 'Metadata' }
    )

    $execSummary | Export-Excel -Path $OutputPath -WorksheetName 'Executive Summary' `
        -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter `
        -TableStyle Medium2 -TableName 'ExecSummary'

    # --- Sheet 2: All Findings ---
    $findingsData = @($RiskResults.Findings | ForEach-Object {
        [PSCustomObject]@{
            Severity       = $_.Severity
            Score          = $_.Score
            FindingType    = $_.FindingType
            Title          = $_.Title
            SourceIdentity = $_.SourceIdentity
            TargetObject   = $_.TargetObject
            Description    = $_.Description
            ExploitMethod  = $_.ExploitMethod
            Remediation    = $_.Remediation
            RemediationRisk = $_.RemediationRisk
            MitreID        = $_.MitreID
            MitreName      = $_.MitreName
            MitreTactic    = $_.MitreTactic
            IsNew           = $_.NewFinding
            RootCause      = $_.RootCause
        }
    })

    if ($findingsData.Count -gt 0) {
        $xlPkg = $findingsData | Export-Excel -Path $OutputPath -WorksheetName 'All Findings' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter `
            -TableStyle Medium6 -TableName 'Findings' -PassThru

        # Conditional formatting for severity
        $ws = $xlPkg.Workbook.Worksheets['All Findings']
        Add-ConditionalFormatting -Worksheet $ws -Address 'A2:A10000' -RuleType Equal -ConditionValue 'Critical' -BackgroundColor '#dc3545' -ForegroundColor 'White'
        Add-ConditionalFormatting -Worksheet $ws -Address 'A2:A10000' -RuleType Equal -ConditionValue 'High'     -BackgroundColor '#fd7e14' -ForegroundColor 'White'
        Add-ConditionalFormatting -Worksheet $ws -Address 'A2:A10000' -RuleType Equal -ConditionValue 'Medium'   -BackgroundColor '#ffc107' -ForegroundColor 'Black'
        Add-ConditionalFormatting -Worksheet $ws -Address 'A2:A10000' -RuleType Equal -ConditionValue 'Low'      -BackgroundColor '#28a745' -ForegroundColor 'White'
        $xlPkg.Save()
        $xlPkg.Dispose()
    }

    # --- Sheet 3: Kerberoastable Accounts ---
    if ($ADData.KerberoastableAccounts.Count -gt 0) {
        $kerbData = @($ADData.KerberoastableAccounts | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName = $_.SamAccountName
                SPNs           = ($_.SPNs -join '; ')
                PasswordLastSet = $_.PasswordLastSet
                AdminCount     = $_.AdminCount
                IsHighPrivilege = $_.IsHighPrivilege
                MemberOf       = ($_.MemberOf -join '; ')
            }
        })
        $kerbData | Export-Excel -Path $OutputPath -WorksheetName 'Kerberoastable' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium3 -TableName 'Kerberoastable'
    }

    # --- Sheet 4: Delegation Issues ---
    if ($ADData.DelegationFindings.Count -gt 0) {
        $delegData = @($ADData.DelegationFindings | ForEach-Object {
            [PSCustomObject]@{
                Type              = $_.Type
                ObjectName        = $_.ObjectName
                ObjectType        = $_.ObjectType
                Risk              = $_.Risk
                Description       = $_.Description
                DelegatesTo       = if ($_.DelegatesTo) { $_.DelegatesTo -join '; ' } else { 'N/A' }
            }
        })
        $delegData | Export-Excel -Path $OutputPath -WorksheetName 'Delegation Issues' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium4 -TableName 'Delegation'
    }

    # --- Sheet 5: DCSync Rights ---
    if ($ADData.DCSyncAccounts.Count -gt 0) {
        $dcsyncData = @($ADData.DCSyncAccounts | ForEach-Object {
            [PSCustomObject]@{
                Identity      = $_.Identity
                Rights        = ($_.Rights -join '; ')
                HasFullDCSync = $_.HasFullDCSync
                Risk          = $_.Risk
                Description   = $_.Description
            }
        })
        $dcsyncData | Export-Excel -Path $OutputPath -WorksheetName 'DCSync Rights' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium9 -TableName 'DCSync'
    }

    # --- Sheet 6: Shadow Admins ---
    if ($ADData.ShadowAdmins.Count -gt 0) {
        $shadowData = @($ADData.ShadowAdmins | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                LastLogonDate     = $_.LastLogonDate
                Risk              = $_.Risk
                Reason            = $_.Reason
            }
        })
        $shadowData | Export-Excel -Path $OutputPath -WorksheetName 'Shadow Admins' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium2 -TableName 'ShadowAdmins'
    }

    # --- Sheet 7: Attack Paths ---
    if ($AttackPaths -and $AttackPaths.Paths.Count -gt 0) {
        $pathData = @($AttackPaths.Paths | ForEach-Object {
            [PSCustomObject]@{
                Severity      = $_.Severity
                RiskScore     = $_.RiskScore
                SourceLabel   = $_.SourceLabel
                TargetLabel   = $_.TargetLabel
                PathLength    = $_.PathLength
                ChainDisplay  = $_.ChainDisplay
                MitreID       = $_.MitreMapping.ID
                MitreName     = $_.MitreMapping.Name
                Remediation   = ($_.Remediation -join ' | ')
            }
        })
        $pathData | Export-Excel -Path $OutputPath -WorksheetName 'Attack Paths' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium7 -TableName 'AttackPaths'
    }

    # --- Sheet 8: Stale Accounts ---
    if ($ADData.StaleAccounts.Count -gt 0) {
        $staleData = @($ADData.StaleAccounts | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName = $_.SamAccountName
                LastLogonDate  = $_.LastLogonDate
                DaysSinceLogin = $_.DaysSinceLogin
                PasswordLastSet = $_.PasswordLastSet
                IsPrivileged   = $_.IsPrivileged
            }
        })
        $staleData | Export-Excel -Path $OutputPath -WorksheetName 'Stale Accounts' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium5 -TableName 'StaleAccounts'
    }

    # --- Sheet 9: Baseline Comparison (if available) ---
    if ($Comparison -and $Comparison.HasPreviousBaseline) {
        $compData = @(
            [PSCustomObject]@{ Category = 'New Findings';      Count = $Comparison.NewFindings.Count;      Details = '' }
            [PSCustomObject]@{ Category = 'Removed Findings';  Count = $Comparison.RemovedFindings.Count;  Details = '' }
            [PSCustomObject]@{ Category = 'Modified Findings'; Count = $Comparison.ModifiedFindings.Count; Details = '' }
            [PSCustomObject]@{ Category = 'Score Change';      Count = $Comparison.ScoreChange;            Details = $Comparison.ScoreDirection }
        )

        # Add new findings detail
        foreach ($f in $Comparison.NewFindings) {
            $compData += [PSCustomObject]@{
                Category = 'NEW'
                Count    = $f.Score
                Details  = $f.Title
            }
        }

        $compData | Export-Excel -Path $OutputPath -WorksheetName 'Week-over-Week' `
            -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium11 -TableName 'Comparison'
    }

    Write-Log "Excel report exported: $OutputPath" -Level SUCCESS -Component Excel
    return $OutputPath
}

function Export-FallbackCSV {
    param([hashtable]$RiskResults, [string]$OutputPath)

    $csvData = @($RiskResults.Findings | ForEach-Object {
        [PSCustomObject]@{
            Severity       = $_.Severity
            Score          = $_.Score
            FindingType    = $_.FindingType
            Title          = $_.Title
            SourceIdentity = $_.SourceIdentity
            TargetObject   = $_.TargetObject
            MitreID        = $_.MitreID
            Remediation    = $_.Remediation
        }
    })
    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV fallback export: $OutputPath" -Level WARNING -Component Excel
}

Export-ModuleMember -Function Export-ToExcel, Export-FallbackCSV
