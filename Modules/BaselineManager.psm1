#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline management module. Saves, loads, and compares AD security baselines.
    Detects new, removed, and modified findings week-over-week.
#>

#region Save / Load

function Save-Baseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RiskResults,

        [Parameter(Mandatory)]
        [hashtable]$ADData,

        [Parameter(Mandatory)]
        [string]$BaselineDirectory
    )

    if (-not (Test-Path $BaselineDirectory)) {
        New-Item -ItemType Directory -Path $BaselineDirectory -Force | Out-Null
    }

    $timestamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baselineFile = Join-Path $BaselineDirectory "baseline_$timestamp.json"

    $baseline = [ordered]@{
        Timestamp       = Get-Date -Format 'o'
        DomainName      = $ADData.Domain.DNSRoot
        DomainRiskScore = $RiskResults.DomainRiskScore
        DomainSeverity  = $RiskResults.DomainSeverity
        TotalFindings   = $RiskResults.TotalFindings
        CriticalCount   = $RiskResults.CriticalCount
        HighCount       = $RiskResults.HighCount
        MediumCount     = $RiskResults.MediumCount
        LowCount        = $RiskResults.LowCount
        Findings        = @($RiskResults.Findings | ForEach-Object {
            [ordered]@{
                ID          = $_.ID
                FindingType = $_.FindingType
                Severity    = $_.Severity
                Score       = $_.Score
                Title       = $_.Title
                SourceIdentity = $_.SourceIdentity
                TargetObject   = $_.TargetObject
            }
        })
        Stats = [ordered]@{
            TotalUsers          = $ADData.Users.Count
            TotalGroups         = $ADData.Groups.Count
            TotalComputers      = $ADData.Computers.Count
            TotalPrivileged     = $ADData.PrivilegedGroups | ForEach-Object { $_.NestedMemberCount } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            Kerberoastable      = $ADData.KerberoastableAccounts.Count
            ASREPRoastable      = $ADData.ASREPRoastableAccounts.Count
            DCSyncAccounts      = $ADData.DCSyncAccounts.Count
            ShadowAdmins        = $ADData.ShadowAdmins.Count
            DelegationIssues    = $ADData.DelegationFindings.Count
            ACLFindings         = $ADData.ACLFindings.Count
        }
    }

    $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-Log "Baseline saved: $baselineFile" -Level SUCCESS -Component BaselineManager
    return $baselineFile
}

function Load-LatestBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaselineDirectory
    )

    if (-not (Test-Path $BaselineDirectory)) { return $null }

    $baselines = Get-ChildItem -Path $BaselineDirectory -Filter 'baseline_*.json' |
                 Sort-Object LastWriteTime -Descending

    if ($baselines.Count -lt 2) {
        Write-Log "No previous baseline found for comparison." -Level INFO -Component BaselineManager
        return $null
    }

    # Return the second-most-recent (most recent is the one we just saved)
    $previousBaseline = $baselines[1]
    Write-Log "Loading previous baseline: $($previousBaseline.Name)" -Level INFO -Component BaselineManager

    try {
        $content  = Get-Content $previousBaseline.FullName -Raw -Encoding UTF8
        $baseline = $content | ConvertFrom-Json
        return $baseline
    } catch {
        Write-Log "Failed to load baseline: $_" -Level ERROR -Component BaselineManager
        return $null
    }
}

function Load-BaselineByDate {
    [CmdletBinding()]
    param(
        [string]$BaselineDirectory,
        [datetime]$Date
    )
    $baselines = Get-ChildItem -Path $BaselineDirectory -Filter 'baseline_*.json' |
                 Where-Object { $_.LastWriteTime.Date -eq $Date.Date } |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1

    if (-not $baselines) { return $null }
    return Get-Content $baselines.FullName -Raw | ConvertFrom-Json
}

#endregion

#region Comparison

function Compare-WithBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CurrentResults,

        [Parameter(Mandatory)]
        $PreviousBaseline  # PSCustomObject from JSON
    )

    if (-not $PreviousBaseline) {
        return [ordered]@{
            HasPreviousBaseline = $false
            Summary             = 'No previous baseline available for comparison.'
            NewFindings         = @()
            RemovedFindings     = @()
            ModifiedFindings    = @()
            ScoreChange         = 0
            ScoreDirection      = 'Unchanged'
            NewAttackPaths      = @()
            TrendData           = @{}
        }
    }

    $currentFindings  = @($CurrentResults.Findings)
    $previousFindings = @($PreviousBaseline.Findings)

    # Key findings by Title + SourceIdentity for comparison
    $currentKeys  = @{}
    $previousKeys = @{}

    foreach ($f in $currentFindings) {
        $key = "$($f.FindingType)|$($f.SourceIdentity)|$($f.TargetObject)"
        $currentKeys[$key] = $f
    }
    foreach ($f in $previousFindings) {
        $key = "$($f.FindingType)|$($f.SourceIdentity)|$($f.TargetObject)"
        $previousKeys[$key] = $f
    }

    # New findings = in current but not in previous
    $newFindings = @(foreach ($key in $currentKeys.Keys) {
        if (-not $previousKeys.ContainsKey($key)) {
            $f = $currentKeys[$key]
            $f.NewFinding = $true
            $f
        }
    })

    # Removed findings = in previous but not in current
    $removedFindings = @(foreach ($key in $previousKeys.Keys) {
        if (-not $currentKeys.ContainsKey($key)) {
            $previousKeys[$key]
        }
    })

    # Modified findings = in both but with changed severity/score
    $modifiedFindings = @(foreach ($key in $currentKeys.Keys) {
        if ($previousKeys.ContainsKey($key)) {
            $curr = $currentKeys[$key]
            $prev = $previousKeys[$key]
            if ($curr.Severity -ne $prev.Severity -or $curr.Score -ne $prev.Score) {
                [ordered]@{
                    Key              = $key
                    CurrentSeverity  = $curr.Severity
                    PreviousSeverity = $prev.Severity
                    CurrentScore     = $curr.Score
                    PreviousScore    = $prev.Score
                    ScoreChange      = $curr.Score - $prev.Score
                    Direction        = if ($curr.Score -gt $prev.Score) { 'Increased' } else { 'Decreased' }
                    FindingType      = $curr.FindingType
                    Title            = $curr.Title
                }
            }
        }
    })

    $scoreChange    = $CurrentResults.DomainRiskScore - $PreviousBaseline.DomainRiskScore
    $scoreDirection = if ($scoreChange -gt 0) { 'Increased' } elseif ($scoreChange -lt 0) { 'Decreased' } else { 'Unchanged' }

    # Trend data for charts
    $trendData = [ordered]@{
        PreviousScore       = $PreviousBaseline.DomainRiskScore
        CurrentScore        = $CurrentResults.DomainRiskScore
        PreviousCritical    = $PreviousBaseline.CriticalCount
        CurrentCritical     = $CurrentResults.CriticalCount
        PreviousHigh        = $PreviousBaseline.HighCount
        CurrentHigh         = $CurrentResults.HighCount
        PreviousMedium      = $PreviousBaseline.MediumCount
        CurrentMedium       = $CurrentResults.MediumCount
        PreviousKerberoast  = $PreviousBaseline.Stats.Kerberoastable
        CurrentKerberoast   = $CurrentResults.Findings | Where-Object FindingType -eq 'Kerberoasting' | Measure-Object | Select-Object -ExpandProperty Count
        PreviousDCSync      = $PreviousBaseline.Stats.DCSyncAccounts
        PreviousDate        = $PreviousBaseline.Timestamp
        CurrentDate         = Get-Date -Format 'o'
    }

    # Highlight critical new findings
    $criticalNewFindings = @($newFindings | Where-Object { $_.Severity -eq 'Critical' })

    return [ordered]@{
        HasPreviousBaseline       = $true
        PreviousBaselineDate      = $PreviousBaseline.Timestamp
        Summary                   = Build-ComparisonSummary -New $newFindings -Removed $removedFindings -Modified $modifiedFindings -ScoreChange $scoreChange
        NewFindings               = $newFindings
        RemovedFindings           = $removedFindings
        ModifiedFindings          = $modifiedFindings
        CriticalNewFindings       = $criticalNewFindings
        ScoreChange               = $scoreChange
        ScoreDirection            = $scoreDirection
        TrendData                 = $trendData
        WeeklyStats               = [ordered]@{
            PreviousDate          = $PreviousBaseline.Timestamp
            PreviousTotalUsers    = $PreviousBaseline.Stats.TotalUsers
            CurrentTotalUsers     = $trendData.PreviousKerberoast  # Placeholder
            NewFindingsCount      = $newFindings.Count
            RemovedFindingsCount  = $removedFindings.Count
            ModifiedFindingsCount = $modifiedFindings.Count
            NewCritical           = @($newFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            NewHigh               = @($newFindings | Where-Object { $_.Severity -eq 'High'     }).Count
        }
    }
}

function Build-ComparisonSummary {
    param($New, $Removed, $Modified, [int]$ScoreChange)

    $parts = @()
    if ($New.Count -gt 0) {
        $parts += "$($New.Count) new finding$(if($New.Count -ne 1){'s'})"
        $critNew = @($New | Where-Object { $_.Severity -eq 'Critical' }).Count
        if ($critNew -gt 0) { $parts[-1] += " ($critNew CRITICAL)" }
    }
    if ($Removed.Count -gt 0) {
        $parts += "$($Removed.Count) finding$(if($Removed.Count -ne 1){'s'}) resolved"
    }
    if ($Modified.Count -gt 0) {
        $parts += "$($Modified.Count) finding$(if($Modified.Count -ne 1){'s'}) changed severity"
    }
    $scoreText = if ($ScoreChange -gt 0) { "Risk score INCREASED by $ScoreChange" }
                 elseif ($ScoreChange -lt 0) { "Risk score decreased by $([Math]::Abs($ScoreChange))" }
                 else { "Risk score unchanged" }
    $parts += $scoreText

    return $parts -join '; '
}

#endregion

#region Retention

function Remove-OldBaselines {
    [CmdletBinding()]
    param(
        [string]$BaselineDirectory,
        [int]$RetentionDays = 90
    )

    $cutoff   = (Get-Date).AddDays(-$RetentionDays)
    $oldFiles = Get-ChildItem -Path $BaselineDirectory -Filter 'baseline_*.json' |
                Where-Object { $_.LastWriteTime -lt $cutoff }

    foreach ($file in $oldFiles) {
        Remove-Item $file.FullName -Force
        Write-Log "Removed old baseline: $($file.Name)" -Level INFO -Component BaselineManager
    }

    Write-Log "Baseline retention: removed $($oldFiles.Count) file(s) older than $RetentionDays days." -Level INFO -Component BaselineManager
}

function Get-BaselineHistory {
    [CmdletBinding()]
    param([string]$BaselineDirectory)

    if (-not (Test-Path $BaselineDirectory)) { return @() }

    $baselines = Get-ChildItem -Path $BaselineDirectory -Filter 'baseline_*.json' |
                 Sort-Object LastWriteTime -Descending

    return @($baselines | ForEach-Object {
        try {
            $content = Get-Content $_.FullName -Raw | ConvertFrom-Json
            [ordered]@{
                FileName     = $_.Name
                Date         = $content.Timestamp
                DomainScore  = $content.DomainRiskScore
                Severity     = $content.DomainSeverity
                TotalFindings = $content.TotalFindings
                Critical     = $content.CriticalCount
                High         = $content.HighCount
            }
        } catch { }
    })
}

#endregion

Export-ModuleMember -Function Save-Baseline, Load-LatestBaseline, Load-BaselineByDate,
    Compare-WithBaseline, Remove-OldBaselines, Get-BaselineHistory
