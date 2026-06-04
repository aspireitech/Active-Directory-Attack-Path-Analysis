#Requires -Version 5.1
<#
.SYNOPSIS
    PDF export module. Generates a PDF executive summary from the HTML report.
    Supports wkhtmltopdf (preferred) and Windows Print-to-PDF fallback.
#>

function Export-ToPDF {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HtmlReportPath,

        [Parameter(Mandatory)]
        [string]$OutputPdfPath,

        [hashtable]$RiskResults,
        [hashtable]$Config
    )

    if (-not (Test-Path $HtmlReportPath)) {
        Write-Log "HTML report not found: $HtmlReportPath" -Level ERROR -Component PDF
        return $null
    }

    # Try wkhtmltopdf first
    $wkhtmlPath = Find-WkHtmlToPdf
    if ($wkhtmlPath) {
        return Export-ViaWkHtml -HtmlPath $HtmlReportPath -PdfPath $OutputPdfPath -WkHtmlPath $wkhtmlPath
    }

    # Try Chromium/Chrome headless
    $chromePath = Find-Chrome
    if ($chromePath) {
        return Export-ViaChrome -HtmlPath $HtmlReportPath -PdfPath $OutputPdfPath -ChromePath $chromePath
    }

    # Generate a standalone executive summary HTML file optimized for print
    Write-Log "No PDF renderer found. Generating print-optimized HTML summary." -Level WARNING -Component PDF
    return Export-PrintOptimizedSummary -RiskResults $RiskResults -OutputPath ($OutputPdfPath -replace '\.pdf$','_summary.html') -Config $Config
}

function Find-WkHtmlToPdf {
    $searchPaths = @(
        'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
        'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
        '/usr/bin/wkhtmltopdf',
        '/usr/local/bin/wkhtmltopdf'
    )
    foreach ($p in $searchPaths) { if (Test-Path $p) { return $p } }
    $found = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    return $null
}

function Find-Chrome {
    $searchPaths = @(
        'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
        'C:\Program Files\Chromium\Application\chromium.exe',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium-browser',
        '/usr/bin/chromium'
    )
    foreach ($p in $searchPaths) { if (Test-Path $p) { return $p } }
    return $null
}

function Export-ViaWkHtml {
    param($HtmlPath, $PdfPath, $WkHtmlPath)
    try {
        $args = @(
            '--enable-local-file-access',
            '--page-size', 'A4',
            '--orientation', 'Portrait',
            '--margin-top', '10mm',
            '--margin-bottom', '10mm',
            '--margin-left', '10mm',
            '--margin-right', '10mm',
            '--encoding', 'UTF-8',
            '--title', 'AD Attack Path Analysis Report',
            '--footer-center', '[page] of [topage]',
            '--footer-font-size', '8',
            '--no-stop-slow-scripts',
            $HtmlPath,
            $PdfPath
        )
        $result = & $WkHtmlPath @args 2>&1
        if (Test-Path $PdfPath) {
            Write-Log "PDF exported via wkhtmltopdf: $PdfPath" -Level SUCCESS -Component PDF
            return $PdfPath
        }
        Write-Log "wkhtmltopdf completed but PDF not found: $result" -Level WARNING -Component PDF
        return $null
    } catch {
        Write-Log "wkhtmltopdf failed: $_" -Level ERROR -Component PDF
        return $null
    }
}

function Export-ViaChrome {
    param($HtmlPath, $PdfPath, $ChromePath)
    try {
        $absPath = (Resolve-Path $HtmlPath).Path
        $args = @(
            '--headless',
            '--disable-gpu',
            '--no-sandbox',
            '--print-to-pdf=' + $PdfPath,
            '--print-to-pdf-no-header',
            "file:///$($absPath -replace '\\','/')"
        )
        $result = & $ChromePath @args 2>&1
        if (Test-Path $PdfPath) {
            Write-Log "PDF exported via Chrome headless: $PdfPath" -Level SUCCESS -Component PDF
            return $PdfPath
        }
        return $null
    } catch {
        Write-Log "Chrome headless PDF failed: $_" -Level ERROR -Component PDF
        return $null
    }
}

function Export-PrintOptimizedSummary {
    param($RiskResults, $OutputPath, $Config)

    $orgName  = $Config.General.OrganizationName
    $genDate  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $scoreColor = switch ($RiskResults.DomainSeverity) {
        'Critical' { '#dc3545' } 'High' { '#fd7e14' } 'Medium' { '#e6ac00' } default { '#28a745' }
    }

    $critFindings = @($RiskResults.Findings | Where-Object { $_.Severity -eq 'Critical' })
    $highFindings = @($RiskResults.Findings | Where-Object { $_.Severity -eq 'High' })

    $critRows = $critFindings | Select-Object -First 10 | ForEach-Object {
        "<tr><td style='color:#dc3545;font-weight:bold'>CRITICAL</td><td>$($_.FindingType)</td><td>$($_.Title)</td><td>$($_.SourceIdentity)</td></tr>"
    }

    $topRemediation = @($RiskResults.Findings | Where-Object { $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' } | Select-Object -First 5)
    $remedRows = $topRemediation | ForEach-Object {
        "<tr><td style='color:$(if($_.Severity -eq 'Critical'){'#dc3545'}else{'#fd7e14'})'>$($_.Severity)</td><td>$($_.Title)</td><td>$($_.Remediation.Substring(0, [Math]::Min(200, $_.Remediation.Length)))...</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>AD Security Executive Summary - $orgName</title>
<style>
  body { font-family: Arial, sans-serif; font-size: 12px; margin: 20px; color: #333; }
  h1 { font-size: 20px; color: #1a1a2e; } h2 { font-size: 15px; color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 4px; }
  .header { background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
  .score-box { display: inline-block; background: $scoreColor; color: white; border-radius: 50%; width: 100px; height: 100px; text-align: center; padding-top: 25px; font-size: 32px; font-weight: bold; float: right; }
  .metric { display: inline-block; padding: 10px 20px; margin: 5px; border-radius: 6px; text-align: center; color: white; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; } th { background: #1a1a2e; color: white; padding: 8px; text-align: left; font-size: 11px; }
  td { padding: 6px 8px; border-bottom: 1px solid #eee; font-size: 11px; } tr:nth-child(even) { background: #f8f9fa; }
  @media print { .no-print { display: none; } }
</style>
</head>
<body>
<div class='header'>
  <div class='score-box'>$($RiskResults.DomainRiskScore)<br><span style='font-size:10px'>$($RiskResults.DomainSeverity)</span></div>
  <h1 style='color:white;margin:0'>&#128737; AD Attack Path Analysis</h1>
  <p style='margin:5px 0;opacity:.8'>$orgName &bull; Generated: $genDate</p>
</div>

<h2>Risk Summary</h2>
<div>
  <span class='metric' style='background:#dc3545'>Critical: $($RiskResults.CriticalCount)</span>
  <span class='metric' style='background:#fd7e14'>High: $($RiskResults.HighCount)</span>
  <span class='metric' style='background:#ffc107;color:#212529'>Medium: $($RiskResults.MediumCount)</span>
  <span class='metric' style='background:#28a745'>Low: $($RiskResults.LowCount)</span>
  <span class='metric' style='background:#6c757d'>Total: $($RiskResults.TotalFindings)</span>
</div>

<h2>Critical Findings Requiring Immediate Action</h2>
$(if($critFindings.Count -gt 0) {
    "<table><tr><th>Severity</th><th>Type</th><th>Title</th><th>Source</th></tr>$($critRows -join '')</table>"
} else { "<p style='color:green'>&#10003; No critical findings.</p>" })

<h2>Priority Remediation Actions</h2>
$(if($topRemediation.Count -gt 0) {
    "<table><tr><th>Severity</th><th>Finding</th><th>Remediation (Summary)</th></tr>$($remedRows -join '')</table>"
} else { "<p style='color:green'>&#10003; No high-priority remediations required.</p>" })

<p style='color:#6c757d;font-size:10px;margin-top:30px;border-top:1px solid #eee;padding-top:10px;'>
  Confidential - AD Attack Path Analysis Platform | $orgName | $genDate
</p>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "Print-optimized summary generated: $OutputPath" -Level SUCCESS -Component PDF
    return $OutputPath
}

Export-ModuleMember -Function Export-ToPDF
