#Requires -Version 5.1
<#
.SYNOPSIS
    Merges every CSV in a folder into a single, self-contained, offline-viewable HTML
    dashboard showing the Top-N Active Directory security gaps ranked by risk score.

.DESCRIPTION
    Designed to sit on top of Find-TopADSecurityGaps.ps1, but it will ingest ANY CSV that
    has (at least) these columns: Category, Severity, RiskScore, Finding, AffectedObject,
    Details, Recommendation. Extra columns are ignored; a source missing a required column
    is skipped with a warning rather than failing the whole run -- so you can point this at
    output from multiple different scans/tools and get one combined view.

    The dashboard is a single .html file with no external dependencies (no CDN, no
    internet required) -- safe to open on an isolated management host or a domain
    controller with no outbound access, and safe to email as an attachment.

.PARAMETER InputPath
    Folder containing one or more *.csv files to merge. Defaults to .\Output next to this script.

.PARAMETER OutputPath
    Path to write the dashboard .html file to. Defaults to a timestamped file in -InputPath.

.PARAMETER TopN
    How many findings to feature in the ranked table. 20 or 30 are typical. Default 30.

.PARAMETER OrganizationName
    Display name shown in the dashboard header.

.PARAMETER Open
    Switch to open the generated dashboard in the default browser when done.

.EXAMPLE
    .\New-SecurityGapsDashboard.ps1

.EXAMPLE
    .\New-SecurityGapsDashboard.ps1 -InputPath D:\ADScan -TopN 20 -OrganizationName 'Contoso' -Open

.EXAMPLE
    # Point it at CSVs produced by more than one run / more than one tool -- they all merge.
    .\New-SecurityGapsDashboard.ps1 -InputPath D:\ADScan -TopN 30
#>
[CmdletBinding()]
param(
    [string]$InputPath = (Join-Path $PSScriptRoot 'Output'),
    [string]$OutputPath,
    [ValidateRange(1,200)]
    [int]$TopN = 30,
    [string]$OrganizationName = 'Active Directory Security',
    [switch]$Open
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InputPath)) { throw "Input path not found: $InputPath" }

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutputPath) { $OutputPath = Join-Path $InputPath "SecurityGaps_Dashboard_$timestamp.html" }

function Write-Status {
    param([string]$Message, [ValidateSet('Info','Ok','Warn')] [string]$Level = 'Info')
    $color = switch ($Level) { 'Ok' { 'Green' } 'Warn' { 'Yellow' } default { 'Cyan' } }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $color
}

#region Ingest every CSV as a "source"

$requiredColumns = @('Category','Severity','RiskScore','Finding','AffectedObject','Details','Recommendation')
$csvFiles = @(Get-ChildItem -Path $InputPath -Filter '*.csv' -File -ErrorAction SilentlyContinue)
if (-not $csvFiles -or $csvFiles.Count -eq 0) {
    throw "No CSV files found in '$InputPath'. Run Find-TopADSecurityGaps.ps1 first, or point -InputPath at a folder containing findings CSVs."
}

Write-Status "Found $($csvFiles.Count) CSV source(s) in $InputPath"

$allFindings = [System.Collections.Generic.List[object]]::new()
$sourcesUsed  = [System.Collections.Generic.List[object]]::new()

foreach ($file in $csvFiles) {
    try {
        $rows = @(Import-Csv -Path $file.FullName)
    } catch {
        Write-Status "Skipped '$($file.Name)': could not parse as CSV ($($_.Exception.Message))" -Level Warn
        continue
    }

    if (-not $rows -or $rows.Count -eq 0) {
        Write-Status "  $($file.Name): 0 rows" -Level Info
        $sourcesUsed.Add([pscustomobject]@{ File = $file.Name; Rows = 0 })
        continue
    }

    $columns = $rows[0].PSObject.Properties.Name
    $missing = @($requiredColumns | Where-Object { $_ -notin $columns })
    if ($missing.Count -gt 0) {
        Write-Status "Skipped '$($file.Name)': missing required column(s): $($missing -join ', ')" -Level Warn
        continue
    }

    $kept = 0
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row.Finding)) { continue }
        $score = 0
        [void][int]::TryParse($row.RiskScore, [ref]$score)
        $severity = $row.Severity
        if ([string]::IsNullOrWhiteSpace($severity)) {
            $severity = if ($score -ge 90) { 'Critical' } elseif ($score -ge 70) { 'High' } elseif ($score -ge 40) { 'Medium' } else { 'Low' }
        }
        $allFindings.Add([PSCustomObject]@{
            Category       = $row.Category
            Severity       = $severity
            RiskScore      = $score
            Finding        = $row.Finding
            AffectedObject = $row.AffectedObject
            ObjectType     = if ($columns -contains 'ObjectType') { $row.ObjectType } else { '' }
            Details        = $row.Details
            Recommendation = $row.Recommendation
            MitreID        = if ($columns -contains 'MitreID') { $row.MitreID } else { '' }
            SourceFile     = $file.Name
        })
        $kept++
    }
    Write-Status "  $($file.Name): $kept finding(s) ingested"
    $sourcesUsed.Add([pscustomobject]@{ File = $file.Name; Rows = $kept })
}

if ($allFindings.Count -eq 0) {
    throw "No usable findings were ingested from any CSV in '$InputPath'."
}

Write-Status "Total findings merged from $($csvFiles.Count) source file(s): $($allFindings.Count)" -Level Ok

#endregion

#region Aggregate

$bySeverity = @($allFindings | Group-Object Severity)
$sevCount = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
foreach ($g in $bySeverity) { if ($sevCount.ContainsKey($g.Name)) { $sevCount[$g.Name] = $g.Count } }

$byCategory = @($allFindings | Group-Object Category | Sort-Object Count -Descending)

# Composite exposure score (0-100): weighted by severity mix across ALL ingested findings,
# not just the Top-N shown in the table, so it reflects the whole posture.
$weightedSum = ($sevCount.Critical * 10) + ($sevCount.High * 5) + ($sevCount.Medium * 2) + ($sevCount.Low * 1)
$exposureScore = [Math]::Min(100, $weightedSum)
$exposureLabel = if ($exposureScore -ge 90) { 'Critical' } elseif ($exposureScore -ge 70) { 'High' } elseif ($exposureScore -ge 40) { 'Medium' } else { 'Low' }

$topFindings = @($allFindings | Sort-Object RiskScore -Descending | Select-Object -First $TopN)

Write-Status "Composite exposure score: $exposureScore/100 ($exposureLabel). Rendering top $($topFindings.Count) of $($allFindings.Count) findings." -Level Ok

#endregion

#region HTML rendering helpers

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

$severityColors = @{
    Critical = @{ bg = '#fde8e8'; fg = '#9b1c1c'; bar = '#e02424' }
    High     = @{ bg = '#feecdc'; fg = '#9a5b13'; bar = '#f05a24' }
    Medium   = @{ bg = '#fdf6b2'; fg = '#8a6d0a'; bar = '#e3a008' }
    Low      = @{ bg = '#e1f5ea'; fg = '#03543f'; bar = '#0e9f6e' }
}

# Pure-CSS donut chart via conic-gradient -- no JS chart library, works fully offline.
$totalForDonut = [Math]::Max(1, ($sevCount.Critical + $sevCount.High + $sevCount.Medium + $sevCount.Low))
$critPct = [Math]::Round(($sevCount.Critical / $totalForDonut) * 100, 2)
$highPct = [Math]::Round(($sevCount.High     / $totalForDonut) * 100, 2)
$medPct  = [Math]::Round(($sevCount.Medium   / $totalForDonut) * 100, 2)
$lowPct  = [Math]::Round(100 - $critPct - $highPct - $medPct, 2)
if ($lowPct -lt 0) { $lowPct = 0 }
$c1 = $critPct
$c2 = $c1 + $highPct
$c3 = $c2 + $medPct
$donutGradient = "conic-gradient($($severityColors.Critical.bar) 0% $c1%, $($severityColors.High.bar) $c1% $c2%, $($severityColors.Medium.bar) $c2% $c3%, $($severityColors.Low.bar) $c3% 100%)"

$maxCategoryCount = ($byCategory | Measure-Object Count -Maximum).Maximum
if (-not $maxCategoryCount) { $maxCategoryCount = 1 }

$categoryRowsHtml = ($byCategory | ForEach-Object {
    $pct = [Math]::Round(($_.Count / $maxCategoryCount) * 100, 1)
    $name = ConvertTo-HtmlSafe $_.Name
    "<div class='cat-row'><div class='cat-label'>$name</div><div class='cat-bar-track'><div class='cat-bar-fill' style='width:$pct%'></div></div><div class='cat-count'>$($_.Count)</div></div>"
}) -join "`n"

$tableRowsHtml = ($topFindings | ForEach-Object {
    $i = $topFindings.IndexOf($_) + 1
    $sevKey = if ($severityColors.ContainsKey($_.Severity)) { $_.Severity } else { 'Low' }
    $colors = $severityColors[$sevKey]
    $mitre = if ($_.MitreID) { " <span class='mitre'>$(ConvertTo-HtmlSafe $_.MitreID)</span>" } else { '' }
    @"
<tr data-severity="$sevKey" data-category="$(ConvertTo-HtmlSafe $_.Category)">
  <td class="rank">$i</td>
  <td><span class="badge" style="background:$($colors.bg);color:$($colors.fg)">$sevKey</span></td>
  <td class="score">$($_.RiskScore)</td>
  <td>$(ConvertTo-HtmlSafe $_.Category)</td>
  <td class="finding-title">$(ConvertTo-HtmlSafe $_.Finding)$mitre</td>
  <td>$(ConvertTo-HtmlSafe $_.AffectedObject)</td>
  <td class="details">$(ConvertTo-HtmlSafe $_.Details)</td>
  <td class="reco">$(ConvertTo-HtmlSafe $_.Recommendation)</td>
  <td class="source">$(ConvertTo-HtmlSafe $_.SourceFile)</td>
</tr>
"@
}) -join "`n"

$sourcesRowsHtml = ($sourcesUsed | ForEach-Object {
    "<li><span class='src-name'>$(ConvertTo-HtmlSafe $_.File)</span><span class='src-rows'>$($_.Rows) finding$(if($_.Rows -ne 1){'s'})</span></li>"
}) -join "`n"

$generatedOn = Get-Date -Format 'dddd, MMMM d, yyyy HH:mm'
$orgSafe = ConvertTo-HtmlSafe $OrganizationName

#endregion

#region HTML document

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Security Gaps Dashboard - $orgSafe</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  :root {
    --bg: #f4f6f9; --panel: #ffffff; --text: #1a2233; --muted: #5b667a;
    --border: #e3e7ee; --accent: #2952e3;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0f1420; --panel:#171d2c; --text:#e8ecf5; --muted:#9aa4bd; --border:#2a3247; --accent:#6f8bff; }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.45;
  }
  .wrap { max-width: 1280px; margin: 0 auto; padding: 28px 24px 60px; }
  header.top { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px; margin-bottom: 24px; }
  header.top h1 { font-size: 1.5rem; margin: 0 0 4px; }
  header.top .subtitle { color: var(--muted); font-size: 0.92rem; }
  header.top .meta { text-align:right; font-size: 0.85rem; color: var(--muted); }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
  .kpi-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap: 14px; margin-bottom: 20px; }
  .kpi { padding: 16px 18px; }
  .kpi .n { font-size: 1.9rem; font-weight: 700; line-height:1; }
  .kpi .l { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: .04em; margin-top: 6px; }
  .kpi.critical .n { color: $($severityColors.Critical.bar); }
  .kpi.high .n     { color: $($severityColors.High.bar); }
  .kpi.medium .n   { color: $($severityColors.Medium.bar); }
  .kpi.low .n      { color: $($severityColors.Low.bar); }
  .row2 { display:grid; grid-template-columns: 300px 1fr; gap: 18px; margin-bottom: 20px; }
  @media (max-width: 860px) { .row2 { grid-template-columns: 1fr; } }
  .panel h2 { font-size: 1rem; margin: 0 0 16px; }
  .donut-wrap { display:flex; align-items:center; gap: 20px; }
  .donut {
    width: 130px; height: 130px; border-radius: 50%;
    background: $donutGradient;
    display:flex; align-items:center; justify-content:center; flex: none;
  }
  .donut .hole { width: 78px; height: 78px; border-radius: 50%; background: var(--panel); display:flex; flex-direction:column; align-items:center; justify-content:center; }
  .donut .hole .score { font-size: 1.5rem; font-weight: 800; }
  .donut .hole .lbl { font-size: 0.62rem; color: var(--muted); text-transform:uppercase; letter-spacing:.04em; }
  .legend { font-size: 0.85rem; }
  .legend div { display:flex; align-items:center; gap:8px; margin-bottom:6px; }
  .legend .dot { width:10px; height:10px; border-radius:50%; flex:none; }
  .cat-row { display:grid; grid-template-columns: 190px 1fr 34px; align-items:center; gap:10px; margin-bottom: 10px; font-size: 0.86rem; }
  .cat-label { color: var(--text); white-space: nowrap; overflow:hidden; text-overflow: ellipsis; }
  .cat-bar-track { background: var(--border); border-radius: 6px; height: 10px; overflow:hidden; }
  .cat-bar-fill { background: var(--accent); height: 100%; border-radius: 6px; }
  .cat-count { text-align:right; color: var(--muted); }
  .controls { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin: 22px 0 12px; }
  .controls input[type=search] {
    flex: 1; min-width: 220px; padding: 9px 12px; border-radius: 8px; border: 1px solid var(--border);
    background: var(--panel); color: var(--text); font-size: 0.9rem;
  }
  .controls select { padding: 9px 12px; border-radius: 8px; border: 1px solid var(--border); background: var(--panel); color: var(--text); font-size:0.9rem; }
  .controls button {
    padding: 9px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--panel);
    color: var(--text); cursor: pointer; font-size: 0.85rem;
  }
  .controls button:hover { border-color: var(--accent); color: var(--accent); }
  table { width: 100%; border-collapse: collapse; font-size: 0.83rem; background: var(--panel); }
  thead th {
    text-align:left; padding: 10px 12px; background: var(--bg); border-bottom: 2px solid var(--border);
    position: sticky; top: 0; cursor: pointer; user-select: none; white-space: nowrap;
  }
  thead th:hover { color: var(--accent); }
  tbody td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:hover { background: color-mix(in srgb, var(--accent) 5%, transparent); }
  td.rank { color: var(--muted); font-variant-numeric: tabular-nums; }
  td.score { font-weight: 700; font-variant-numeric: tabular-nums; }
  td.finding-title { font-weight: 600; min-width: 220px; }
  td.details, td.reco { color: var(--muted); max-width: 320px; }
  td.source { color: var(--muted); font-size: 0.75rem; white-space: nowrap; }
  .mitre { font-size: 0.7rem; color: var(--accent); border: 1px solid var(--accent); border-radius: 4px; padding: 1px 5px; margin-left: 6px; white-space: nowrap; }
  .badge { display:inline-block; padding: 3px 10px; border-radius: 999px; font-weight: 700; font-size: 0.72rem; text-transform: uppercase; letter-spacing: .03em; }
  .table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; }
  footer { margin-top: 28px; color: var(--muted); font-size: 0.78rem; }
  footer .sources { margin-top: 10px; }
  footer .sources ul { list-style:none; padding:0; margin: 6px 0 0; }
  footer .sources li { display:flex; justify-content:space-between; max-width: 420px; padding: 3px 0; border-bottom: 1px dashed var(--border); }
  footer .src-rows { color: var(--muted); }
  .hidden-row { display: none !important; }
  @media print {
    .controls { display:none; }
    body { background: white; }
    .panel { border: 1px solid #ccc; }
  }
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <div>
      <h1>Active Directory Security Gaps Dashboard</h1>
      <div class="subtitle">$orgSafe &middot; Top $($topFindings.Count) of $($allFindings.Count) findings across $($csvFiles.Count) source file(s)</div>
    </div>
    <div class="meta">
      Generated $generatedOn<br>
      Read-only analysis &middot; for authorized security review use
    </div>
  </header>

  <div class="kpi-grid">
    <div class="panel kpi"><div class="n">$($allFindings.Count)</div><div class="l">Total Findings</div></div>
    <div class="panel kpi critical"><div class="n">$($sevCount.Critical)</div><div class="l">Critical</div></div>
    <div class="panel kpi high"><div class="n">$($sevCount.High)</div><div class="l">High</div></div>
    <div class="panel kpi medium"><div class="n">$($sevCount.Medium)</div><div class="l">Medium</div></div>
    <div class="panel kpi low"><div class="n">$($sevCount.Low)</div><div class="l">Low</div></div>
  </div>

  <div class="row2">
    <div class="panel">
      <h2>Overall Exposure</h2>
      <div class="donut-wrap">
        <div class="donut"><div class="hole"><div class="score">$exposureScore</div><div class="lbl">$exposureLabel</div></div></div>
        <div class="legend">
          <div><span class="dot" style="background:$($severityColors.Critical.bar)"></span> Critical ($($sevCount.Critical))</div>
          <div><span class="dot" style="background:$($severityColors.High.bar)"></span> High ($($sevCount.High))</div>
          <div><span class="dot" style="background:$($severityColors.Medium.bar)"></span> Medium ($($sevCount.Medium))</div>
          <div><span class="dot" style="background:$($severityColors.Low.bar)"></span> Low ($($sevCount.Low))</div>
        </div>
      </div>
    </div>
    <div class="panel">
      <h2>Findings by Category</h2>
      $categoryRowsHtml
    </div>
  </div>

  <div class="controls">
    <input type="search" id="searchBox" placeholder="Search findings, objects, categories...">
    <select id="severityFilter">
      <option value="">All severities</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <select id="categoryFilter">
      <option value="">All categories</option>
      $((($byCategory | ForEach-Object { "<option value=`"$(ConvertTo-HtmlSafe $_.Name)`">$(ConvertTo-HtmlSafe $_.Name)</option>" }) -join "`n"))
    </select>
    <button id="exportBtn" type="button">Export visible rows (CSV)</button>
  </div>

  <div class="table-wrap">
    <table id="findingsTable">
      <thead>
        <tr>
          <th data-sort="num">#</th>
          <th data-sort="text">Severity</th>
          <th data-sort="num">Score</th>
          <th data-sort="text">Category</th>
          <th data-sort="text">Finding</th>
          <th data-sort="text">Affected Object</th>
          <th data-sort="text">Details</th>
          <th data-sort="text">Recommendation</th>
          <th data-sort="text">Source</th>
        </tr>
      </thead>
      <tbody>
        $tableRowsHtml
      </tbody>
    </table>
  </div>

  <footer>
    <div>This dashboard is a static snapshot merged from the CSV files listed below. Re-run the scanner and regenerate to refresh.</div>
    <div class="sources">
      <strong>Sources ingested:</strong>
      <ul>
        $sourcesRowsHtml
      </ul>
    </div>
  </footer>

</div>

<script>
(function () {
  var table = document.getElementById('findingsTable');
  var tbody = table.querySelector('tbody');
  var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));

  function applyFilters() {
    var q = document.getElementById('searchBox').value.trim().toLowerCase();
    var sev = document.getElementById('severityFilter').value;
    var cat = document.getElementById('categoryFilter').value;
    rows.forEach(function (row) {
      var matchesText = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
      var matchesSev = !sev || row.getAttribute('data-severity') === sev;
      var matchesCat = !cat || row.getAttribute('data-category') === cat;
      row.classList.toggle('hidden-row', !(matchesText && matchesSev && matchesCat));
    });
  }
  document.getElementById('searchBox').addEventListener('input', applyFilters);
  document.getElementById('severityFilter').addEventListener('change', applyFilters);
  document.getElementById('categoryFilter').addEventListener('change', applyFilters);

  var sortState = {};
  table.querySelectorAll('thead th').forEach(function (th, idx) {
    th.addEventListener('click', function () {
      var type = th.getAttribute('data-sort');
      var dir = sortState[idx] === 'asc' ? 'desc' : 'asc';
      sortState = {}; sortState[idx] = dir;
      var sorted = rows.slice().sort(function (a, b) {
        var av = a.children[idx].textContent.trim();
        var bv = b.children[idx].textContent.trim();
        if (type === 'num') { av = parseFloat(av) || 0; bv = parseFloat(bv) || 0; return dir === 'asc' ? av - bv : bv - av; }
        return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      sorted.forEach(function (r) { tbody.appendChild(r); });
      rows = sorted;
    });
  });

  document.getElementById('exportBtn').addEventListener('click', function () {
    var visible = rows.filter(function (r) { return !r.classList.contains('hidden-row'); });
    var headers = Array.prototype.map.call(table.querySelectorAll('thead th'), function (th) { return th.textContent.trim(); });
    var lines = [headers.join(',')];
    visible.forEach(function (r) {
      var cells = Array.prototype.map.call(r.children, function (td) {
        return '"' + td.textContent.replace(/"/g, '""').trim() + '"';
      });
      lines.push(cells.join(','));
    });
    var blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'ad_security_gaps_export.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });
})();
</script>
</body>
</html>
"@

$html | Set-Content -Path $OutputPath -Encoding UTF8

#endregion

Write-Host ''
Write-Status "Dashboard written: $OutputPath" -Level Ok
Write-Status "$($allFindings.Count) findings merged from $($csvFiles.Count) file(s); showing top $($topFindings.Count); composite exposure score $exposureScore/100 ($exposureLabel)." -Level Ok

if ($Open) {
    try { Invoke-Item $OutputPath } catch { Write-Status "Could not auto-open the dashboard: $($_.Exception.Message)" -Level Warn }
}
