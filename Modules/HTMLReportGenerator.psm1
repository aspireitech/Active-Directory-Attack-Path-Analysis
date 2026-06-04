#Requires -Version 5.1
<#
.SYNOPSIS
    HTML report generator for the AD Attack Path Analysis Platform.
    Produces a fully interactive Bootstrap + DataTables dashboard with all sections.
#>

function New-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ADData,

        [Parameter(Mandatory)]
        [hashtable]$RiskResults,

        [hashtable]$AttackPaths,

        [hashtable]$Comparison,

        [hashtable]$Config,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $orgName  = $Config.General.OrganizationName
    $genDate  = Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss'
    $domain   = $ADData.Domain.DNSRoot

    $scoreColor = switch ($RiskResults.DomainSeverity) {
        'Critical' { '#dc3545' } 'High' { '#fd7e14' } 'Medium' { '#e6ac00' } default { '#28a745' }
    }

    # Pre-render sections
    $execSummarySection     = Get-ExecSummarySection    -ADData $ADData -RiskResults $RiskResults -Comparison $Comparison -ScoreColor $scoreColor
    $attentionSection       = Get-AttentionSection      -RiskResults $RiskResults
    $newThisWeekSection     = Get-NewThisWeekSection    -Comparison $Comparison
    $attackPathSection      = Get-AttackPathSection     -AttackPaths $AttackPaths
    $privilegedSection      = Get-PrivilegedSection     -ADData $ADData
    $tier0Section           = Get-Tier0Section          -ADData $ADData
    $dcsyncSection          = Get-DCSyncSection         -ADData $ADData
    $kerbSection            = Get-KerberoastingSection  -ADData $ADData
    $aclSection             = Get-ACLSection            -ADData $ADData
    $shadowAdminSection     = Get-ShadowAdminSection    -ADData $ADData
    $staleAccountSection    = Get-StaleAccountSection   -ADData $ADData
    $delegationSection      = Get-DelegationSection     -ADData $ADData
    $passwordSection        = Get-PasswordPolicySection -ADData $ADData
    $serviceAccountSection  = Get-ServiceAccountSection -ADData $ADData
    $dcSection              = Get-DomainControllerSection -ADData $ADData
    $remediationSection     = Get-RemediationSection    -RiskResults $RiskResults
    $trendSection           = Get-TrendSection          -Comparison $Comparison -RiskResults $RiskResults
    $allFindingsSection     = Get-AllFindingsSection    -RiskResults $RiskResults

    $html = @"
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Attack Path Report - $orgName</title>
<!-- Bootstrap 5.3 -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
<!-- DataTables -->
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
<link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css">
<!-- Bootstrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.min.css">
<style>
  :root {
    --ad-primary: #1a1a2e;
    --ad-secondary: #16213e;
    --ad-accent: #0f3460;
    --ad-highlight: #e94560;
  }
  [data-bs-theme="dark"] {
    --bs-body-bg: #121212;
    --bs-body-color: #e0e0e0;
    --bs-card-bg: #1e1e1e;
    --bs-table-bg: #1e1e1e;
    --bs-table-striped-bg: #252525;
    --bs-border-color: #333;
  }
  body { font-size: 14px; }
  .sidebar {
    position: fixed; top: 0; left: 0; height: 100vh; width: 240px;
    background: var(--ad-primary); color: white; overflow-y: auto; z-index: 1000;
    transition: width 0.3s ease;
  }
  .sidebar.collapsed { width: 60px; }
  .sidebar .nav-link { color: rgba(255,255,255,.75); padding: 10px 15px; border-radius: 6px; margin: 2px 8px; font-size: 13px; white-space: nowrap; overflow: hidden; }
  .sidebar .nav-link:hover, .sidebar .nav-link.active { color: white; background: var(--ad-accent); }
  .sidebar .nav-link .bi { margin-right: 8px; font-size: 16px; min-width: 20px; }
  .sidebar-brand { padding: 20px 15px; border-bottom: 1px solid rgba(255,255,255,.1); }
  .sidebar-section { font-size: 10px; color: rgba(255,255,255,.4); text-transform: uppercase; padding: 10px 23px 4px; letter-spacing: 1px; }
  .main-content { margin-left: 240px; padding: 20px; min-height: 100vh; transition: margin-left 0.3s ease; }
  .main-content.expanded { margin-left: 60px; }
  @media (max-width: 768px) { .sidebar { width: 60px; } .main-content { margin-left: 60px; } .sidebar .nav-label { display: none; } }

  /* Risk badges */
  .badge-critical { background-color: #dc3545 !important; color: white !important; }
  .badge-high     { background-color: #fd7e14 !important; color: white !important; }
  .badge-medium   { background-color: #ffc107 !important; color: #212529 !important; }
  .badge-low      { background-color: #28a745 !important; color: white !important; }

  /* Score circle */
  .risk-score-circle {
    width: 140px; height: 140px; border-radius: 50%; display: flex; flex-direction: column;
    align-items: center; justify-content: center; font-weight: bold; color: white;
    box-shadow: 0 4px 15px rgba(0,0,0,.3); margin: 0 auto;
  }
  .risk-score-number { font-size: 42px; line-height: 1; }
  .risk-score-label  { font-size: 12px; opacity: .9; text-transform: uppercase; letter-spacing: 1px; }

  /* Metric cards */
  .metric-card { border: none; border-radius: 12px; transition: transform .2s; cursor: default; }
  .metric-card:hover { transform: translateY(-3px); box-shadow: 0 6px 20px rgba(0,0,0,.15); }
  .metric-number { font-size: 36px; font-weight: 700; line-height: 1.1; }

  /* Attack path chain */
  .path-chain { font-family: monospace; font-size: 12px; background: #f8f9fa; border-radius: 6px; padding: 10px 14px; border-left: 3px solid #0d6efd; word-break: break-all; }
  [data-bs-theme="dark"] .path-chain { background: #2a2a2a; }

  /* Finding cards */
  .finding-card { border-left: 4px solid; transition: all .2s; }
  .finding-card.critical { border-left-color: #dc3545; }
  .finding-card.high     { border-left-color: #fd7e14; }
  .finding-card.medium   { border-left-color: #ffc107; }
  .finding-card.low      { border-left-color: #28a745; }

  /* Timeline */
  .timeline-item { border-left: 2px solid #dee2e6; padding-left: 20px; margin-left: 10px; position: relative; padding-bottom: 20px; }
  .timeline-item::before { content: ''; position: absolute; left: -8px; top: 4px; width: 14px; height: 14px; border-radius: 50%; background: #0d6efd; }
  .timeline-item.new::before    { background: #dc3545; }
  .timeline-item.removed::before { background: #28a745; }

  /* Stat pills */
  .stat-pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 20px; font-size: 13px; font-weight: 500; }

  /* Page header */
  .page-header { background: linear-gradient(135deg, var(--ad-primary) 0%, var(--ad-accent) 100%);
    color: white; border-radius: 12px; padding: 24px 30px; margin-bottom: 24px; }

  /* Remediation steps */
  .remediation-step { background: #e8f5e9; border-radius: 6px; padding: 12px 16px; margin: 6px 0; border-left: 3px solid #28a745; }
  [data-bs-theme="dark"] .remediation-step { background: #1a2e1a; }

  .section-anchor { padding-top: 70px; margin-top: -60px; }

  /* Print */
  @media print {
    .sidebar, .btn, .no-print { display: none !important; }
    .main-content { margin-left: 0 !important; }
    .card { break-inside: avoid; }
  }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-thumb { background: #888; border-radius: 3px; }

  /* Search highlight */
  .highlight { background: yellow; color: black !important; border-radius: 2px; padding: 0 2px; }
  [data-bs-theme="dark"] .highlight { background: #856404; color: white !important; }
</style>
</head>
<body>

<!-- ============================================================ SIDEBAR -->
<nav class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="d-flex align-items-center gap-2">
      <i class="bi bi-shield-lock-fill text-danger fs-4"></i>
      <div class="nav-label">
        <div style="font-weight:700;font-size:14px;">AD Attack Path</div>
        <div style="font-size:11px;opacity:.6;">Security Platform</div>
      </div>
    </div>
  </div>
  <div style="padding:10px 8px;">
    <div class="sidebar-section nav-label">Overview</div>
    <a href="#exec-summary"    class="nav-link active"><i class="bi bi-speedometer2"></i><span class="nav-label">Executive Summary</span></a>
    <a href="#attention"       class="nav-link"><i class="bi bi-exclamation-triangle-fill text-danger"></i><span class="nav-label">Attention Required</span></a>
    <a href="#new-this-week"   class="nav-link"><i class="bi bi-bell-fill text-warning"></i><span class="nav-label">New This Week</span></a>
    <a href="#risk-trends"     class="nav-link"><i class="bi bi-graph-up"></i><span class="nav-label">Risk Trends</span></a>

    <div class="sidebar-section nav-label">Attack Analysis</div>
    <a href="#attack-paths"    class="nav-link"><i class="bi bi-diagram-3-fill text-danger"></i><span class="nav-label">Attack Paths</span></a>
    <a href="#all-findings"    class="nav-link"><i class="bi bi-list-ul"></i><span class="nav-label">All Findings</span></a>
    <a href="#acl-risks"       class="nav-link"><i class="bi bi-key-fill text-warning"></i><span class="nav-label">ACL Risks</span></a>
    <a href="#dcsync"          class="nav-link"><i class="bi bi-arrow-repeat text-danger"></i><span class="nav-label">DCSync</span></a>
    <a href="#kerberoasting"   class="nav-link"><i class="bi bi-ticket-fill text-warning"></i><span class="nav-label">Kerberoasting</span></a>

    <div class="sidebar-section nav-label">Identity Risks</div>
    <a href="#privileged"      class="nav-link"><i class="bi bi-person-fill-gear text-warning"></i><span class="nav-label">Privileged Access</span></a>
    <a href="#tier0"           class="nav-link"><i class="bi bi-crown-fill text-danger"></i><span class="nav-label">Tier-0 Exposure</span></a>
    <a href="#shadow-admins"   class="nav-link"><i class="bi bi-incognito text-warning"></i><span class="nav-label">Shadow Admins</span></a>
    <a href="#stale-accounts"  class="nav-link"><i class="bi bi-person-slash"></i><span class="nav-label">Stale Accounts</span></a>
    <a href="#service-accounts" class="nav-link"><i class="bi bi-gear-fill"></i><span class="nav-label">Service Accounts</span></a>
    <a href="#delegation"      class="nav-link"><i class="bi bi-arrow-left-right text-warning"></i><span class="nav-label">Delegation Risks</span></a>

    <div class="sidebar-section nav-label">Infrastructure</div>
    <a href="#domain-controllers" class="nav-link"><i class="bi bi-server text-info"></i><span class="nav-label">Domain Controllers</span></a>
    <a href="#password-policy"    class="nav-link"><i class="bi bi-lock-fill"></i><span class="nav-label">Password Policies</span></a>

    <div class="sidebar-section nav-label">Remediation</div>
    <a href="#remediation"     class="nav-link"><i class="bi bi-tools text-success"></i><span class="nav-label">Remediation Plan</span></a>
  </div>
</nav>

<!-- ============================================================ TOPBAR -->
<div class="main-content" id="mainContent">
<nav class="navbar navbar-expand-lg bg-body-tertiary rounded mb-3 px-3 sticky-top" style="z-index:999;">
  <button class="btn btn-sm btn-outline-secondary me-2" id="sidebarToggle" title="Toggle sidebar">
    <i class="bi bi-layout-sidebar"></i>
  </button>
  <span class="navbar-brand mb-0 h6 text-muted">
    <i class="bi bi-building me-1"></i>$orgName &nbsp;|&nbsp; <i class="bi bi-globe me-1"></i>$domain
  </span>
  <div class="ms-auto d-flex align-items-center gap-2">
    <!-- Global search -->
    <div class="input-group input-group-sm" style="width:220px;">
      <span class="input-group-text"><i class="bi bi-search"></i></span>
      <input type="text" id="globalSearch" class="form-control" placeholder="Search findings...">
    </div>
    <!-- Dark mode toggle -->
    <button class="btn btn-sm btn-outline-secondary" id="darkModeToggle" title="Toggle dark mode">
      <i class="bi bi-moon-fill"></i>
    </button>
    <!-- Export buttons -->
    <div class="dropdown">
      <button class="btn btn-sm btn-primary dropdown-toggle" data-bs-toggle="dropdown">
        <i class="bi bi-download me-1"></i>Export
      </button>
      <ul class="dropdown-menu dropdown-menu-end">
        <li><a class="dropdown-item" href="#" onclick="exportPDF()"><i class="bi bi-file-pdf me-2"></i>PDF Report</a></li>
        <li><a class="dropdown-item" id="exportCsvBtn" href="#"><i class="bi bi-file-csv me-2"></i>CSV Export</a></li>
        <li><hr class="dropdown-divider"></li>
        <li><a class="dropdown-item" href="#" onclick="window.print()"><i class="bi bi-printer me-2"></i>Print</a></li>
      </ul>
    </div>
    <span class="badge bg-secondary ms-1" title="Report generated">
      <i class="bi bi-clock me-1"></i>$genDate
    </span>
  </div>
</nav>

<!-- ============================================================ PAGE HEADER -->
<div class="page-header">
  <div class="row align-items-center">
    <div class="col">
      <h1 class="h3 mb-1"><i class="bi bi-shield-lock me-2"></i>Active Directory Attack Path Analysis</h1>
      <p class="mb-0 opacity-75"><i class="bi bi-building me-1"></i>$orgName &nbsp;&nbsp; <i class="bi bi-globe me-1"></i>$domain &nbsp;&nbsp; <i class="bi bi-calendar3 me-1"></i>$genDate</p>
    </div>
    <div class="col-auto text-end">
      <div class="risk-score-circle" style="background:$scoreColor;">
        <div class="risk-score-number">$($RiskResults.DomainRiskScore)</div>
        <div class="risk-score-label">$($RiskResults.DomainSeverity)</div>
      </div>
    </div>
  </div>
</div>

<!-- ============================================================ SECTIONS -->
$execSummarySection
$attentionSection
$newThisWeekSection
$trendSection
$attackPathSection
$allFindingsSection
$aclSection
$dcsyncSection
$kerbSection
$privilegedSection
$tier0Section
$shadowAdminSection
$staleAccountSection
$serviceAccountSection
$delegationSection
$dcSection
$passwordSection
$remediationSection

</div><!-- /main-content -->

<!-- ============================================================ SCRIPTS -->
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.bootstrap5.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

<script>
// =======================================
// Dark Mode
// =======================================
const darkBtn = document.getElementById('darkModeToggle');
function setTheme(dark) {
  document.documentElement.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
  darkBtn.innerHTML = dark ? '<i class="bi bi-sun-fill"></i>' : '<i class="bi bi-moon-fill"></i>';
  localStorage.setItem('ad-dark-mode', dark);
  // Update Chart.js defaults
  Chart.defaults.color = dark ? '#ccc' : '#666';
  Chart.defaults.borderColor = dark ? '#444' : '#ddd';
}
const savedDark = localStorage.getItem('ad-dark-mode') === 'true';
setTheme(savedDark);
darkBtn.addEventListener('click', () => setTheme(document.documentElement.getAttribute('data-bs-theme') !== 'dark'));

// =======================================
// Sidebar Toggle
// =======================================
document.getElementById('sidebarToggle').addEventListener('click', function() {
  const sb = document.getElementById('sidebar');
  const mc = document.getElementById('mainContent');
  sb.classList.toggle('collapsed');
  mc.classList.toggle('expanded');
});

// =======================================
// Active nav on scroll
// =======================================
const sections = document.querySelectorAll('.section-anchor');
const navLinks = document.querySelectorAll('.sidebar .nav-link');
window.addEventListener('scroll', () => {
  let current = '';
  sections.forEach(s => { if (window.pageYOffset >= s.offsetTop - 80) current = s.id; });
  navLinks.forEach(l => { l.classList.remove('active'); if (l.getAttribute('href') === '#' + current) l.classList.add('active'); });
});

// =======================================
// DataTables - initialize all tables
// =======================================
$(document).ready(function() {
  $('table.dt-table').each(function() {
    $(this).DataTable({
      pageLength: 25,
      responsive: true,
      dom: "<'row'<'col-sm-6'l><'col-sm-6'f>>" +
           "<'row'<'col-12'tr>>" +
           "<'row'<'col-sm-5'i><'col-sm-7'p>>",
      language: { search: '<i class="bi bi-search"></i> ', emptyTable: 'No findings.' }
    });
  });

  // Tables with export buttons
  $('table.dt-export').each(function() {
    const tbl = this;
    $(tbl).DataTable({
      pageLength: 25,
      responsive: true,
      dom: 'Bfrtip',
      buttons: [
        { extend: 'csv',   text: '<i class="bi bi-file-csv me-1"></i>CSV',   className: 'btn btn-sm btn-outline-secondary' },
        { extend: 'excel', text: '<i class="bi bi-file-excel me-1"></i>Excel', className: 'btn btn-sm btn-outline-success' },
        { extend: 'print', text: '<i class="bi bi-printer me-1"></i>Print',  className: 'btn btn-sm btn-outline-secondary' }
      ]
    });
  });
});

// =======================================
// Global Search
// =======================================
document.getElementById('globalSearch').addEventListener('keyup', function() {
  const term = this.value.toLowerCase();
  if (!term) { document.querySelectorAll('.finding-card').forEach(c => { c.style.display=''; c.querySelectorAll('.highlight').forEach(h => { h.outerHTML = h.textContent; }); }); return; }
  document.querySelectorAll('.finding-card').forEach(card => {
    const text = card.textContent.toLowerCase();
    card.style.display = text.includes(term) ? '' : 'none';
  });
});

// =======================================
// Attack Path Drill-Down
// =======================================
function showPathDetail(pathId) {
  const data = window.pathDetails[pathId];
  if (!data) return;
  document.getElementById('pathDetailTitle').textContent = data.title;
  document.getElementById('pathDetailBody').innerHTML = data.html;
  new bootstrap.Modal(document.getElementById('pathDetailModal')).show();
}

// =======================================
// CSV Export (all findings)
// =======================================
document.getElementById('exportCsvBtn').addEventListener('click', function(e) {
  e.preventDefault();
  const rows = [['Severity','Score','FindingType','Title','SourceIdentity','TargetObject','MitreID','Remediation']];
  document.querySelectorAll('#allFindingsTable tbody tr').forEach(tr => {
    rows.push(Array.from(tr.querySelectorAll('td')).map(td => '"' + td.textContent.replace(/"/g,'""').trim() + '"'));
  });
  const csv = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a'); a.href = url; a.download = 'ad-findings.csv'; a.click();
});

// =======================================
// PDF Export
// =======================================
function exportPDF() { window.print(); }

// =======================================
// Collapsible sections
// =======================================
document.querySelectorAll('.section-toggle').forEach(btn => {
  btn.addEventListener('click', function() {
    const target = document.getElementById(this.dataset.target);
    const icon   = this.querySelector('i');
    target.classList.toggle('d-none');
    icon.classList.toggle('bi-chevron-up');
    icon.classList.toggle('bi-chevron-down');
  });
});

// =======================================
// Charts (Risk Trend)
// =======================================
(function buildCharts() {
  // Severity donut
  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical','High','Medium','Low'],
        datasets: [{ data: [$($RiskResults.CriticalCount),$($RiskResults.HighCount),$($RiskResults.MediumCount),$($RiskResults.LowCount)],
          backgroundColor: ['#dc3545','#fd7e14','#ffc107','#28a745'], borderWidth: 2 }]
      },
      options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
    });
  }

  // Attack surface bar chart
  const asCtx = document.getElementById('attackSurfaceChart');
  if (asCtx) {
    new Chart(asCtx, {
      type: 'bar',
      data: {
        labels: ['Kerberoastable','AS-REP Roastable','DCSync','Shadow Admins','Delegation Issues','ACL Findings'],
        datasets: [{ label: 'Count',
          data: [$($ADData.KerberoastableAccounts.Count),$($ADData.ASREPRoastableAccounts.Count),$($ADData.DCSyncAccounts.Count),$($ADData.ShadowAdmins.Count),$($ADData.DelegationFindings.Count),$($ADData.ACLFindings.Count)],
          backgroundColor: ['#dc3545','#fd7e14','#e94560','#ffc107','#6f42c1','#0dcaf0'] }]
      },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }
})();

</script>

<!-- Attack Path Detail Modal -->
<div class="modal fade" id="pathDetailModal" tabindex="-1">
  <div class="modal-dialog modal-xl">
    <div class="modal-content">
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title" id="pathDetailTitle"><i class="bi bi-diagram-3 me-2"></i>Attack Path Details</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body" id="pathDetailBody"></div>
    </div>
  </div>
</div>

</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Log "HTML report generated: $OutputPath" -Level SUCCESS -Component HTMLReport
    return $OutputPath
}

#region Section Builders

function Get-ExecSummarySection {
    param($ADData, $RiskResults, $Comparison, $ScoreColor)

    $changeHtml = ''
    if ($Comparison -and $Comparison.HasPreviousBaseline) {
        $arrow   = if ($Comparison.ScoreChange -gt 0) { '&#x2191;' } elseif ($Comparison.ScoreChange -lt 0) { '&#x2193;' } else { '~' }
        $chClass = if ($Comparison.ScoreChange -gt 0) { 'text-danger' } elseif ($Comparison.ScoreChange -lt 0) { 'text-success' } else { 'text-secondary' }
        $changeHtml = "<span class='$chClass fw-bold'>$arrow $([Math]::Abs($Comparison.ScoreChange)) vs last week</span>"
    }

    $totalPrivileged = 0
    foreach ($pg in $ADData.PrivilegedGroups) { $totalPrivileged += $pg.NestedMemberCount }

    $pathCount = if ($RiskResults.AttackPathCount) { $RiskResults.AttackPathCount } else { 0 }

    return @"
<div class="section-anchor" id="exec-summary"></div>
<div class="mb-4">
  <div class="d-flex align-items-center justify-content-between mb-3">
    <h2 class="h4 mb-0"><i class="bi bi-speedometer2 me-2 text-primary"></i>Executive Summary</h2>
    <button class="btn btn-sm btn-outline-secondary section-toggle" data-target="execBody"><i class="bi bi-chevron-up"></i></button>
  </div>
  <div id="execBody">
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
      <div class="card metric-card text-center p-3" style="background:$ScoreColor;color:white;">
        <div class="metric-number">$($RiskResults.DomainRiskScore)</div>
        <div class="small opacity-90">Domain Risk Score</div>
        <div class="small fw-bold">$($RiskResults.DomainSeverity) $changeHtml</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="card metric-card bg-danger text-white text-center p-3">
        <div class="metric-number">$($RiskResults.CriticalCount)</div>
        <div class="small">Critical Findings</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="card metric-card text-center p-3" style="background:#fd7e14;color:white;">
        <div class="metric-number">$($RiskResults.HighCount)</div>
        <div class="small">High Findings</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="card metric-card bg-warning text-dark text-center p-3">
        <div class="metric-number">$($RiskResults.MediumCount)</div>
        <div class="small">Medium Findings</div>
      </div>
    </div>
  </div>
  <div class="row g-3 mb-4">
    <div class="col-md-4">
      <div class="card p-3">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <span class="fw-semibold">AD Statistics</span><i class="bi bi-building text-muted"></i>
        </div>
        <table class="table table-sm table-borderless mb-0">
          <tr><td class="text-muted">Users</td><td class="fw-bold text-end">$($ADData.Users.Count)</td></tr>
          <tr><td class="text-muted">Groups</td><td class="fw-bold text-end">$($ADData.Groups.Count)</td></tr>
          <tr><td class="text-muted">Computers</td><td class="fw-bold text-end">$($ADData.Computers.Count)</td></tr>
          <tr><td class="text-muted">Domain Controllers</td><td class="fw-bold text-end">$($ADData.DomainControllers.Count)</td></tr>
          <tr><td class="text-muted">Total Privileged</td><td class="fw-bold text-end text-warning">$totalPrivileged</td></tr>
        </table>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <span class="fw-semibold">Attack Surface</span><i class="bi bi-bullseye text-danger"></i>
        </div>
        <table class="table table-sm table-borderless mb-0">
          <tr><td class="text-muted">Kerberoastable</td><td class="fw-bold text-end text-danger">$($ADData.KerberoastableAccounts.Count)</td></tr>
          <tr><td class="text-muted">AS-REP Roastable</td><td class="fw-bold text-end text-danger">$($ADData.ASREPRoastableAccounts.Count)</td></tr>
          <tr><td class="text-muted">DCSync Capable</td><td class="fw-bold text-end text-danger">$($ADData.DCSyncAccounts.Count)</td></tr>
          <tr><td class="text-muted">Shadow Admins</td><td class="fw-bold text-end text-warning">$($ADData.ShadowAdmins.Count)</td></tr>
          <tr><td class="text-muted">Delegation Risks</td><td class="fw-bold text-end text-warning">$($ADData.DelegationFindings.Count)</td></tr>
        </table>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3">
        <canvas id="severityChart" height="180"></canvas>
      </div>
    </div>
  </div>
  <div class="row g-3">
    <div class="col-12">
      <div class="card p-3">
        <div class="fw-semibold mb-2">Attack Surface Overview</div>
        <canvas id="attackSurfaceChart" height="80"></canvas>
      </div>
    </div>
  </div>
  </div>
</div>
"@
}

function Get-AttentionSection {
    param($RiskResults)

    $criticalFindings = @($RiskResults.Findings | Where-Object { $_.Severity -eq 'Critical' })
    if ($criticalFindings.Count -eq 0) {
        $body = '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No critical findings at this time.</div>'
    } else {
        $cards = $criticalFindings | ForEach-Object {
            $mitre = if ($_.MitreID) { "<span class='badge bg-dark ms-1' title='MITRE ATT&CK'>$($_.MitreID)</span>" } else { '' }
            @"
<div class="card finding-card critical mb-3 p-3">
  <div class="d-flex justify-content-between align-items-start">
    <div>
      <h6 class="fw-bold mb-1"><span class="badge badge-critical me-2">CRITICAL</span>$($_.Title) $mitre</h6>
      <p class="text-muted small mb-2">$($_.Description)</p>
      <details>
        <summary class="text-primary small" style="cursor:pointer">Show details</summary>
        <div class="mt-2">
          <div class="row g-2">
            <div class="col-md-6">
              <div class="small text-muted fw-semibold">Exploit Method</div>
              <div class="small font-monospace path-chain">$($_.ExploitMethod)</div>
            </div>
            <div class="col-md-6">
              <div class="small text-muted fw-semibold">Root Cause</div>
              <div class="small">$($_.RootCause)</div>
            </div>
          </div>
          <div class="remediation-step mt-2">
            <div class="small text-success fw-semibold mb-1"><i class="bi bi-tools me-1"></i>Remediation</div>
            <div class="small">$($_.Remediation)</div>
            <div class="small text-muted mt-1"><i class="bi bi-exclamation-circle me-1"></i>Remediation Risk: $($_.RemediationRisk)</div>
          </div>
        </div>
      </details>
    </div>
    <div class="text-end ms-3">
      <div class="h4 text-danger fw-bold">$($_.Score)</div>
      <div class="small text-muted">risk score</div>
      <div class="small text-muted">$($_.SourceIdentity)</div>
    </div>
  </div>
</div>
"@
        }
        $body = $cards -join ''
    }

    return @"
<div class="section-anchor" id="attention"></div>
<div class="mb-4">
  <div class="d-flex align-items-center justify-content-between mb-3">
    <h2 class="h4 mb-0"><i class="bi bi-exclamation-triangle-fill text-danger me-2"></i>Attention Required <span class="badge badge-critical ms-2">$($criticalFindings.Count)</span></h2>
    <button class="btn btn-sm btn-outline-secondary section-toggle" data-target="attentionBody"><i class="bi bi-chevron-up"></i></button>
  </div>
  <div id="attentionBody">$body</div>
</div>
"@
}

function Get-NewThisWeekSection {
    param($Comparison)

    if (-not $Comparison -or -not $Comparison.HasPreviousBaseline) {
        return @"
<div class="section-anchor" id="new-this-week"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-bell-fill text-warning me-2"></i>New This Week</h2>
  <div class="alert alert-info"><i class="bi bi-info-circle me-2"></i>No previous baseline available. Run again next week to see week-over-week changes.</div>
</div>
"@
    }

    $newRows = $Comparison.NewFindings | ForEach-Object {
        $sevClass = $_.Severity.ToLower()
        "<tr><td><span class='badge badge-$sevClass'>$($_.Severity)</span></td><td>$($_.FindingType)</td><td>$($_.Title)</td><td>$($_.SourceIdentity)</td><td>$($_.TargetObject)</td></tr>"
    }

    $removedRows = $Comparison.RemovedFindings | ForEach-Object {
        "<tr><td><span class='badge bg-success'>RESOLVED</span></td><td>$($_.FindingType)</td><td>$($_.Title)</td><td>$($_.SourceIdentity)</td></tr>"
    }

    $newCount     = $Comparison.NewFindings.Count
    $removedCount = $Comparison.RemovedFindings.Count

    return @"
<div class="section-anchor" id="new-this-week"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-bell-fill text-warning me-2"></i>New This Week</h2>
  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div class="card text-center p-3 $(if($newCount -gt 0){'border-danger'})">
        <div class="h2 fw-bold $(if($newCount -gt 0){'text-danger'} else {'text-muted'})">$newCount</div>
        <div class="small">New Findings</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3 border-success">
        <div class="h2 fw-bold text-success">$removedCount</div>
        <div class="small">Resolved</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="h2 fw-bold $(if($Comparison.ScoreChange -gt 0){'text-danger'} elseif($Comparison.ScoreChange -lt 0){'text-success'} else {'text-muted'})">$(if($Comparison.ScoreChange -gt 0){'+'})$($Comparison.ScoreChange)</div>
        <div class="small">Score Change</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center p-3">
        <div class="h2 fw-bold">$($Comparison.ModifiedFindings.Count)</div>
        <div class="small">Modified</div>
      </div>
    </div>
  </div>
  $(if($newCount -gt 0) {
    "<h6 class='fw-semibold'>New Findings</h6><div class='table-responsive'><table class='table table-sm table-hover dt-table'><thead class='table-dark'><tr><th>Severity</th><th>Type</th><th>Title</th><th>Source</th><th>Target</th></tr></thead><tbody>$($newRows -join '')</tbody></table></div>"
  })
  $(if($removedCount -gt 0) {
    "<h6 class='fw-semibold mt-3'>Resolved Findings</h6><div class='table-responsive'><table class='table table-sm table-hover dt-table'><thead class='table-success'><tr><th>Status</th><th>Type</th><th>Title</th><th>Source</th></tr></thead><tbody>$($removedRows -join '')</tbody></table></div>"
  })
</div>
"@
}

function Get-TrendSection {
    param($Comparison, $RiskResults)

    $trendCards = if ($Comparison -and $Comparison.HasPreviousBaseline) {
        $td = $Comparison.TrendData
        @"
<div class="row g-3">
  <div class="col-md-6">
    <div class="card p-3">
      <div class="fw-semibold mb-2">Risk Score Trend</div>
      <canvas id="trendChart" height="120"></canvas>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card p-3">
      <div class="fw-semibold mb-2">Finding Comparison</div>
      <table class="table table-sm mb-0">
        <thead><tr><th>Category</th><th class="text-center">Previous</th><th class="text-center">Current</th><th class="text-center">Change</th></tr></thead>
        <tbody>
          <tr><td>Critical</td><td class="text-center">$($td.PreviousCritical)</td><td class="text-center">$($td.CurrentCritical)</td><td class="text-center $(if($td.CurrentCritical -gt $td.PreviousCritical){'text-danger'} else {'text-success'})">$(if($td.CurrentCritical -gt $td.PreviousCritical){'+'}$(($td.CurrentCritical - $td.PreviousCritical)))</td></tr>
          <tr><td>High</td><td class="text-center">$($td.PreviousHigh)</td><td class="text-center">$($td.CurrentHigh)</td><td class="text-center $(if($td.CurrentHigh -gt $td.PreviousHigh){'text-danger'} else {'text-success'})">$(if($td.CurrentHigh -gt $td.PreviousHigh){'+'}$(($td.CurrentHigh - $td.PreviousHigh)))</td></tr>
          <tr><td>Medium</td><td class="text-center">$($td.PreviousMedium)</td><td class="text-center">$($td.CurrentMedium)</td><td class="text-center">$(($td.CurrentMedium - $td.PreviousMedium))</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>
<script>
(function(){
  const ctx = document.getElementById('trendChart');
  if(!ctx) return;
  new Chart(ctx, {
    type:'line',
    data:{
      labels:['Previous','Current'],
      datasets:[{
        label:'Risk Score',
        data:[$($td.PreviousScore),$($td.CurrentScore)],
        borderColor:'#dc3545',backgroundColor:'rgba(220,53,69,.1)',
        pointRadius:6,pointBackgroundColor:'#dc3545',fill:true,tension:0.3
      }]
    },
    options:{responsive:true,scales:{y:{beginAtZero:false,min:0,max:100}},plugins:{legend:{display:false}}}
  });
})();
</script>
"@
    } else {
        '<div class="alert alert-info"><i class="bi bi-info-circle me-2"></i>Trend data will be available after the second weekly run.</div>'
    }

    return @"
<div class="section-anchor" id="risk-trends"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-graph-up me-2 text-primary"></i>Risk Trends</h2>
  $trendCards
</div>
"@
}

function Get-AttackPathSection {
    param($AttackPaths)

    if (-not $AttackPaths -or $AttackPaths.Paths.Count -eq 0) {
        return @"
<div class="section-anchor" id="attack-paths"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-diagram-3-fill text-danger me-2"></i>Attack Path Explorer</h2>
  <div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No attack paths discovered in current analysis.</div>
</div>
"@
    }

    $pathDetails = @{}
    $pathCards = $AttackPaths.Paths | Select-Object -First 50 | ForEach-Object {
        $p = $_
        $sevClass = $p.Severity.ToLower()
        $pathId   = $p.PathId

        # Build modal detail HTML
        $stepsHtml = ''
        if ($p.ExploitSteps) {
            $stepsHtml = '<ol>' + ($p.ExploitSteps | ForEach-Object { "<li class='mb-1'>$_</li>" }) -join '' + '</ol>'
        }
        $remedHtml = ''
        if ($p.Remediation) {
            $remedHtml = '<ul>' + ($p.Remediation | ForEach-Object { "<li>$_</li>" }) -join '' + '</ul>'
        }

        $detailHtml = @"
<div class='row g-3'>
  <div class='col-12'><div class='path-chain p-3'>$($p.ChainDisplay)</div></div>
  <div class='col-md-6'>
    <div class='fw-semibold mb-1'>Exploit Steps</div>$stepsHtml
    <div class='fw-semibold mb-1 mt-2'>MITRE ATT&amp;CK</div>
    <span class='badge bg-dark'>$($p.MitreMapping.ID)</span> $($p.MitreMapping.Name) &bull; $($p.MitreMapping.Tactic)
  </div>
  <div class='col-md-6'>
    <div class='fw-semibold mb-1'>Remediation</div>
    <div class='remediation-step'>$remedHtml</div>
    <div class='small text-muted mt-2'><i class='bi bi-exclamation-circle me-1'></i>Remediation Risk: $($p.RemediationRisk)</div>
  </div>
</div>
"@
        $pathDetails[$pathId] = @{ title = $p.ChainDisplay; html = $detailHtml }

        @"
<div class="card finding-card $sevClass mb-2 p-3" style="cursor:pointer;" onclick="showPathDetail('$pathId')">
  <div class="d-flex justify-content-between align-items-center">
    <div class="flex-grow-1 me-3">
      <span class="badge badge-$sevClass me-2">$($p.Severity)</span>
      <span class="fw-semibold">$($p.SourceLabel)</span>
      <i class="bi bi-arrow-right mx-2 text-muted"></i>
      <span class="fw-semibold text-danger">$($p.TargetLabel)</span>
      <span class="badge bg-secondary ms-2">$($p.PathLength) hop$(if($p.PathLength -ne 1){'s'})</span>
      <span class="badge bg-dark ms-1">$($p.MitreMapping.ID)</span>
    </div>
    <div class="text-end">
      <div class="fw-bold text-danger">$($p.RiskScore)</div>
      <div class="small text-muted">score</div>
    </div>
  </div>
  <div class="path-chain mt-2 small text-truncate" title="$($p.ChainDisplay)">$($p.ChainDisplay)</div>
</div>
"@
    }

    $statsHtml = if ($AttackPaths.Stats) {
        $s = $AttackPaths.Stats
        "<div class='row g-2 mb-3'><div class='col-md-2'><div class='card text-center p-2'><div class='h5 fw-bold text-danger'>$($s.CriticalPaths)</div><div class='small'>Critical</div></div></div><div class='col-md-2'><div class='card text-center p-2'><div class='h5 fw-bold' style='color:#fd7e14'>$($s.HighPaths)</div><div class='small'>High</div></div></div><div class='col-md-2'><div class='card text-center p-2'><div class='h5 fw-bold'>$($s.TotalPaths)</div><div class='small'>Total</div></div></div><div class='col-md-2'><div class='card text-center p-2'><div class='h5 fw-bold'>$($s.ShortestPath)</div><div class='small'>Shortest</div></div></div><div class='col-md-2'><div class='card text-center p-2'><div class='h5 fw-bold'>$($s.AveragePathLength)</div><div class='small'>Avg Length</div></div></div></div>"
    } else { '' }

    # Serialize pathDetails to JSON for JS
    $pathDetailsJson = ($pathDetails | ConvertTo-Json -Depth 5 -Compress) -replace "'","\\'"
    $jsInit = "<script>window.pathDetails = $pathDetailsJson;</script>"

    return @"
<div class="section-anchor" id="attack-paths"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-diagram-3-fill text-danger me-2"></i>Attack Path Explorer
    <span class="badge badge-critical ms-2">$($AttackPaths.Paths.Count)</span>
    <small class="text-muted fs-6 fw-normal ms-2">Click any path for drill-down analysis</small>
  </h2>
  $statsHtml
  <div id="pathList">$($pathCards -join '')</div>
  $jsInit
</div>
"@
}

function Get-AllFindingsSection {
    param($RiskResults)

    $rows = $RiskResults.Findings | ForEach-Object {
        $sevClass = $_.Severity.ToLower()
        $newBadge = if ($_.NewFinding) { "<span class='badge bg-warning text-dark ms-1'>NEW</span>" } else { '' }
        "<tr><td><span class='badge badge-$sevClass'>$($_.Severity)</span>$newBadge</td><td>$($_.Score)</td><td><code>$($_.FindingType)</code></td><td>$($_.Title)</td><td>$($_.SourceIdentity)</td><td>$($_.TargetObject)</td><td><a href='https://attack.mitre.org/techniques/$($_.MitreID -replace '\.','/')' target='_blank' class='badge bg-dark text-decoration-none'>$($_.MitreID)</a></td></tr>"
    }

    return @"
<div class="section-anchor" id="all-findings"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-list-ul me-2"></i>All Findings ($($RiskResults.TotalFindings))</h2>
  <div class="table-responsive">
    <table id="allFindingsTable" class="table table-sm table-hover dt-export">
      <thead class="table-dark">
        <tr><th>Severity</th><th>Score</th><th>Type</th><th>Title</th><th>Source</th><th>Target</th><th>MITRE</th></tr>
      </thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-ACLSection {
    param($ADData)

    if ($ADData.ACLFindings.Count -eq 0) {
        return "<div class='section-anchor' id='acl-risks'></div><div class='mb-4'><h2 class='h4 mb-3'><i class='bi bi-key-fill text-warning me-2'></i>ACL Risk Report</h2><div class='alert alert-success'><i class='bi bi-check-circle me-2'></i>No ACL risks found.</div></div>"
    }

    $rows = $ADData.ACLFindings | ForEach-Object {
        "<tr><td><span class='badge badge-high'>$($_.FindingType)</span></td><td>$($_.SourceIdentity)</td><td>$($_.TargetObject)</td><td>$($_.TargetObjectType)</td><td>$($_.Rights)</td><td>$(if($_.Inherited){'<span class=''badge bg-secondary''>Inherited</span>'} else {'<span class=''badge bg-warning text-dark''>Direct</span>'})</td></tr>"
    }

    return @"
<div class="section-anchor" id="acl-risks"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-key-fill text-warning me-2"></i>ACL Risk Report <span class="badge badge-high ms-2">$($ADData.ACLFindings.Count)</span></h2>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>Finding Type</th><th>Source Identity</th><th>Target Object</th><th>Object Type</th><th>Rights</th><th>ACE Type</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-DCSyncSection {
    param($ADData)

    if ($ADData.DCSyncAccounts.Count -eq 0) {
        return "<div class='section-anchor' id='dcsync'></div><div class='mb-4'><h2 class='h4 mb-3'><i class='bi bi-arrow-repeat text-danger me-2'></i>DCSync Exposure</h2><div class='alert alert-success'><i class='bi bi-check-circle me-2'></i>No unauthorized DCSync rights detected.</div></div>"
    }

    $rows = $ADData.DCSyncAccounts | ForEach-Object {
        $fullBadge = if ($_.HasFullDCSync) { "<span class='badge badge-critical'>Full DCSync</span>" } else { "<span class='badge badge-high'>Partial</span>" }
        "<tr><td>$($_.Identity)</td><td>$($_.Rights -join ', ')</td><td>$fullBadge</td><td>$($_.Description)</td></tr>"
    }

    return @"
<div class="section-anchor" id="dcsync"></div>
<div class="mb-4">
  <div class="alert alert-danger mb-3">
    <i class="bi bi-exclamation-octagon-fill me-2"></i><strong>DCSync rights allow replication of all AD credentials including the KRBTGT hash.</strong>
    Only Domain Controllers and specific service accounts (e.g., Azure AD Connect) should have these rights.
  </div>
  <h2 class="h4 mb-3"><i class="bi bi-arrow-repeat text-danger me-2"></i>DCSync Exposure <span class="badge badge-critical ms-2">$($ADData.DCSyncAccounts.Count)</span></h2>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>Identity</th><th>Rights</th><th>DCSync Capability</th><th>Description</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-KerberoastingSection {
    param($ADData)

    if ($ADData.KerberoastableAccounts.Count -eq 0) {
        return "<div class='section-anchor' id='kerberoasting'></div><div class='mb-4'><h2 class='h4 mb-3'><i class='bi bi-ticket-fill text-warning me-2'></i>Kerberoasting</h2><div class='alert alert-success'><i class='bi bi-check-circle me-2'></i>No Kerberoastable accounts found.</div></div>"
    }

    $rows = $ADData.KerberoastableAccounts | ForEach-Object {
        $privBadge = if ($_.IsHighPrivilege) { "<span class='badge badge-critical'>Privileged</span>" } else { "<span class='badge badge-medium'>Standard</span>" }
        "<tr><td>$($_.SamAccountName)</td><td>$(($_.SPNs -join '<br>') | Select-Object -First 2)</td><td>$($_.PasswordLastSet)</td><td>$privBadge</td></tr>"
    }

    return @"
<div class="section-anchor" id="kerberoasting"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-ticket-fill text-warning me-2"></i>Kerberoasting Exposure <span class="badge badge-high ms-2">$($ADData.KerberoastableAccounts.Count)</span></h2>
  <div class="alert alert-warning mb-3"><i class="bi bi-info-circle me-2"></i>Accounts with SPNs can have TGS tickets requested by any authenticated user and cracked offline with Hashcat mode 13100.</div>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>Account</th><th>SPNs</th><th>Password Last Set</th><th>Privilege Level</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-PrivilegedSection {
    param($ADData)

    $rows = $ADData.PrivilegedGroups | ForEach-Object {
        $tier0Badge = if ($_.IsTier0) { "<span class='badge badge-critical'>Tier-0</span>" } else { "<span class='badge badge-high'>Privileged</span>" }
        "<tr><td>$($_.Name)</td><td>$($_.DirectMemberCount)</td><td>$($_.NestedMemberCount)</td><td>$tier0Badge</td><td>$(($_.DirectMembers | Select-Object -First 5) -join ', ')$(if($_.DirectMemberCount -gt 5){'...'})</td></tr>"
    }

    return @"
<div class="section-anchor" id="privileged"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-person-fill-gear text-warning me-2"></i>Privileged Access Overview</h2>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>Group</th><th>Direct Members</th><th>Nested Members</th><th>Tier</th><th>Sample Members</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-Tier0Section {
    param($ADData)

    $rows = $ADData.Tier0Objects | ForEach-Object {
        "<tr><td>$($_.Name)</td><td>$($_.ObjectType)</td><td>$($_.Tier0Group)</td></tr>"
    }
    $count = $ADData.Tier0Objects.Count

    return @"
<div class="section-anchor" id="tier0"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-crown-fill text-danger me-2"></i>Tier-0 Exposure Report <span class="badge badge-critical ms-2">$count objects</span></h2>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>Account</th><th>Object Type</th><th>Via Group</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-ShadowAdminSection {
    param($ADData)

    if ($ADData.ShadowAdmins.Count -eq 0) {
        return "<div class='section-anchor' id='shadow-admins'></div><div class='mb-4'><h2 class='h4 mb-3'><i class='bi bi-incognito text-warning me-2'></i>Shadow Admins</h2><div class='alert alert-success'><i class='bi bi-check-circle me-2'></i>No shadow administrators detected.</div></div>"
    }

    $rows = $ADData.ShadowAdmins | ForEach-Object {
        "<tr><td>$($_.SamAccountName)</td><td>$($_.LastLogonDate)</td><td>$($_.Risk)</td><td>$($_.Reason)</td></tr>"
    }

    return @"
<div class="section-anchor" id="shadow-admins"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-incognito text-warning me-2"></i>Shadow Admin Report <span class="badge badge-high ms-2">$($ADData.ShadowAdmins.Count)</span></h2>
  <div class="alert alert-warning"><i class="bi bi-info-circle me-2"></i>Shadow admins have AdminCount=1 (protected by SDProp) but do not appear in standard privileged groups. They may have direct ACE grants or be remnants of old group memberships.</div>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>Account</th><th>Last Logon</th><th>Risk</th><th>Reason</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-StaleAccountSection {
    param($ADData)

    $privStale = @($ADData.StaleAccounts | Where-Object { $_.IsPrivileged })
    $rows = $privStale | ForEach-Object {
        $daysBadge = if ($_.DaysSinceLogin -gt 365) { "<span class='badge badge-critical'>$($_.DaysSinceLogin) days</span>" } else { "<span class='badge badge-high'>$($_.DaysSinceLogin) days</span>" }
        "<tr><td>$($_.SamAccountName)</td><td>$($_.LastLogonDate)</td><td>$daysBadge</td><td>$($_.PasswordLastSet)</td></tr>"
    }

    return @"
<div class="section-anchor" id="stale-accounts"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-person-slash me-2"></i>Stale Privileged Accounts <span class="badge badge-high ms-2">$($privStale.Count)</span></h2>
  $(if($privStale.Count -gt 0) {
    "<div class='table-responsive'><table class='table table-sm table-hover dt-table'><thead class='table-dark'><tr><th>Account</th><th>Last Logon</th><th>Days Since Login</th><th>Password Last Set</th></tr></thead><tbody>$($rows -join '')</tbody></table></div>"
  } else {
    "<div class='alert alert-success'><i class='bi bi-check-circle me-2'></i>No stale privileged accounts found.</div>"
  })
</div>
"@
}

function Get-ServiceAccountSection {
    param($ADData)

    $rows = $ADData.ServiceAccounts | Select-Object -First 100 | ForEach-Object {
        $kerbBadge = if ($_.ServicePrincipalNames.Count -gt 0) { "<span class='badge badge-high'>Kerberoastable</span>" } else { '' }
        $delegBadge = if ($_.TrustedForDelegation) { "<span class='badge badge-critical'>Unconstrained</span>" } elseif ($_.TrustedToAuthForDelegation) { "<span class='badge badge-high'>Constrained</span>" } else { '' }
        "<tr><td>$($_.SamAccountName)</td><td>$($_.Enabled)</td><td>$($_.PasswordLastSet)</td><td>$($_.PasswordNeverExpires)</td><td>$kerbBadge $delegBadge</td></tr>"
    }

    return @"
<div class="section-anchor" id="service-accounts"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-gear-fill me-2"></i>Service Account Risks <span class="badge bg-secondary ms-2">$($ADData.ServiceAccounts.Count)</span></h2>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>Account</th><th>Enabled</th><th>Password Last Set</th><th>Never Expires</th><th>Risks</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-DelegationSection {
    param($ADData)

    $rows = $ADData.DelegationFindings | ForEach-Object {
        $riskBadge = switch ($_.Risk) { 'Critical' { 'badge-critical' } 'High' { 'badge-high' } default { 'badge-medium' } }
        "<tr><td><span class='badge $riskBadge'>$($_.Type)</span></td><td>$($_.ObjectName)</td><td>$($_.ObjectType)</td><td>$($_.Description)</td></tr>"
    }

    return @"
<div class="section-anchor" id="delegation"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-arrow-left-right text-warning me-2"></i>Delegation Risks <span class="badge badge-high ms-2">$($ADData.DelegationFindings.Count)</span></h2>
  $(if($ADData.DelegationFindings.Count -gt 0) {
    "<div class='table-responsive'><table class='table table-sm table-hover dt-table'><thead class='table-dark'><tr><th>Delegation Type</th><th>Object</th><th>Object Type</th><th>Description</th></tr></thead><tbody>$($rows -join '')</tbody></table></div>"
  } else {
    "<div class='alert alert-success'><i class='bi bi-check-circle me-2'></i>No dangerous delegation configurations found.</div>"
  })
</div>
"@
}

function Get-PasswordPolicySection {
    param($ADData)

    $pwdRows = $ADData.PasswordFindings | Group-Object FindingType | ForEach-Object {
        "<tr><td>$($_.Name)</td><td>$($_.Count)</td><td>$(if($_.Group[0].IsPrivileged){'Yes'} else {'No'})</td></tr>"
    }

    $fgppRows = $ADData.FineGrainedPolicies | ForEach-Object {
        "<tr><td>$($_.Name)</td><td>$($_.Precedence)</td><td>$($_.MinPasswordLength)</td><td>$($_.MaxPasswordAge)</td><td>$($_.ComplexityEnabled)</td><td>$($_.LockoutThreshold)</td></tr>"
    }

    return @"
<div class="section-anchor" id="password-policy"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-lock-fill me-2"></i>Password Policy Exceptions</h2>
  <div class="row g-3">
    <div class="col-md-6">
      <h6>Password Policy Violations</h6>
      $(if($ADData.PasswordFindings.Count -gt 0) {
        "<table class='table table-sm dt-table'><thead class='table-dark'><tr><th>Finding Type</th><th>Count</th><th>Affects Privileged</th></tr></thead><tbody>$($pwdRows -join '')</tbody></table>"
      } else { "<div class='alert alert-success'><i class='bi bi-check-circle me-2'></i>No password policy violations.</div>" })
    </div>
    <div class="col-md-6">
      <h6>Fine-Grained Password Policies ($($ADData.FineGrainedPolicies.Count))</h6>
      $(if($ADData.FineGrainedPolicies.Count -gt 0) {
        "<table class='table table-sm dt-table'><thead class='table-dark'><tr><th>Name</th><th>Precedence</th><th>Min Length</th><th>Max Age (days)</th><th>Complexity</th><th>Lockout</th></tr></thead><tbody>$($fgppRows -join '')</tbody></table>"
      } else { "<div class='text-muted small'>No fine-grained password policies configured.</div>" })
    </div>
  </div>
</div>
"@
}

function Get-DomainControllerSection {
    param($ADData)

    $rows = $ADData.DomainControllers | ForEach-Object {
        $gcBadge = if ($_.IsGlobalCatalog) { "<span class='badge bg-info'>GC</span>" } else { '' }
        $roBadge = if ($_.IsReadOnly) { "<span class='badge bg-secondary'>RODC</span>" } else { '' }
        $roles   = ($_.OperationMasterRoles -join ', ')
        "<tr><td>$($_.Name) $gcBadge $roBadge</td><td>$($_.IPv4Address)</td><td>$($_.OperatingSystem)</td><td>$($_.Site)</td><td>$roles</td></tr>"
    }

    return @"
<div class="section-anchor" id="domain-controllers"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-server text-info me-2"></i>Domain Controller Exposure</h2>
  <div class="table-responsive">
    <table class="table table-sm table-hover dt-table">
      <thead class="table-dark"><tr><th>DC Name</th><th>IP Address</th><th>OS</th><th>Site</th><th>FSMO Roles</th></tr></thead>
      <tbody>$($rows -join '')</tbody>
    </table>
  </div>
</div>
"@
}

function Get-RemediationSection {
    param($RiskResults)

    $critFindings = @($RiskResults.Findings | Where-Object { $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' } | Sort-Object Score -Descending | Select-Object -First 20)

    $items = $critFindings | ForEach-Object {
        $sev = $_.Severity.ToLower()
        $icon = switch ($_.Severity) { 'Critical' { 'bi-exclamation-octagon-fill text-danger' } 'High' { 'bi-exclamation-triangle-fill text-warning' } default { 'bi-info-circle text-info' } }
        @"
<div class="card finding-card $sev mb-3 p-3">
  <div class="d-flex justify-content-between align-items-start mb-2">
    <h6 class="mb-0 fw-bold"><i class="bi $icon me-2"></i>$($_.Title)</h6>
    <span class="badge badge-$sev ms-2">$($_.Severity)</span>
  </div>
  <div class="row g-3">
    <div class="col-md-4">
      <div class="small text-muted fw-semibold">WHAT IS THE RISK?</div>
      <div class="small">$($_.Description)</div>
    </div>
    <div class="col-md-4">
      <div class="small text-muted fw-semibold">WHY IS THIS DANGEROUS?</div>
      <div class="small font-monospace">$($_.ExploitMethod)</div>
    </div>
    <div class="col-md-4">
      <div class="remediation-step">
        <div class="small text-success fw-semibold"><i class="bi bi-check-circle me-1"></i>SAFE REMEDIATION STEPS</div>
        <div class="small mt-1">$($_.Remediation)</div>
        <div class="small text-muted mt-1"><strong>Risk:</strong> $($_.RemediationRisk)</div>
        <div class="small text-muted"><strong>MITRE:</strong> <a href="https://attack.mitre.org/techniques/$($_.MitreID -replace '\.','/')" target="_blank" class="badge bg-dark text-decoration-none">$($_.MitreID)</a> $($_.MitreName)</div>
      </div>
    </div>
  </div>
</div>
"@
    }

    return @"
<div class="section-anchor" id="remediation"></div>
<div class="mb-4">
  <h2 class="h4 mb-3"><i class="bi bi-tools text-success me-2"></i>Remediation Dashboard</h2>
  <div class="alert alert-info mb-3">
    <i class="bi bi-info-circle me-2"></i>
    All remediation steps are designed for zero or minimal operational risk. Each step includes a risk rating and technical justification.
    <strong>Always test in a non-production environment first.</strong>
  </div>
  <div id="remediationList">$($items -join '')</div>
</div>
"@
}

#endregion

Export-ModuleMember -Function New-HTMLReport
