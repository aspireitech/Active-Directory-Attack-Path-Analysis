# AD Attack Path Analysis Platform

Enterprise-grade PowerShell platform for Active Directory attack path analysis, identity exposure reporting, and security posture monitoring.

---

## Overview

This platform provides comprehensive analysis of your Active Directory environment to identify attack paths, privileged identity exposure, and misconfigurations that could be exploited by attackers to gain elevated access — including Domain Admin, Enterprise Admin, Tier-0, and DCSync rights.

Reports are generated as interactive HTML dashboards with drill-down analysis, week-over-week baseline comparison, MITRE ATT&CK mapping, root cause analysis, and safe step-by-step remediation guidance.

---

## Architecture

```
ADAttackPathPlatform/
├── Invoke-ADAttackPathAnalysis.ps1     ← Main entry point
├── Install-ADAttackPathPlatform.ps1    ← Installer + scheduler setup
├── Config/
│   └── config.json                     ← All configuration settings
├── Modules/
│   ├── Logger.psm1                     ← Structured logging
│   ├── ADDataCollector.psm1            ← AD data collection
│   ├── RiskScoringEngine.psm1          ← Risk scoring (0-100) + MITRE mapping
│   ├── AttackPathEngine.psm1           ← BFS graph-based attack path analysis
│   ├── BaselineManager.psm1            ← JSON baseline storage + comparison
│   ├── BloodHoundIntegration.psm1      ← BloodHound CE/Enterprise API
│   ├── HTMLReportGenerator.psm1        ← Interactive Bootstrap 5 dashboard
│   ├── ExcelExporter.psm1              ← Multi-sheet Excel workbook
│   ├── PDFExporter.psm1                ← PDF via wkhtmltopdf or Chrome headless
│   ├── EmailModule.psm1                ← SMTP + Microsoft Graph API email
│   └── SchedulerModule.psm1            ← Windows Task Scheduler management
├── Baselines/                          ← Weekly JSON baselines
├── Reports/                            ← Generated HTML/Excel/PDF/CSV reports
└── Logs/                               ← Structured execution logs
```

---

## Installation

### Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Windows PowerShell | 5.1 | PowerShell Core 7 works for most features |
| RSAT AD Tools | Any | `Install-WindowsFeature RSAT-AD-PowerShell` |
| ImportExcel | 7.0+ | Auto-installed by installer |
| wkhtmltopdf | Any | Optional — for PDF generation |
| .NET Framework | 4.7.2+ | Already present on Windows Server 2016+ |

### Quick Install

```powershell
# Run as Administrator on a Domain-joined machine
.\Install-ADAttackPathPlatform.ps1

# With scheduled task (weekly Monday 06:00 as SYSTEM)
.\Install-ADAttackPathPlatform.ps1 -ConfigureScheduler

# Custom schedule
.\Install-ADAttackPathPlatform.ps1 -ConfigureScheduler -ScheduleFrequency Daily -ScheduleTime 03:00

# Custom service account
.\Install-ADAttackPathPlatform.ps1 -ConfigureScheduler -RunAsUser 'DOMAIN\svc-adsecurity'
```

### Minimum AD Permissions

The account running the analysis requires:

- **Read** access to all AD objects (Domain Users is sufficient for basic collection)
- **Read** on Security Descriptors (needed for ACL analysis — requires `msDS-Security-Descriptor` read right)
- For full ACL analysis: membership in **Account Operators** or explicit delegate read of ACLs

> **Principle of Least Privilege:** Create a dedicated read-only service account. Do not run as Domain Admin.

```powershell
# Create least-privilege service account
New-ADUser -Name 'svc-adsecurity' -SamAccountName 'svc-adsecurity' -PasswordNeverExpires $true -Enabled $true
Add-ADGroupMember -Identity 'Distributed COM Users' -Members 'svc-adsecurity'
# Grant read ACL on domain root (for ACL analysis)
$domain = Get-ADDomain
$acl = Get-Acl "AD:\$($domain.DistinguishedName)"
# ... (see RUNBOOK.md for full delegation steps)
```

---

## Configuration

Edit `Config\config.json` before first run:

### Key Settings

```json
{
  "General": {
    "OrganizationName": "ACME Corp",
    "ReportStoragePath": "C:\\ADAttackPathReports"
  },
  "Email": {
    "Enabled": true,
    "Provider": "SMTP",
    "SmtpServer": "smtp.acme.com",
    "ToRecipients": ["security@acme.com", "ciso@acme.com"]
  },
  "BloodHound": {
    "Enabled": true,
    "Edition": "Community",
    "ServerUrl": "http://localhost:8080",
    "ApiKey": "your-api-key"
  },
  "Analysis": {
    "MaxAttackPathDepth": 10,
    "StaleAccountDays": 90,
    "EnableDCSync": true,
    "EnableACLAnalysis": true
  }
}
```

### Email Providers

**SMTP:**
```json
"Email": { "Provider": "SMTP", "SmtpServer": "smtp.domain.com", "SmtpPort": 587, "UseTLS": true }
```

**Microsoft Graph API (app registration):**
```json
"Email": {
  "Provider": "GRAPH",
  "MicrosoftGraph": {
    "TenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ClientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "CertificateThumbprint": "ABCDEF1234567890"
  }
}
```

---

## Usage

### Manual Run (Interactive)

```powershell
.\Invoke-ADAttackPathAnalysis.ps1
```

### Automated / Silent Run

```powershell
.\Invoke-ADAttackPathAnalysis.ps1 -AutoRun
```

### Custom Config / Output Path

```powershell
.\Invoke-ADAttackPathAnalysis.ps1 -ConfigPath D:\Config\prod.json -OutputPath D:\Reports
```

### With Alternate Credentials

```powershell
$cred = Get-Credential
.\Invoke-ADAttackPathAnalysis.ps1 -Credential $cred
```

### Generate Baseline Only (No Report)

```powershell
.\Invoke-ADAttackPathAnalysis.ps1 -GenerateBaseline
```

### Skip Email / BloodHound

```powershell
.\Invoke-ADAttackPathAnalysis.ps1 -SkipEmail -SkipBloodHound
```

---

## Quick Scan: Top Security Gaps Dashboard

For a lightweight, standalone alternative to the full platform above — no `config.json`,
no installer, just two scripts — see `QuickScan\`. It scans four specific gap areas and
renders one merged, offline-viewable HTML dashboard ranking the top 20-30 findings by risk.

| Script | Purpose |
|---|---|
| `QuickScan\Find-TopADSecurityGaps.ps1` | Read-only scan. Writes one CSV per category to `QuickScan\Output\` (or `-OutputPath`): **ACL Inheritance Gaps**, **Password Security Gaps** (password-not-required, AS-REP roastable, never-expires, reversible encryption, stale/Kerberoastable privileged accounts), **Privilege Escalation Paths** (non-admins who can reach Domain Admin equivalence via nesting, ACEs, or unconstrained delegation), and **Protected Container Misconfiguration** (AdminSDHolder, orphaned `adminCount=1`, legacy Pre-Windows 2000 group, Domain Controllers OU delegation). |
| `QuickScan\New-SecurityGapsDashboard.ps1` | Merges **every** CSV it finds in a folder — this scan, an older scan, or any other tool's output with the same columns — into one ranked, sortable, filterable dashboard with severity/category breakdowns and a composite exposure score. Single self-contained `.html` file: no CDN, no internet required. |

```powershell
# 1. Scan (read-only)
.\QuickScan\Find-TopADSecurityGaps.ps1

# 2. Build the dashboard from everything in Output\ (repeat any time to merge more CSVs)
.\QuickScan\New-SecurityGapsDashboard.ps1 -TopN 30 -OrganizationName 'Contoso Ltd' -Open
```

---

## What Is Analyzed

### Identity & Account Analysis
| Category | Details |
|---|---|
| Users | All attributes, MemberOf, delegation flags, password settings |
| Groups | Membership, nesting depth, circular chains |
| Service Accounts | SPNs, delegation, password age |
| Managed Service Accounts | gMSA/MSA host computers |
| AdminCount Accounts | SDProp protection, orphaned admin count |
| Shadow Admins | AdminCount=1 outside known privileged groups |

### Attack Surface
| Finding | MITRE | Risk |
|---|---|---|
| Kerberoastable Accounts | T1558.003 | High–Critical |
| AS-REP Roastable Accounts | T1558.004 | High–Critical |
| DCSync Rights | T1003.006 | Critical |
| Unconstrained Delegation | T1558.001 | Critical |
| Constrained Delegation | T1558.001 | Medium–High |
| RBCD | T1558.001 | High |
| GenericAll ACEs | T1484.001 | Critical |
| GenericWrite ACEs | T1098 | High |
| WriteDACL / WriteOwner | T1222 | High |
| SID History | T1134.005 | High |
| Password Never Expires | T1078 | Low–High |
| Reversible Encryption | T1003 | High |
| Stale Privileged Accounts | T1078.002 | Medium–High |
| Orphaned SIDs | T1134 | Medium |
| Circular Group Memberships | T1078.002 | Medium |

### Attack Paths (Graph Analysis)
- BFS traversal from all users to Tier-0 targets
- Targets: Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers, DCSync
- Each path includes: chain display, exploit steps, MITRE mapping, remediation, risk score

---

## BloodHound Integration

When BloodHound CE or Enterprise is available, the platform:
1. Connects via REST API (API key or credentials)
2. Pulls shortest paths to Domain Admins and Enterprise Admins via Cypher queries
3. Retrieves Kerberoastable and unconstrained delegation data for cross-validation
4. Merges BloodHound paths with native PowerShell findings (deduplicating overlaps)

### Setup BloodHound CE

```bash
# Docker Compose (recommended)
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Default: http://localhost:8080
# Initial password: printed to console on first start
```

```powershell
# Collect BloodHound data
./SharpHound.exe --CollectionMethods All --ZipFilename bloodhound.zip
# Import ZIP into BloodHound UI, then enable integration in config.json
```

---

## Report Sections

| Section | Content |
|---|---|
| Executive Summary | Risk score, finding counts, AD statistics, attack surface overview |
| Attention Required | All critical findings with drill-down |
| New This Week | Findings added/removed/modified vs last baseline |
| Risk Trends | Week-over-week score trend charts |
| Attack Path Explorer | Clickable paths with full exploit/remediation details |
| All Findings | Sortable, filterable, exportable DataTable |
| ACL Risks | GenericAll/Write/DACL/Owner ACE findings |
| DCSync Exposure | Accounts with replication rights |
| Kerberoasting | Accounts with SPNs |
| Privileged Access | All privileged group memberships |
| Tier-0 Exposure | Who has Tier-0 access and how |
| Shadow Admins | AdminCount=1 outside privileged groups |
| Stale Accounts | Unused privileged accounts |
| Service Account Risks | SPNs, delegation, password age |
| Delegation Risks | Unconstrained/Constrained/RBCD findings |
| Domain Controllers | DC inventory and exposure |
| Password Policies | Violations and fine-grained policies |
| Remediation Dashboard | Prioritized step-by-step remediations with risk ratings |

---

## Report Features

- **Dark mode** toggle (persisted in localStorage)
- **Collapsible sections** for executive briefings
- **Global search** across all findings
- **DataTables** with sort, filter, paginate on every table
- **Export** to CSV, Excel, Print from any table
- **Export to PDF** via wkhtmltopdf or Chrome headless
- **Attack Path drill-down** modal with exploit steps and remediation
- **MITRE ATT&CK links** linking to attack.mitre.org
- **Mobile-responsive** Bootstrap 5 layout
- **Chart.js** visualizations (severity donut, attack surface bar, trend line)

---

## Scheduling

```powershell
# Install weekly task (Monday 06:00 as SYSTEM)
.\Install-ADAttackPathPlatform.ps1 -ConfigureScheduler

# Check status
Import-Module .\Modules\SchedulerModule.psm1
Get-ADAttackPathScheduleStatus

# Run on-demand
Invoke-ADAttackPathNow

# Remove task
Remove-ADAttackPathSchedule
```

---

## Baseline Comparison

The platform stores a JSON baseline after every run. On subsequent runs, it:

- Identifies **new findings** (not in previous baseline) → marked `NEW` in report
- Identifies **resolved findings** (in previous but not current) → shown in "New This Week"
- Detects **severity changes** (same finding, different risk level)
- Calculates **score delta** with trend direction

Baselines are retained for 90 days (configurable). Old baselines are automatically purged.

---

## Security Considerations

- The platform performs **read-only** AD queries with no modifications
- Credentials are handled via Windows Credential Manager or current session context
- Report files contain sensitive security data — restrict access to the output directory
- Email attachments contain ACL and privilege data — use encryption/TLS
- Store config.json securely; it may contain SMTP passwords or API keys
- For the Graph API email option, use certificate authentication (not client secret) in production

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `ActiveDirectory module not found` | Install RSAT: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| `Access Denied` on ACL collection | Run as Domain Admin or delegate ACL read rights to service account |
| ImportExcel not found | `Install-Module ImportExcel -Scope CurrentUser -Force` |
| BloodHound connection fails | Verify ServerUrl, check API key, ensure BH service is running |
| Email fails | Check SMTP relay whitelist, test with `Send-MailMessage` manually |
| PDF not generated | Install wkhtmltopdf from https://wkhtmltopdf.org/downloads.html |
| Task Scheduler run fails | Check task's "Run As" account has AD read rights and logon-as-batch-job right |

---

## License

This project is provided for authorized security testing and enterprise security monitoring purposes only.
