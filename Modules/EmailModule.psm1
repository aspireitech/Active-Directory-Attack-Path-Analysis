#Requires -Version 5.1
<#
.SYNOPSIS
    Email reporting module supporting SMTP and Microsoft Graph API.
    Sends weekly AD security reports with attachments.
#>

function Send-ADSecurityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RiskResults,

        [hashtable]$Comparison,

        [string[]]$AttachmentPaths = @(),

        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    if (-not $Config.Email.Enabled) {
        Write-Log "Email reporting is disabled in config." -Level INFO -Component Email
        return
    }

    $subject = Build-EmailSubject -RiskResults $RiskResults -Comparison $Comparison -Config $Config
    $body    = Build-EmailBody   -RiskResults $RiskResults -Comparison $Comparison -Config $Config

    switch ($Config.Email.Provider.ToUpper()) {
        'SMTP'  { Send-ViaSmtp  -Subject $subject -Body $body -Attachments $AttachmentPaths -Config $Config }
        'GRAPH' { Send-ViaGraph -Subject $subject -Body $body -Attachments $AttachmentPaths -Config $Config }
        default { Send-ViaSmtp  -Subject $subject -Body $body -Attachments $AttachmentPaths -Config $Config }
    }
}

#region Subject Line

function Build-EmailSubject {
    param($RiskResults, $Comparison, $Config)

    $prefix = $Config.Email.SubjectPrefix
    $date   = Get-Date -Format 'yyyy-MM-dd'

    if ($RiskResults.CriticalCount -gt 0) {
        $urgency = "[CRITICAL]"
    } elseif ($RiskResults.HighCount -gt 0) {
        $urgency = "[HIGH]"
    } else {
        $urgency = "[INFO]"
    }

    $newText = ''
    if ($Comparison -and $Comparison.HasPreviousBaseline -and $Comparison.NewFindings.Count -gt 0) {
        $critNew = @($Comparison.NewFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        if ($critNew -gt 0) {
            $newText = " - $critNew New Critical Finding$(if($critNew -ne 1){'s'})"
        } else {
            $newText = " - $($Comparison.NewFindings.Count) New Finding$(if($Comparison.NewFindings.Count -ne 1){'s'})"
        }
    }

    return "$urgency $prefix - $date$newText [Score: $($RiskResults.DomainRiskScore)/100]"
}

#endregion

#region Email Body (HTML)

function Build-EmailBody {
    param($RiskResults, $Comparison, $Config)

    $orgName  = $Config.General.OrganizationName
    $date     = Get-Date -Format 'dddd, MMMM dd, yyyy'
    $scoreColor = switch ($RiskResults.DomainSeverity) {
        'Critical' { '#dc3545' }
        'High'     { '#fd7e14' }
        'Medium'   { '#ffc107' }
        'Low'      { '#28a745' }
        default    { '#6c757d' }
    }

    $newFindingsHtml = ''
    if ($Comparison -and $Comparison.HasPreviousBaseline -and $Comparison.NewFindings.Count -gt 0) {
        $rows = $Comparison.NewFindings | Select-Object -First 10 | ForEach-Object {
            $sColor = switch ($_.Severity) {
                'Critical' { '#dc3545' } 'High' { '#fd7e14' } 'Medium' { '#ffc107' } default { '#28a745' }
            }
            "<tr><td style='color:$sColor;font-weight:bold'>$($_.Severity)</td><td>$($_.FindingType)</td><td>$($_.Title)</td></tr>"
        }
        $newFindingsHtml = @"
<h3 style='color:#dc3545;'>&#9888; New This Week ($($Comparison.NewFindings.Count) findings)</h3>
<table style='width:100%;border-collapse:collapse;margin-bottom:20px;'>
<tr style='background:#333;color:white;'><th style='padding:8px;'>Severity</th><th style='padding:8px;'>Type</th><th style='padding:8px;'>Title</th></tr>
$($rows -join '')
</table>
"@
    }

    $topFindings = $RiskResults.Findings | Where-Object { $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' } | Select-Object -First 10
    $topFindingsRows = $topFindings | ForEach-Object {
        $sColor = switch ($_.Severity) { 'Critical' { '#dc3545' } 'High' { '#fd7e14' } default { '#ffc107' } }
        "<tr style='border-bottom:1px solid #eee'><td style='padding:8px;color:$sColor;font-weight:bold'>$($_.Severity)</td><td style='padding:8px'>$($_.FindingType)</td><td style='padding:8px'>$($_.Title)</td><td style='padding:8px'>$($_.SourceIdentity)</td></tr>"
    }

    $changeHtml = ''
    if ($Comparison -and $Comparison.HasPreviousBaseline) {
        $arrow   = if ($Comparison.ScoreChange -gt 0) { '&#x2191;' } elseif ($Comparison.ScoreChange -lt 0) { '&#x2193;' } else { '&#x2194;' }
        $chColor = if ($Comparison.ScoreChange -gt 0) { '#dc3545' } elseif ($Comparison.ScoreChange -lt 0) { '#28a745' } else { '#6c757d' }
        $changeHtml = "<p><strong>Score Change:</strong> <span style='color:$chColor'>$arrow $([Math]::Abs($Comparison.ScoreChange)) ($($Comparison.ScoreDirection))</span></p>"
        $changeHtml += "<p><strong>New Findings:</strong> $($Comparison.NewFindings.Count) | <strong>Resolved:</strong> $($Comparison.RemovedFindings.Count) | <strong>Modified:</strong> $($Comparison.ModifiedFindings.Count)</p>"
    }

    return @"
<!DOCTYPE html>
<html>
<head><meta charset='UTF-8'></head>
<body style='font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:20px;background:#f8f9fa;'>

<div style='background:white;border-radius:8px;padding:30px;box-shadow:0 2px 10px rgba(0,0,0,0.1);'>

<div style='background:#1a1a2e;padding:20px;border-radius:6px;margin-bottom:25px;'>
  <h1 style='color:white;margin:0;font-size:22px;'>&#128737; AD Attack Path Analysis Report</h1>
  <p style='color:#adb5bd;margin:5px 0 0;'>$orgName &nbsp;|&nbsp; $date</p>
</div>

<table style='width:100%;margin-bottom:25px;'>
<tr>
  <td style='text-align:center;background:$scoreColor;color:white;border-radius:6px;padding:20px;'>
    <div style='font-size:48px;font-weight:bold;'>$($RiskResults.DomainRiskScore)</div>
    <div style='font-size:18px;'>Domain Risk Score</div>
    <div style='font-size:14px;opacity:0.9;'>$($RiskResults.DomainSeverity)</div>
  </td>
  <td style='padding-left:20px;'>
    <table style='width:100%;'>
      <tr><td style='padding:5px;'><strong>Critical</strong></td><td style='padding:5px;color:#dc3545;font-weight:bold;font-size:20px;'>$($RiskResults.CriticalCount)</td></tr>
      <tr><td style='padding:5px;'><strong>High</strong></td><td style='padding:5px;color:#fd7e14;font-weight:bold;font-size:20px;'>$($RiskResults.HighCount)</td></tr>
      <tr><td style='padding:5px;'><strong>Medium</strong></td><td style='padding:5px;color:#ffc107;font-weight:bold;font-size:20px;'>$($RiskResults.MediumCount)</td></tr>
      <tr><td style='padding:5px;'><strong>Low</strong></td><td style='padding:5px;color:#28a745;font-weight:bold;font-size:20px;'>$($RiskResults.LowCount)</td></tr>
      <tr><td style='padding:5px;'><strong>Total</strong></td><td style='padding:5px;font-weight:bold;font-size:20px;'>$($RiskResults.TotalFindings)</td></tr>
    </table>
  </td>
</tr>
</table>

$changeHtml

$newFindingsHtml

<h3>Top Priority Findings</h3>
<table style='width:100%;border-collapse:collapse;margin-bottom:20px;'>
<tr style='background:#1a1a2e;color:white;'><th style='padding:10px;text-align:left;'>Severity</th><th style='padding:10px;text-align:left;'>Type</th><th style='padding:10px;text-align:left;'>Title</th><th style='padding:10px;text-align:left;'>Source</th></tr>
$($topFindingsRows -join '')
</table>

<div style='background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:15px;margin-top:20px;'>
  <strong>&#128196; Report Attachments</strong><br>
  Full HTML Report, Excel Workbook, CSV Export, and JSON Baseline are attached to this email.
</div>

<p style='color:#6c757d;font-size:12px;margin-top:30px;border-top:1px solid #dee2e6;padding-top:15px;'>
  This report was automatically generated by the AD Attack Path Analysis Platform.<br>
  For questions, contact your security team. Do not forward this email outside the organization.
</p>

</div>
</body>
</html>
"@
}

#endregion

#region SMTP

function Send-ViaSmtp {
    param($Subject, $Body, $Attachments, $Config)

    try {
        $smtp  = $Config.Email.SmtpServer
        $port  = $Config.Email.SmtpPort
        $from  = $Config.Email.SenderAddress
        $to    = @($Config.Email.ToRecipients)
        $cc    = @($Config.Email.CcRecipients)
        $bcc   = @($Config.Email.BccRecipients)

        $msg = New-Object System.Net.Mail.MailMessage
        $msg.From       = New-Object System.Net.Mail.MailAddress($from, $Config.Email.SenderName)
        $msg.Subject    = $Subject
        $msg.Body       = $Body
        $msg.IsBodyHtml = $true

        foreach ($addr in $to)  { $msg.To.Add($addr) }
        foreach ($addr in $cc)  { $msg.CC.Add($addr) }
        foreach ($addr in $bcc) { $msg.Bcc.Add($addr) }

        foreach ($attachment in $Attachments) {
            if (Test-Path $attachment) {
                $msg.Attachments.Add((New-Object System.Net.Mail.Attachment($attachment)))
            }
        }

        $smtpClient = New-Object System.Net.Mail.SmtpClient($smtp, $port)
        $smtpClient.EnableSsl = $Config.Email.UseTLS

        if ($Config.Credentials.UseCurrentContext -eq $false) {
            $cred = Get-StoredCredential -Target $Config.Credentials.CredentialManagerTarget
            if ($cred) { $smtpClient.Credentials = $cred.GetNetworkCredential() }
        }

        $smtpClient.Send($msg)
        $msg.Dispose()
        $smtpClient.Dispose()

        Write-Log "Email sent via SMTP to: $($to -join ', ')" -Level SUCCESS -Component Email
    } catch {
        Write-Log "SMTP email failed: $_" -Level ERROR -Component Email
        throw
    }
}

#endregion

#region Microsoft Graph

function Send-ViaGraph {
    param($Subject, $Body, $Attachments, $Config)

    try {
        $graphConfig = $Config.Email.MicrosoftGraph
        $token = Get-GraphAccessToken -TenantId $graphConfig.TenantId `
                                       -ClientId $graphConfig.ClientId `
                                       -CertThumbprint $graphConfig.CertificateThumbprint `
                                       -ClientSecret $graphConfig.ClientSecret

        $messageBody = [ordered]@{
            message = [ordered]@{
                subject = $Subject
                body    = @{ contentType = 'HTML'; content = $Body }
                toRecipients  = @($Config.Email.ToRecipients  | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                ccRecipients  = @($Config.Email.CcRecipients  | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                bccRecipients = @($Config.Email.BccRecipients | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                attachments   = @()
            }
            saveToSentItems = $false
        }

        foreach ($attachment in $Attachments) {
            if (-not (Test-Path $attachment)) { continue }
            $fileBytes   = [System.IO.File]::ReadAllBytes($attachment)
            $base64      = [Convert]::ToBase64String($fileBytes)
            $fileName    = Split-Path $attachment -Leaf
            $contentType = Get-MimeType -FileName $fileName

            $messageBody.message.attachments += @{
                '@odata.type' = '#microsoft.graph.fileAttachment'
                name          = $fileName
                contentType   = $contentType
                contentBytes  = $base64
            }
        }

        $headers  = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
        $jsonBody = $messageBody | ConvertTo-Json -Depth 10
        $sender   = $Config.Email.SenderAddress

        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$sender/sendMail" `
            -Method POST -Headers $headers -Body $jsonBody -ErrorAction Stop

        Write-Log "Email sent via Microsoft Graph from $sender" -Level SUCCESS -Component Email
    } catch {
        Write-Log "Graph API email failed: $_" -Level ERROR -Component Email
        throw
    }
}

function Get-GraphAccessToken {
    param($TenantId, $ClientId, $CertThumbprint, $ClientSecret)

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    if ($CertThumbprint) {
        $cert      = Get-Item "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction Stop
        $assertion = New-JwtAssertion -Certificate $cert -ClientId $ClientId -TenantId $TenantId
        $body = @{
            client_id             = $ClientId
            scope                 = 'https://graph.microsoft.com/.default'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $assertion
            grant_type            = 'client_credentials'
        }
    } else {
        $body = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }
    }

    $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'
    return $response.access_token
}

function New-JwtAssertion {
    param($Certificate, $ClientId, $TenantId)

    $now = [DateTimeOffset]::UtcNow
    $header = @{
        alg = 'RS256'
        typ = 'JWT'
        x5t = [Convert]::ToBase64String($Certificate.GetCertHash()) -replace '\+','-' -replace '/','_' -replace '='
    } | ConvertTo-Json -Compress

    $payload = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
        iss = $ClientId
        jti = [System.Guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds()
        sub = $ClientId
        iat = $now.ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $encodedHeader  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))  -replace '\+','-' -replace '/','_' -replace '='
    $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)) -replace '\+','-' -replace '/','_' -replace '='
    $dataToSign     = "$encodedHeader.$encodedPayload"

    $rsa       = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $signature = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($dataToSign), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $encodedSig = [Convert]::ToBase64String($signature) -replace '\+','-' -replace '/','_' -replace '='

    return "$dataToSign.$encodedSig"
}

function Get-MimeType {
    param([string]$FileName)
    switch ([System.IO.Path]::GetExtension($FileName).ToLower()) {
        '.html' { 'text/html' }
        '.xlsx' { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }
        '.csv'  { 'text/csv' }
        '.json' { 'application/json' }
        '.pdf'  { 'application/pdf' }
        default { 'application/octet-stream' }
    }
}

#endregion

#region Credential Helper

function Get-StoredCredential {
    param([string]$Target)
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $credManager = [System.Security.SecureString]::new()
        # Use cmdkey/Windows Credential Manager
        $cred = Get-Credential -Message "Enter SMTP credentials for $Target" -ErrorAction SilentlyContinue
        return $cred
    } catch { return $null }
}

#endregion

Export-ModuleMember -Function Send-ADSecurityReport, Build-EmailSubject, Build-EmailBody
