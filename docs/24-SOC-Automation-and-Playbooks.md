# 24 — SOC Automation and Playbooks

> **Prerequisites:** Varies by integration — `Az.SecurityInsights` for Sentinel, REST API access for Splunk/ServiceNow/VirusTotal  
> **Run as:** Service account with appropriate API permissions for each integrated platform.

---

## ⚡ Quick Reference

| Playbook | Purpose |
|----------|---------|
| [Alert Triage Automation](#1-alert-triage-automation) | Auto-enrich and prioritize incoming alerts |
| [Incident Response — Isolate Host](#2-incident-response-automation--isolate-host) | Automated host isolation and artifact collection |
| [Sentinel API Integration](#3-sentinel-api-integration) | Automate Sentinel incident management |
| [Automated IOC Hunting](#4-automated-ioc-hunting) | Bulk-search for indicators of compromise |
| [IP/Hash Reputation — VirusTotal](#5-bulk-iphash-reputation--virustotal-api) | Bulk reputation checks via VirusTotal API |
| [ServiceNow Ticket Creation](#6-automated-servicenow-ticket-creation) | Create IR tickets automatically via REST |
| [HTML Dashboard Generation](#7-html-dashboard-generation) | Build security dashboards from PS data |
| [Automated Report Generation](#8-automated-report-generation) | Scheduled security posture reports |
| [Scheduled Hunting Scripts](#9-scheduled-hunting-scripts) | Continuous threat hunting via Task Scheduler |
| [New Local Admin Alerting](#10-alerting-on-new-local-admin-accounts) | Detect unauthorized local admin creation |
| [Critical Group Monitoring](#11-detecting-critical-group-membership-changes) | Alert on privileged group modifications |

---

## 1. Alert Triage Automation

### What it does
Automatically enriches incoming security alerts with context (user info, device status, threat intel) so analysts can triage faster.

### Automation Script
```powershell
function Invoke-AlertTriage {
    param(
        [string]$UserPrincipalName,
        [string]$IPAddress,
        [string]$ComputerName
    )

    $report = [ordered]@{}

    # User context
    if ($UserPrincipalName) {
        $user = Get-ADUser -Filter "UserPrincipalName -eq '$UserPrincipalName'" -Properties Enabled, LastLogonDate, MemberOf, PasswordLastSet
        $report['User'] = $user.Name
        $report['Enabled'] = $user.Enabled
        $report['LastLogon'] = $user.LastLogonDate
        $report['PasswordAge'] = ((Get-Date) - $user.PasswordLastSet).Days
        $report['IsPrivileged'] = ($user.MemberOf -match 'Domain Admins|Enterprise Admins|Administrators')
    }

    # Device context
    if ($ComputerName) {
        $computer = Get-ADComputer -Identity $ComputerName -Properties OperatingSystem, LastLogonDate -ErrorAction SilentlyContinue
        $report['OS'] = $computer.OperatingSystem
        $report['DeviceLastSeen'] = $computer.LastLogonDate
    }

    # IP reputation (VirusTotal)
    if ($IPAddress) {
        $report['IP'] = $IPAddress
        # Add VT check here (see section 5)
    }

    [PSCustomObject]$report
}

# Usage
Invoke-AlertTriage -UserPrincipalName "jsmith@corp.local" -ComputerName "WORKSTATION01" -IPAddress "185.220.101.5"
```

### Sample Output
```
User          : John Smith
Enabled       : True
LastLogon     : 3/29/2026 8:45:00 AM
PasswordAge   : 73
IsPrivileged  : True
OS            : Windows 11 Enterprise
DeviceLastSeen : 3/29/2026 8:00:00 AM
IP            : 185.220.101.5
```

### Tips & Warnings
> 💡 Prioritize alerts where `IsPrivileged = True` — compromised admin accounts require immediate escalation.

---

## 2. Incident Response Automation — Isolate Host

### What it does
Automated playbook to isolate a compromised host: disable network, collect volatile artifacts, and notify the IR team.

### Automation Script
```powershell
function Invoke-HostIsolation {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [string]$Reason = "Security incident",
        [string]$AnalystEmail = "soc@contoso.com"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $evidencePath = "\\forensics-share\cases\$ComputerName-$timestamp"
    New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null

    Write-Host "=== ISOLATING $ComputerName ===" -ForegroundColor Red

    # Step 1: Collect volatile evidence BEFORE isolation
    Write-Host "[1/4] Collecting volatile artifacts..." -ForegroundColor Yellow
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-NetTCPConnection -State Established |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
            Export-Csv "C:\forensics_network.csv" -NoTypeInformation

        Get-Process | Select-Object Id, ProcessName, Path, StartTime |
            Export-Csv "C:\forensics_processes.csv" -NoTypeInformation

        Get-DnsClientCache | Export-Csv "C:\forensics_dns.csv" -NoTypeInformation
    }

    # Copy evidence
    Copy-Item "\\$ComputerName\C$\forensics_*.csv" $evidencePath -Force

    # Step 2: Isolate via firewall (block all except management)
    Write-Host "[2/4] Applying firewall isolation..." -ForegroundColor Yellow
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        # Block all inbound/outbound except management subnet
        New-NetFirewallRule -DisplayName "IR-ISOLATE-BLOCK-ALL" -Direction Outbound -Action Block -Enabled True
        New-NetFirewallRule -DisplayName "IR-ISOLATE-ALLOW-MGMT" -Direction Outbound -Action Allow `
            -RemoteAddress "10.0.100.0/24" -Enabled True  # Management subnet
        New-NetFirewallRule -DisplayName "IR-ISOLATE-BLOCK-IN" -Direction Inbound -Action Block -Enabled True
        New-NetFirewallRule -DisplayName "IR-ISOLATE-ALLOW-MGMT-IN" -Direction Inbound -Action Allow `
            -RemoteAddress "10.0.100.0/24" -Enabled True
    }

    # Step 3: Disable AD account if applicable
    Write-Host "[3/4] Disabling associated user accounts..." -ForegroundColor Yellow
    # Find last logged-on user and disable
    $lastUser = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        (Get-WmiObject Win32_ComputerSystem).UserName
    }
    if ($lastUser -and $lastUser -match '\\(.+)') {
        Disable-ADAccount -Identity $Matches[1] -Confirm:$false
        Write-Host "  Disabled: $lastUser"
    }

    # Step 4: Log the action
    Write-Host "[4/4] Logging isolation action..." -ForegroundColor Yellow
    $logEntry = [PSCustomObject]@{
        Timestamp  = Get-Date
        Computer   = $ComputerName
        Action     = "ISOLATED"
        Reason     = $Reason
        Evidence   = $evidencePath
        DisabledUser = $lastUser
    }
    $logEntry | Export-Csv "\\forensics-share\isolation_log.csv" -Append -NoTypeInformation

    Write-Host "=== ISOLATION COMPLETE ===" -ForegroundColor Green
    return $logEntry
}

# Usage
Invoke-HostIsolation -ComputerName "WORKSTATION01" -Reason "Malware C2 detected"
```

### Tips & Warnings
> ⚠️ Always collect evidence BEFORE isolation — network connections are lost when firewall rules apply.

> 💡 Keep a management subnet exception so you can still remotely manage the isolated host.

---

## 3. Sentinel API Integration

### What it does
Automates Microsoft Sentinel incident management — update status, assign owners, add comments programmatically.

### Automation Script
```powershell
# Get open high-severity incidents
$incidents = Get-AzSentinelIncident -ResourceGroupName "SOC-RG" -WorkspaceName "SentinelWS" |
    Where-Object { $_.Severity -eq "High" -and $_.Status -eq "New" }

# Auto-assign to on-call analyst and add enrichment comment
foreach ($incident in $incidents) {
    # Assign to analyst
    Update-AzSentinelIncident -ResourceGroupName "SOC-RG" -WorkspaceName "SentinelWS" `
        -IncidentId $incident.Name `
        -Status Active `
        -OwnerObjectId "analyst-aad-object-id"

    # Add triage comment
    New-AzSentinelIncidentComment -ResourceGroupName "SOC-RG" -WorkspaceName "SentinelWS" `
        -IncidentId $incident.Name `
        -Message "Auto-triaged: High severity. Assigned to on-call analyst. Alert count: $($incident.AlertsCount)"
}

Write-Host "Processed $($incidents.Count) high-severity incidents"
```

### Tips & Warnings
> 💡 Schedule this to run every 5 minutes for near-real-time auto-triage.

---

## 4. Automated IOC Hunting

### What it does
Bulk-searches your environment for indicators of compromise (IPs, hashes, domains) from threat intelligence feeds.

### Hunting Script
```powershell
function Search-IOCs {
    param(
        [string[]]$MaliciousIPs,
        [string[]]$MaliciousDomains,
        [string[]]$MaliciousHashes
    )

    $findings = @()

    # Hunt IPs in network connections
    if ($MaliciousIPs) {
        Write-Host "Hunting $($MaliciousIPs.Count) malicious IPs..." -ForegroundColor Yellow
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($ip in $MaliciousIPs) {
            $hits = $connections | Where-Object { $_.RemoteAddress -eq $ip }
            foreach ($hit in $hits) {
                $findings += [PSCustomObject]@{
                    Type    = "IP"
                    IOC     = $ip
                    Context = "PID $($hit.OwningProcess) connected to $ip`:$($hit.RemotePort)"
                    Host    = $env:COMPUTERNAME
                }
            }
        }
    }

    # Hunt domains in DNS cache
    if ($MaliciousDomains) {
        Write-Host "Hunting $($MaliciousDomains.Count) malicious domains..." -ForegroundColor Yellow
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($domain in $MaliciousDomains) {
            $hits = $dnsCache | Where-Object { $_.Entry -match $domain }
            foreach ($hit in $hits) {
                $findings += [PSCustomObject]@{
                    Type    = "Domain"
                    IOC     = $domain
                    Context = "DNS cache: $($hit.Entry) -> $($hit.Data)"
                    Host    = $env:COMPUTERNAME
                }
            }
        }
    }

    # Hunt file hashes
    if ($MaliciousHashes) {
        Write-Host "Hunting $($MaliciousHashes.Count) malicious hashes..." -ForegroundColor Yellow
        $suspectPaths = @("C:\Users", "C:\Temp", "C:\ProgramData")
        foreach ($path in $suspectPaths) {
            Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 -and $_.Length -lt 50MB } |
                ForEach-Object {
                    $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if ($hash -and $hash -in $MaliciousHashes) {
                        $findings += [PSCustomObject]@{
                            Type    = "Hash"
                            IOC     = $hash
                            Context = "File: $($_.FullName)"
                            Host    = $env:COMPUTERNAME
                        }
                    }
                }
        }
    }

    return $findings
}

# Usage
$results = Search-IOCs -MaliciousIPs @("185.220.101.5","45.33.32.156") `
    -MaliciousDomains @("evil.com","c2server.net") `
    -MaliciousHashes @("abc123def456...")

$results | Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Load IOCs from a CSV threat intel feed: `$iocs = Import-Csv C:\intel\iocs.csv`

---

## 5. Bulk IP/Hash Reputation — VirusTotal API

### What it does
Checks IP addresses and file hashes against VirusTotal for reputation scoring — essential for alert enrichment.

### Automation Script
```powershell
function Get-VTReputation {
    param(
        [string]$ApiKey,
        [string]$IOC,
        [ValidateSet("ip","hash","domain")]
        [string]$Type
    )

    $headers = @{ "x-apikey" = $ApiKey }

    $uri = switch ($Type) {
        "ip"     { "https://www.virustotal.com/api/v3/ip_addresses/$IOC" }
        "hash"   { "https://www.virustotal.com/api/v3/files/$IOC" }
        "domain" { "https://www.virustotal.com/api/v3/domains/$IOC" }
    }

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        $stats = $response.data.attributes.last_analysis_stats
        [PSCustomObject]@{
            IOC        = $IOC
            Type       = $Type
            Malicious  = $stats.malicious
            Suspicious = $stats.suspicious
            Clean      = $stats.undetected
            Verdict    = if ($stats.malicious -gt 5) { "MALICIOUS" }
                         elseif ($stats.malicious -gt 0) { "SUSPICIOUS" }
                         else { "CLEAN" }
        }
    } catch {
        [PSCustomObject]@{ IOC = $IOC; Type = $Type; Verdict = "ERROR: $($_.Exception.Message)" }
    }
}

# Bulk check IPs
$apiKey = "your-vt-api-key"  # Store securely!
$suspiciousIPs = @("185.220.101.5", "45.33.32.156", "8.8.8.8")

$results = foreach ($ip in $suspiciousIPs) {
    Get-VTReputation -ApiKey $apiKey -IOC $ip -Type "ip"
    Start-Sleep -Seconds 15  # Free API rate limit: 4 requests/minute
}
$results | Format-Table -AutoSize
```

### Sample Output
```
IOC              Type  Malicious  Suspicious  Clean  Verdict
---              ----  ---------  ----------  -----  -------
185.220.101.5    ip    42         3           25     MALICIOUS
45.33.32.156     ip    0          1           69     CLEAN
8.8.8.8          ip    0          0           70     CLEAN
```

### Tips & Warnings
> ⚠️ **Never commit API keys to scripts.** Use: `$apiKey = Get-Secret -Name "VT-API" -Vault "SOC"`

> 💡 Free VT API = 4 requests/minute. Premium removes this limit.

---

## 6. Automated ServiceNow Ticket Creation

### What it does
Creates incident tickets in ServiceNow automatically from PowerShell — for IR workflow integration.

### Automation Script
```powershell
function New-SNOWIncident {
    param(
        [string]$Instance,       # e.g., "contoso.service-now.com"
        [PSCredential]$Credential,
        [string]$ShortDescription,
        [string]$Description,
        [string]$Urgency = "2",   # 1=High, 2=Medium, 3=Low
        [string]$AssignmentGroup = "Security Operations"
    )

    $uri = "https://$Instance/api/now/table/incident"
    $body = @{
        short_description  = $ShortDescription
        description        = $Description
        urgency            = $Urgency
        assignment_group   = $AssignmentGroup
        category           = "Security"
    } | ConvertTo-Json

    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
        "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    ))

    $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
        -ContentType "application/json" -Headers @{ Authorization = "Basic $auth" }

    [PSCustomObject]@{
        TicketNumber = $response.result.number
        SysId        = $response.result.sys_id
        Status       = "Created"
    }
}

# Usage
$cred = Get-Credential
New-SNOWIncident -Instance "contoso.service-now.com" -Credential $cred `
    -ShortDescription "Malware C2 detected on WORKSTATION01" `
    -Description "Defender alert: HackTool:Win64/Mimikatz.A detected. Host isolated. Evidence collected." `
    -Urgency "1"
```

### Tips & Warnings
> 💡 Chain with isolation playbook: isolate first, then auto-create the ticket with evidence paths.

---

## 7. HTML Dashboard Generation

### What it does
Generates a visual HTML security dashboard from PowerShell-collected data — useful for daily SOC reports and executive briefings.

### Generation Script
```powershell
$css = @"
<style>
body { font-family: Segoe UI, sans-serif; margin: 20px; }
h1 { color: #1a1a2e; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; }
th { background: #16213e; color: white; padding: 10px; text-align: left; }
td { padding: 8px; border-bottom: 1px solid #ddd; }
.critical { background: #ff4444; color: white; padding: 3px 8px; border-radius: 3px; }
.warning { background: #ffaa00; padding: 3px 8px; border-radius: 3px; }
.ok { background: #44bb44; color: white; padding: 3px 8px; border-radius: 3px; }
</style>
"@

$body = @"
<h1>🛡️ Daily SOC Dashboard — $(Get-Date -Format 'yyyy-MM-dd')</h1>
<h2>Failed Logons (Last 24h)</h2>
"@

# Add failed logon data
$failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 -ErrorAction SilentlyContinue
$body += "<p>Total failed logons: <strong>$($failedLogons.Count)</strong></p>"

# Generate HTML
$html = ConvertTo-Html -Head $css -Body $body -Title "SOC Dashboard"
$html | Out-File "C:\Reports\soc_dashboard_$(Get-Date -Format 'yyyyMMdd').html"

Write-Host "Dashboard saved: C:\Reports\soc_dashboard_$(Get-Date -Format 'yyyyMMdd').html"
```

### Tips & Warnings
> 💡 Schedule daily generation via Task Scheduler and email with `Send-MailMessage`.

---

## 8. Automated Report Generation

### What it does
Generates comprehensive security posture reports on a schedule — covering open vulnerabilities, compliance status, and recent incidents.

### Report Script
```powershell
function New-SecurityReport {
    $report = @()

    # Defender status across machines
    $report += [PSCustomObject]@{
        Category = "Endpoint Protection"
        Check    = "Defender Real-Time Protection"
        Status   = if ((Get-MpComputerStatus).RealTimeProtectionEnabled) { "PASS" } else { "FAIL" }
    }

    $report += [PSCustomObject]@{
        Category = "Endpoint Protection"
        Check    = "Signature Age"
        Status   = if ((Get-MpComputerStatus).AntivirusSignatureAge -le 1) { "PASS" } else { "WARN" }
    }

    # Password policy
    $policy = Get-ADDefaultDomainPasswordPolicy
    $report += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Min Password Length >= 12"
        Status   = if ($policy.MinPasswordLength -ge 12) { "PASS" } else { "FAIL" }
    }

    $report += [PSCustomObject]@{
        Category = "Identity"
        Check    = "Account Lockout Enabled"
        Status   = if ($policy.LockoutThreshold -gt 0) { "PASS" } else { "FAIL" }
    }

    $report | Format-Table -AutoSize
    $report | Export-Csv "C:\Reports\security_posture_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
}

New-SecurityReport
```

### Tips & Warnings
> 💡 Schedule weekly and email to management — consistent reporting builds security culture.

---

## 9. Scheduled Hunting Scripts

### What it does
Registers threat hunting scripts as scheduled tasks for continuous monitoring.

### Setup Script
```powershell
# Create a hunting script
$huntScript = @'
$findings = @()

# Hunt: New local admins
$admins = Get-LocalGroupMember -Group "Administrators"
$baseline = Get-Content "C:\Baselines\local_admins.txt" -ErrorAction SilentlyContinue
$newAdmins = $admins | Where-Object { $_.Name -notin $baseline }
if ($newAdmins) {
    $findings += "NEW LOCAL ADMIN: $($newAdmins.Name -join ', ')"
}

# Hunt: Suspicious scheduled tasks
$suspTasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike '\Microsoft\*' -and
    $_.Actions.Execute -match 'powershell|cmd|wscript|mshta'
}
if ($suspTasks) {
    $findings += "SUSPICIOUS TASKS: $($suspTasks.TaskName -join ', ')"
}

if ($findings) {
    $findings | Out-File "C:\Hunts\findings_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    # Send alert (customize for your environment)
}
'@

$huntScript | Out-File "C:\Scripts\daily_hunt.ps1"

# Register as scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Scripts\daily_hunt.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "06:00"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName "SOC-DailyHunt" -Action $action -Trigger $trigger -Principal $principal
```

### Tips & Warnings
> 💡 Run hunts during off-hours to minimize performance impact and catch overnight attacker activity.

---

## 10. Alerting on New Local Admin Accounts

### What it does
Monitors for new local administrator accounts — a common persistence technique.

### Detection Script
```powershell
# Get current admins
$currentAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name

# Compare with baseline
$baselinePath = "C:\Baselines\local_admins.txt"
if (Test-Path $baselinePath) {
    $baseline = Get-Content $baselinePath
    $newAdmins = $currentAdmins | Where-Object { $_ -notin $baseline }
    $removedAdmins = $baseline | Where-Object { $_ -notin $currentAdmins }

    if ($newAdmins) {
        Write-Host "[ALERT] New local admins detected:" -ForegroundColor Red
        $newAdmins | ForEach-Object { Write-Host "  + $_" -ForegroundColor Red }
    }
    if ($removedAdmins) {
        Write-Host "[INFO] Removed local admins:" -ForegroundColor Yellow
        $removedAdmins | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
    if (-not $newAdmins -and -not $removedAdmins) {
        Write-Host "[OK] No changes to local admins" -ForegroundColor Green
    }
} else {
    Write-Host "Creating baseline..." -ForegroundColor Yellow
}

# Update baseline
$currentAdmins | Out-File $baselinePath -Force
```

### Tips & Warnings
> ⚠️ New local admins on servers or domain controllers are critical findings — investigate immediately.

---

## 11. Detecting Critical Group Membership Changes

### What it does
Monitors changes to high-value Active Directory groups by checking Event 4728 (member added to security group) and 4729 (member removed).

### Detection Script
```powershell
$criticalGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                     "Account Operators","Backup Operators","Server Operators")

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4728, 4729, 4732, 4733, 4756, 4757
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 200 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $groupName = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
        if ($groupName -in $criticalGroups) {
            [PSCustomObject]@{
                Time     = $_.TimeCreated
                Event    = switch ($_.Id) {
                    4728 { "Member ADDED (global)" }
                    4729 { "Member REMOVED (global)" }
                    4732 { "Member ADDED (local)" }
                    4733 { "Member REMOVED (local)" }
                    4756 { "Member ADDED (universal)" }
                    4757 { "Member REMOVED (universal)" }
                }
                Group    = $groupName
                Member   = ($xml.Event.EventData.Data | Where-Object Name -eq 'MemberName').'#text'
                ChangedBy = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Sample Output
```
Time                     Event                  Group          Member                          ChangedBy
----                     -----                  -----          ------                          ---------
3/29/2026 2:00:00 AM     Member ADDED (global)  Domain Admins  CN=EvilUser,OU=Users,DC=corp..  attacker
```

### Tips & Warnings
> ⚠️ **Unauthorized additions to Domain Admins outside change windows are critical incidents.**

> 💡 Set up a real-time alert by forwarding these events to your SIEM with Windows Event Forwarding (WEF).

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [23 — Credential Security and LAPS](23-Credential-Security-and-LAPS.md) | [README](../README.md) | [25 — AppLocker and WDAC](25-AppLocker-and-WDAC.md) |
