# 09 — Log Management & SIEM

> **Purpose:** Windows Event Logs are the primary evidence source for security investigations. This guide covers querying them efficiently, filtering for security-relevant Event IDs, and exporting data to SIEM tools.  
> **Run as:** Local Administrator (or Event Log Readers group member for read access)

---

## ⚡ Quick Reference

| Event ID | Log | Security Relevance |
|----------|-----|--------------------|
| 4624 | Security | Successful logon — track user activity |
| 4625 | Security | Failed logon — detect brute force |
| 4648 | Security | Explicit credential logon — detect Pass-the-Hash/runas |
| 4672 | Security | Special privileges assigned — detect privilege escalation |
| 4688 | Security | New process created — detect malicious execution |
| 4697 | Security | Service installed — detect persistence |
| 7045 | System | New service installed — detect persistence |

---

## 1. `Get-WinEvent` with `-FilterHashtable`

### What it does
Queries Windows Event Logs efficiently using a hashtable of filter criteria. This is faster and more readable than XML queries. The `-FilterHashtable` parameter is the recommended way to query event logs from PowerShell.

### Full Syntax
```powershell
Get-WinEvent
    -FilterHashtable <Hashtable>
    [-MaxEvents <Int64>]
    [-ComputerName <String>]
    [-Credential <PSCredential>]
    [-Oldest]
    [-ErrorAction <ActionPreference>]
```

### FilterHashtable Keys
| Key | Description |
|-----|-------------|
| `LogName` | Log name: `'Security'`, `'System'`, `'Application'` |
| `Id` | One or more Event IDs (integer or array) |
| `StartTime` | Events after this DateTime |
| `EndTime` | Events before this DateTime |
| `Level` | `1`=Critical, `2`=Error, `3`=Warning, `4`=Information |
| `ProviderName` | Event source/provider name |
| `Keywords` | Bitmask — e.g., `4503599627370496` = Audit Success |

### Real-World Example
**Scenario:** Pull all successful and failed logon events from the last 24 hours for SIEM triage.

```powershell
$since = (Get-Date).AddHours(-24)

# Get both successful and failed logons
$logonEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4624, 4625)
    StartTime = $since
} -ErrorAction SilentlyContinue

# Parse and structure the events
$logonEvents | ForEach-Object {
    $event = $_
    [PSCustomObject]@{
        TimeCreated    = $event.TimeCreated
        EventId        = $event.Id
        EventType      = if ($event.Id -eq 4624) { 'SUCCESS' } else { 'FAILURE' }
        AccountName    = $event.Properties[5].Value
        AccountDomain  = $event.Properties[6].Value
        LogonType      = $event.Properties[8].Value
        WorkstationName = $event.Properties[11].Value
        SourceIP       = $event.Properties[18].Value
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
```

### Sample Output
```
TimeCreated              EventId  EventType  AccountName  LogonType  SourceIP
-----------              -------  ---------  -----------  ---------  --------
3/29/2026 8:03:00 AM     4624     SUCCESS    jsmith       3          10.0.0.20
3/29/2026 3:14:22 AM     4625     FAILURE    Administrator  3        185.220.101.45
3/29/2026 3:14:18 AM     4625     FAILURE    Administrator  3        185.220.101.45
3/29/2026 3:14:10 AM     4625     FAILURE    Administrator  3        185.220.101.45
```

### Tips & Warnings
> ⚠️ **Multiple 4625 failures from `185.220.101.45`** at 3 AM targeting the Administrator account — this is a brute force attack from an external IP. Block the IP at the firewall and investigate.

> 💡 **Logon Types explained:**
> | Type | Description |
> |------|-------------|
> | 2 | Interactive (local console) |
> | 3 | Network (file share, WMI) |
> | 4 | Batch (scheduled task) |
> | 5 | Service |
> | 7 | Unlock |
> | 10 | RemoteInteractive (RDP) |
> | 11 | CachedInteractive (cached credentials) |

---

## 2. Filtering Key Security Event IDs

### Event ID 4625 — Failed Logon (Brute Force Detection)

```powershell
# Detect brute force: accounts with 5+ failures in last hour
$since = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $since
} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            TargetAccount = $_.Properties[5].Value
            SourceIP    = $_.Properties[19].Value
        }
    } |
    Group-Object TargetAccount |
    Where-Object { $_.Count -ge 5 } |
    Select-Object Count, Name |
    Sort-Object Count -Descending |
    Format-Table -AutoSize
```

### Event ID 4648 — Explicit Credential Logon (Pass-the-Hash / runas)

```powershell
# Logons using explicit credentials (suspicious if from unexpected processes)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4648
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            CallerProcess = $_.Properties[11].Value
            CredentialsFor = $_.Properties[5].Value
            TargetServer  = $_.Properties[8].Value
        }
    } |
    Where-Object { $_.CallerProcess -match 'mimikatz|lsass|wce|fgdump|gsecdump|powershell|cmd' } |
    Format-Table -AutoSize -Wrap
```

### Event ID 4672 — Special Privileges Assigned (Privilege Escalation)

```powershell
# High-privilege logons (SeDebugPrivilege, SeTcbPrivilege, etc.)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4672
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time       = $_.TimeCreated
            Account    = $_.Properties[1].Value
            Privileges = $_.Properties[4].Value
        }
    } |
    Where-Object { $_.Account -notmatch 'SYSTEM|NETWORK SERVICE|LOCAL SERVICE|DWM|UMFD' } |
    Format-Table -AutoSize
```

### Event IDs 4697 and 7045 — New Service Installed

```powershell
# Detect new service installations (common persistence technique)
$since = (Get-Date).AddDays(-7)

# Service object audit log
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697; StartTime=$since} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{n='ServiceName'; e={$_.Properties[4].Value}},
        @{n='ImagePath'; e={$_.Properties[5].Value}},
        @{n='StartType'; e={$_.Properties[6].Value}},
        @{n='Account'; e={$_.Properties[7].Value}} |
    Format-Table -AutoSize

# System log version
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$since} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{n='ServiceName'; e={$_.Properties[0].Value}},
        @{n='ImagePath'; e={$_.Properties[1].Value}} |
    Format-Table -AutoSize
```

### Event ID 4688 — New Process Created (Malicious Execution)

```powershell
# Find suspicious process creation events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            NewProcess    = $_.Properties[5].Value
            CommandLine   = $_.Properties[8].Value
            ParentProcess = $_.Properties[13].Value
            RunAs         = $_.Properties[6].Value
        }
    } |
    Where-Object {
        $_.CommandLine -match '-enc|-encodedcommand|IEX|Invoke-Expression|DownloadString|Net\.WebClient' -or
        $_.NewProcess  -match 'mshta|regsvr32|certutil|bitsadmin|wmic|cmstp|installutil'
    } |
    Format-Table -AutoSize -Wrap
```

---

## 3. `Export-Csv` for SIEM Integration

### What it does
Exports PowerShell objects to CSV format — the most common format for ingesting into SIEM tools (Splunk, Microsoft Sentinel, QRadar, etc.). `-NoTypeInformation` removes the PowerShell type header that would appear in the first line.

### Real-World Example
**Scenario:** Export the last 24 hours of security events to CSV for import into Splunk.

```powershell
$since    = (Get-Date).AddHours(-24)
$outFile  = "C:\SIEM\security_events_$(Get-Date -Format 'yyyyMMdd_HH').csv"

# Collect and parse critical event IDs
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = @(4624, 4625, 4648, 4672, 4688, 4697, 4720, 4740)
    StartTime = $since
} -ErrorAction SilentlyContinue

$events | Select-Object TimeCreated, Id,
    @{n='MachineName'; e={$_.MachineName}},
    @{n='Message'; e={$_.Message -replace '\r?\n',' '}} |
    Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

Write-Host "Exported $($events.Count) events to $outFile"
```

### Tips & Warnings
> 💡 Schedule this as a Windows Scheduled Task to run hourly and drop files to a monitored directory picked up by your SIEM agent.

> 💡 For Splunk Universal Forwarder, configure it to monitor `C:\SIEM\*.csv` — or better, configure Windows Event Log forwarding directly using WEF (Windows Event Forwarding).

---

## 4. Configuring Log Forwarding with `wecutil` and `Set-WinEvent`

### What it does
Windows Event Forwarding (WEF) centralizes logs from many Windows machines to a single Windows Event Collector server without needing a SIEM agent on every endpoint.

### Real-World Example
**Scenario:** Configure log forwarding so that Security events from all domain computers are forwarded to your central SIEM collector.

```powershell
# On the COLLECTOR server — configure Windows Event Collector service
wecutil qc /q

# On each SOURCE computer — set WinRM to allow forwarding
winrm quickconfig -quiet

# Set the event log to allow forwarding via GPO or directly:
$logName = "Security"
$maxSizeMB = 1024

# Increase log size to prevent overwriting before collection
$log = Get-WinEvent -ListLog $logName
$log.MaximumSizeInBytes = $maxSizeMB * 1MB
$log.IsEnabled = $true
$log.SaveChanges()

Write-Host "Security log max size set to $maxSizeMB MB"
```

### Tips & Warnings
> 💡 Deploy WEF subscriptions via Group Policy (`Computer Configuration > Windows Settings > Security Settings > Event Log`).

> 💡 For cloud-based SIEM (Microsoft Sentinel), use the **Azure Monitor Agent** (AMA) with a Data Collection Rule (DCR) — no WEF needed.

---

## 5. Detecting Brute Force Attacks — Full Script

### What it does
A complete, production-ready script to detect brute force attacks by analyzing failed logon events, identifying attacking IPs, and optionally blocking them via Windows Firewall.

```powershell
param(
    [int]$ThresholdCount    = 10,    # Failures to trigger alert
    [int]$ThresholdMinutes  = 15,    # Lookback window
    [switch]$BlockAttackers          # Auto-block via firewall (use with caution)
)

$since = (Get-Date).AddMinutes(-$ThresholdMinutes)

Write-Host "Analyzing failed logons since $since..." -ForegroundColor Cyan

# Collect and parse 4625 events
$failedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $since
} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            TargetUser  = $_.Properties[5].Value
            SourceIP    = $_.Properties[19].Value
            LogonType   = $_.Properties[10].Value
        }
    }

if (-not $failedLogons) {
    Write-Host "No failed logons found in the last $ThresholdMinutes minutes." -ForegroundColor Green
    exit
}

# Group by source IP
$attackers = $failedLogons | Group-Object SourceIP |
    Where-Object { $_.Count -ge $ThresholdCount -and $_.Name -match '\d{1,3}\.\d{1,3}' } |
    Select-Object Count, Name,
        @{n='TargetAccounts'; e={($_.Group.TargetUser | Sort-Object -Unique) -join ', '}} |
    Sort-Object Count -Descending

if ($attackers) {
    Write-Host "`n🚨 BRUTE FORCE DETECTED:" -ForegroundColor Red
    $attackers | Format-Table -AutoSize

    if ($BlockAttackers) {
        foreach ($attacker in $attackers) {
            $ip = $attacker.Name
            Write-Host "Blocking $ip via firewall..." -ForegroundColor Yellow
            New-NetFirewallRule -DisplayName "BLOCK BruteForce $ip" `
                -Direction Inbound -Protocol Any `
                -RemoteAddress $ip -Action Block `
                -Enabled True -Profile Any `
                -Description "Auto-blocked by brute force detection script $(Get-Date)"
        }
    }
} else {
    Write-Host "No brute force activity detected (threshold: $ThresholdCount failures in $ThresholdMinutes min)" -ForegroundColor Green
}
```

### Sample Output
```
🚨 BRUTE FORCE DETECTED:

Count  Name              TargetAccounts
-----  ----              --------------
47     185.220.101.45    Administrator, admin, root, jsmith
12     203.0.113.99      Administrator, user
```

### Tips & Warnings
> ⚠️ Use `-BlockAttackers` cautiously in production. Automated blocking can potentially lock out legitimate users if IPs are shared (NAT, VPN exit nodes).

> 💡 For enterprise environments, integrate with your SIEM to trigger this automatically when threshold-based alerts fire.

---

## 6. Detecting Privilege Escalation Events — Full Script

```powershell
# Combined view: Special privilege logons followed by suspicious process creation
$since = (Get-Date).AddDays(-1)

Write-Host "=== Privilege Escalation Hunt ===" -ForegroundColor Cyan

# Step 1: Who logged on with special privileges?
$specialLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4672; StartTime=$since
} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time       = $_.TimeCreated
            Account    = $_.Properties[1].Value
            Domain     = $_.Properties[2].Value
            Privileges = ($_.Properties[4].Value -replace '\s+', ', ')
        }
    } | Where-Object { $_.Account -notmatch 'SYSTEM|NETWORK SERVICE|LOCAL SERVICE|DWM|UMFD' }

Write-Host "`nSpecial Privilege Logons (non-system):"
$specialLogons | Format-Table -AutoSize

# Step 2: Cross-reference with account creation events (4720)
$newAccounts = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4720; StartTime=$since
} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time       = $_.TimeCreated
            NewAccount = $_.Properties[0].Value
            CreatedBy  = $_.Properties[4].Value
        }
    }

if ($newAccounts) {
    Write-Host "`n⚠️ NEW ACCOUNTS CREATED in last 24h:" -ForegroundColor Yellow
    $newAccounts | Format-Table -AutoSize
}

# Step 3: Account lockouts (4740) — may indicate ongoing attack
$lockouts = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4740; StartTime=$since
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
        @{n='LockedAccount'; e={$_.Properties[0].Value}},
        @{n='CallerComputer'; e={$_.Properties[1].Value}}

if ($lockouts) {
    Write-Host "`n🔒 ACCOUNT LOCKOUTS in last 24h:" -ForegroundColor Red
    $lockouts | Format-Table -AutoSize
}
```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [08 — Cloud Security: Azure](08-Cloud-Security-Azure.md) | [README](../README.md) | [10 — Compliance and Auditing](10-Compliance-and-Auditing.md) |
