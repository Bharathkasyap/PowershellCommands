# 17 — Microsoft Defender and Sentinel

> **Modules required:** `ConfigDefender` (built-in), `Az.SecurityInsights`, `Microsoft.Graph.Security`  
> **Run as:** Local Administrator for Defender commands; appropriate Azure RBAC roles for Sentinel.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-MpComputerStatus` | View Defender antivirus status, signature versions, and engine state |
| `Set-MpPreference` | Configure Defender scanning, exclusions, and real-time protection settings |
| `Get-MpThreat` | List threats currently detected on the endpoint |
| `Get-MpThreatDetection` | Show history of all threat detections with timestamps |
| `Start-MpScan` | Trigger a quick, full, or custom scan |
| `Update-MpSignature` | Force a signature definition update |
| `Get-MpComputerStatus` (ATP) | Check Defender for Endpoint onboarding status |
| `Get-AzSentinelIncident` | Retrieve Sentinel incidents via Az module |
| `Invoke-AzOperationalInsightsQuery` | Run KQL queries from PowerShell |
| `Get-AzSentinelAlertRule` | List Sentinel analytics rules |

---

## 1. `Get-MpComputerStatus`

### What it does
Returns the complete status of Microsoft Defender Antivirus on the local machine — whether real-time protection is on, when the last scan ran, signature age, engine version, and whether the machine is managed by Defender for Endpoint.

### Full Syntax
```powershell
Get-MpComputerStatus
    [-CimSession <CimSession[]>]
    [-AsJob]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-CimSession` | CimSession[] | Query a remote machine via CIM |
| `-AsJob` | Switch | Run as a background job |

### Real-World Example
**Scenario:** During an incident, you need to confirm that Defender is active and signatures are current on a suspect workstation.

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled,
    RealTimeProtectionEnabled, AntivirusSignatureLastUpdated,
    AntivirusSignatureAge, FullScanAge, QuickScanAge,
    OnAccessProtectionEnabled, BehaviorMonitorEnabled
```

### Sample Output
```
AMRunningMode                  : Normal
AntivirusEnabled               : True
RealTimeProtectionEnabled      : True
AntivirusSignatureLastUpdated  : 3/29/2026 4:15:00 AM
AntivirusSignatureAge          : 0
FullScanAge                    : 3
QuickScanAge                   : 0
OnAccessProtectionEnabled      : True
BehaviorMonitorEnabled         : True
```

### Tips & Warnings
> ⚠️ If `AMRunningMode` shows `Passive Mode`, another AV product is primary and Defender is not actively protecting.

> 💡 Signature age > 3 days is a red flag — indicates update failures.

---

## 2. `Set-MpPreference`

### What it does
Configures Microsoft Defender Antivirus preferences — exclusions, scan schedules, cloud protection level, real-time monitoring behavior, and more.

### Full Syntax
```powershell
Set-MpPreference
    [-ExclusionPath <String[]>]
    [-ExclusionExtension <String[]>]
    [-ExclusionProcess <String[]>]
    [-RealTimeProtectionEnabled <Boolean>]
    [-CloudBlockLevel <CloudBlockLevelType>]
    [-MAPSReporting <MAPSReportingType>]
    [-SubmitSamplesConsent <SubmitSamplesConsentType>]
    [-ScanScheduleQuickScanTime <DateTime>]
    [-DisableRealtimeMonitoring <Boolean>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-ExclusionPath` | Folders to exclude from scanning |
| `-ExclusionExtension` | File extensions to exclude |
| `-ExclusionProcess` | Processes whose file activity is excluded |
| `-CloudBlockLevel` | `Default`, `Moderate`, `High`, `HighPlus`, `ZeroTolerance` |
| `-MAPSReporting` | `Disabled`, `Basic`, `Advanced` — cloud telemetry level |
| `-DisableRealtimeMonitoring` | `$true` disables real-time protection (dangerous!) |

### Real-World Example
**Scenario:** You're hardening Defender settings across endpoints — enable cloud-delivered protection at maximum level and audit current exclusions.

```powershell
# Set aggressive cloud protection
Set-MpPreference -CloudBlockLevel HighPlus -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples

# Audit existing exclusions (attackers love to hide here)
$prefs = Get-MpPreference
Write-Host "=== Path Exclusions ===" -ForegroundColor Yellow
$prefs.ExclusionPath
Write-Host "=== Process Exclusions ===" -ForegroundColor Yellow
$prefs.ExclusionProcess
Write-Host "=== Extension Exclusions ===" -ForegroundColor Yellow
$prefs.ExclusionExtension
```

### Sample Output
```
=== Path Exclusions ===
C:\SQL\Data
C:\Temp\BuildAgent
=== Process Exclusions ===
sqlservr.exe
w3wp.exe
=== Extension Exclusions ===
.bak
.log
```

### Tips & Warnings
> ⚠️ **Attackers add exclusions** to hide malware. Regularly audit exclusions with `Get-MpPreference` and alert on changes.

> 💡 Use `Add-MpPreference` to append exclusions without overwriting, and `Remove-MpPreference` to remove specific ones.

---

## 3. `Get-MpThreat` and `Get-MpThreatDetection`

### What it does
`Get-MpThreat` shows threats currently on the system. `Get-MpThreatDetection` shows the full history of detections including those already remediated.

### Full Syntax
```powershell
Get-MpThreat [-ThreatID <Int64>]
Get-MpThreatDetection [-ThreatID <Int64>]
```

### Real-World Example
**Scenario:** After an alert fires, you want to see all threats detected in the last 7 days and their remediation status.

```powershell
Get-MpThreatDetection |
    Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-7) } |
    Select-Object ThreatID, @{n='Threat';e={
        (Get-MpThreat -ThreatID $_.ThreatID).ThreatName
    }}, InitialDetectionTime, ProcessName, ActionSuccess |
    Sort-Object InitialDetectionTime -Descending |
    Format-Table -AutoSize
```

### Sample Output
```
ThreatID Threat                          InitialDetectionTime     ProcessName       ActionSuccess
-------- ------                          --------------------     -----------       -------------
2147735735 HackTool:Win64/Mimikatz.A     3/28/2026 3:14:22 PM    powershell.exe    True
2147519003 Trojan:Script/Wacatac.B!ml    3/27/2026 11:02:05 AM   chrome.exe        True
```

### Tips & Warnings
> ⚠️ `HackTool:*Mimikatz*` detections are critical — investigate the user and machine immediately.

> 💡 Export detections to CSV for your SIEM or incident report:
> ```powershell
> Get-MpThreatDetection | Export-Csv C:\ir\defender_detections.csv -NoTypeInformation
> ```

---

## 4. `Start-MpScan`

### What it does
Initiates a manual antivirus scan — quick (common malware locations), full (entire disk), or custom (specific path).

### Full Syntax
```powershell
Start-MpScan
    [-ScanType <ScanType>]    # QuickScan, FullScan, CustomScan
    [-ScanPath <String>]       # Required for CustomScan
    [-AsJob]
```

### Real-World Example
**Scenario:** You've identified a suspicious directory during incident response and want to scan it immediately.

```powershell
# Scan a specific suspect directory
Start-MpScan -ScanType CustomScan -ScanPath "C:\Users\compromised\AppData\Local\Temp"

# Quick scan after remediation to verify clean
Start-MpScan -ScanType QuickScan
```

### Sample Output
```
(No output on success — check Get-MpThreatDetection for results)
```

### Tips & Warnings
> 💡 Full scans can take hours. Run as a background job: `Start-MpScan -ScanType FullScan -AsJob`

> ⚠️ Custom scans only check the specified path — they don't scan memory or running processes.

---

## 5. `Update-MpSignature`

### What it does
Forces an immediate update of Defender antivirus definitions from the configured update source.

### Full Syntax
```powershell
Update-MpSignature
    [-UpdateSource <UpdateSource>]   # MicrosoftUpdateServer, MMPC, InternalDefinitionUpdateServer, FileShares
```

### Real-World Example
**Scenario:** A new zero-day has been disclosed and Microsoft has pushed emergency signatures. You need all endpoints updated now.

```powershell
# Force update from Microsoft
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# Verify the update
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureAge, AntivirusSignatureVersion
```

### Sample Output
```
AntivirusSignatureLastUpdated : 3/29/2026 2:30:00 PM
AntivirusSignatureAge         : 0
AntivirusSignatureVersion     : 1.407.521.0
```

### Tips & Warnings
> 💡 For air-gapped networks, download definitions manually from [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/defenderupdates) and use `-UpdateSource FileShares`.

---

## 6. Defender for Endpoint Integration

### What it does
Check whether a machine is onboarded to Microsoft Defender for Endpoint (MDE) and query its status.

### Detection Script
```powershell
# Check MDE onboarding status
$mdeSvc = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
if ($mdeSvc -and $mdeSvc.Status -eq 'Running') {
    Write-Host "[OK] Defender for Endpoint service (Sense) is running" -ForegroundColor Green

    # Check onboarding state in registry
    $onboardState = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue
    if ($onboardState.OnboardingState -eq 1) {
        Write-Host "[OK] MDE onboarding confirmed — OrgId: $($onboardState.OrgId)" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Sense service running but onboarding incomplete" -ForegroundColor Yellow
    }
} else {
    Write-Host "[ALERT] Defender for Endpoint is NOT running!" -ForegroundColor Red
}
```

### Sample Output
```
[OK] Defender for Endpoint service (Sense) is running
[OK] MDE onboarding confirmed — OrgId: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

### Tips & Warnings
> ⚠️ If Sense is stopped, the machine is blind to MDE — investigate immediately.

---

## 7. Microsoft Sentinel — Querying Incidents

### What it does
Retrieve security incidents from Microsoft Sentinel using the Az module for triage and automation.

### Full Syntax
```powershell
Get-AzSentinelIncident
    -ResourceGroupName <String>
    -WorkspaceName <String>
    [-Id <String>]
    [-Filter <String>]
    [-OrderBy <String>]
```

### Real-World Example
**Scenario:** Pull all high-severity Sentinel incidents from the last 24 hours for triage.

```powershell
Connect-AzAccount
$incidents = Get-AzSentinelIncident -ResourceGroupName "SOC-RG" -WorkspaceName "SentinelWorkspace" |
    Where-Object { $_.Severity -eq "High" -and $_.CreatedTimeUtc -gt (Get-Date).AddDays(-1) } |
    Select-Object Title, IncidentNumber, Severity, Status, CreatedTimeUtc, AlertsCount
$incidents | Format-Table -AutoSize
```

### Sample Output
```
Title                               IncidentNumber Severity Status  CreatedTimeUtc           AlertsCount
-----                               -------------- -------- ------  --------------           -----------
Brute force against Azure portal    4521           High     New     3/29/2026 1:00:00 AM     3
Suspicious PowerShell execution     4523           High     New     3/29/2026 6:45:00 AM     1
```

### Tips & Warnings
> 💡 Automate incident assignment by piping results to `Update-AzSentinelIncident` with `-Owner` and `-Status`.

---

## 8. Running KQL Queries from PowerShell

### What it does
Execute Kusto Query Language (KQL) queries against your Log Analytics workspace directly from PowerShell — enabling automated hunting, reporting, and alerting.

### Full Syntax
```powershell
Invoke-AzOperationalInsightsQuery
    -WorkspaceId <String>
    -Query <String>
    [-Timespan <TimeSpan>]
```

### Real-World Example
**Scenario:** Hunt for failed sign-ins from unusual countries in the last 24 hours.

```powershell
$workspaceId = "your-workspace-guid"
$query = @"
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize FailureCount=count() by UserPrincipalName, Location=LocationDetails.city, IPAddress
| where FailureCount > 10
| order by FailureCount desc
"@

$results = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query
$results.Results | Format-Table -AutoSize
```

### Sample Output
```
UserPrincipalName        Location     IPAddress       FailureCount
-----------------        --------     ---------       ------------
admin@contoso.com        Moscow       185.220.101.5   47
jsmith@contoso.com       Lagos        102.89.23.18    23
```

### Tips & Warnings
> 💡 Wrap KQL queries in here-strings (`@" ... "@`) for readability.

> ⚠️ Large queries can time out — use `-Timespan` to limit the window and add `| take 1000` to cap results.

---

## 9. Managing Sentinel Analytics Rules

### What it does
List, create, and manage Sentinel analytics (alert) rules programmatically for bulk rule management.

### Real-World Example
**Scenario:** Audit all enabled analytics rules and export their configuration.

```powershell
$rules = Get-AzSentinelAlertRule -ResourceGroupName "SOC-RG" -WorkspaceName "SentinelWorkspace"
$rules | Where-Object { $_.Enabled -eq $true } |
    Select-Object DisplayName, Kind, Severity, @{n='Query';e={$_.Query}} |
    Export-Csv C:\sentinel\active_rules.csv -NoTypeInformation

Write-Host "Total rules: $($rules.Count)  |  Enabled: $(($rules | Where-Object Enabled).Count)"
```

### Sample Output
```
Total rules: 87  |  Enabled: 72
```

### Tips & Warnings
> 💡 Version-control your analytics rules by exporting them as ARM templates: `Export-AzResourceGroup`.

---

## 10. M365 Defender Alert Policies and Advanced Hunting

### What it does
Query Microsoft 365 Defender alert policies and use the Advanced Hunting API to run cross-workload KQL queries spanning email, identity, endpoint, and cloud apps.

### Real-World Example
**Scenario:** Use the Microsoft Graph Security API to pull recent high-severity alerts.

```powershell
Connect-MgGraph -Scopes "SecurityEvents.Read.All"

# Get high-severity alerts from the last 48 hours
$alerts = Get-MgSecurityAlert -Filter "severity eq 'high' and createdDateTime gt $(
    (Get-Date).AddHours(-48).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
)" -Top 50

$alerts | Select-Object Title, Severity, Status, CreatedDateTime,
    @{n='Source';e={$_.VendorInformation.Provider}} |
    Format-Table -AutoSize
```

### Sample Output
```
Title                                  Severity Status  CreatedDateTime          Source
-----                                  -------- ------  ---------------          ------
Suspicious inbox forwarding rule       High     newAlert 3/29/2026 8:00:00 AM   OATP
Credential access via LSASS            High     newAlert 3/28/2026 11:30:00 PM  WDATP
```

### Tips & Warnings
> 💡 For Advanced Hunting API, use `Invoke-MgGraphRequest`:
> ```powershell
> $body = @{ Query = "DeviceProcessEvents | where FileName == 'mimikatz.exe' | take 10" }
> Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body $body
> ```

> ⚠️ Advanced Hunting requires `ThreatHunting.Read.All` permission — request it in your app registration.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [16 — WinRM and Remote Management Security](16-WinRM-and-Remote-Management-Security.md) | [README](../README.md) | [18 — Exchange and Email Security](18-Exchange-and-Email-Security.md) |
