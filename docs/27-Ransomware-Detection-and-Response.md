# 27 — Ransomware Detection and Response

> **Run as:** Local Administrator for detection scripts; Domain Admin for enterprise-wide response.  
> **Philosophy:** Speed is critical — detect fast, isolate fast, preserve evidence, then remediate.

---

## ⚡ Quick Reference

| Technique | Purpose |
|-----------|---------|
| [FileSystemWatcher for Mass Encryption](#1-filesystemwatcher--mass-encryption-detection) | Real-time detection of ransomware encrypting files |
| [Shadow Copy Deletion Detection](#2-shadow-copy-deletion-detection) | Detect VSS deletion (Event 524, vssadmin in logs) |
| [Process Hollowing Detection](#3-detecting-process-hollowing) | Find ransomware hiding in legitimate processes |
| [Backup Tool Termination](#4-backup-tool-termination-detection) | Detect services being killed before encryption |
| [Host Isolation](#5-isolating-infected-hosts) | Emergency network isolation via PS |
| [Evidence Collection Pre-Remediation](#6-collecting-evidence-pre-remediation) | Capture forensic data before cleanup |
| [VSS Restoration](#7-vss-shadow-copy-restoration) | Recover files from shadow copies |
| [Patient Zero Identification](#8-identifying-patient-zero) | Find the first infected machine via process trees |
| [Persistence Hunting](#9-hunting-ransomware-persistence) | Find ransomware persistence mechanisms |
| [TTP Detection Scripts](#10-common-ransomware-ttp-detection) | Detect Conti/LockBit/BlackCat patterns |

---

## 1. FileSystemWatcher — Mass Encryption Detection

### What it does
Uses .NET's `FileSystemWatcher` to monitor directories for rapid file changes (renames, modifications) that indicate ransomware encryption in progress.

### Detection Script
```powershell
function Start-RansomwareWatch {
    param(
        [string]$WatchPath = "C:\Users",
        [int]$ThresholdPerMinute = 50,
        [string]$AlertScript = $null
    )

    $script:changeCount = 0
    $script:lastCheck = Get-Date
    $script:ransomwareExtensions = @('.encrypted','.locked','.crypto','.crypt','.enc','.locky',
        '.cerber','.zepto','.thor','.aesir','.zzzzz','.conti','.lockbit','.blackcat')

    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $WatchPath
    $watcher.IncludeSubdirectories = $true
    $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
    $watcher.EnableRaisingEvents = $true

    $action = {
        $script:changeCount++
        $extension = [System.IO.Path]::GetExtension($Event.SourceEventArgs.FullPath)

        # Check for known ransomware extensions
        if ($extension -in $script:ransomwareExtensions) {
            Write-Host "[CRITICAL] Ransomware extension detected: $($Event.SourceEventArgs.FullPath)" -ForegroundColor Red
        }

        # Check rate threshold
        $elapsed = (Get-Date) - $script:lastCheck
        if ($elapsed.TotalSeconds -ge 60) {
            if ($script:changeCount -gt $ThresholdPerMinute) {
                Write-Host "[ALERT] $($script:changeCount) file changes in last minute — possible ransomware!" -ForegroundColor Red
                # Trigger isolation
            }
            $script:changeCount = 0
            $script:lastCheck = Get-Date
        }
    }

    Register-ObjectEvent $watcher "Changed" -Action $action | Out-Null
    Register-ObjectEvent $watcher "Renamed" -Action $action | Out-Null
    Register-ObjectEvent $watcher "Created" -Action $action | Out-Null

    Write-Host "Ransomware watch active on $WatchPath (threshold: $ThresholdPerMinute changes/min)" -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop..."
}

Start-RansomwareWatch -WatchPath "C:\Users" -ThresholdPerMinute 50
```

### Sample Output
```
Ransomware watch active on C:\Users (threshold: 50 changes/min)
[CRITICAL] Ransomware extension detected: C:\Users\jsmith\Documents\report.docx.lockbit
[ALERT] 347 file changes in last minute — possible ransomware!
```

### Tips & Warnings
> ⚠️ When the threshold triggers, **immediately isolate the host** — every second of delay means more encrypted files.

> 💡 Deploy this on file servers monitoring shared directories for maximum coverage.

---

## 2. Shadow Copy Deletion Detection

### What it does
Detects when Volume Shadow Copies are deleted — ransomware's first step is usually to destroy backups.

### Detection Script
```powershell
# Method 1: Check System event log for VSS deletion (Event 524)
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Microsoft-Windows-Backup'
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'shadow copy|vss|backup' } |
    Select-Object TimeCreated, Id, Message | Format-Table -AutoSize -Wrap

# Method 2: Check for vssadmin or wmic shadowcopy delete in process creation logs
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 10000 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $cmdLine = ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
        if ($cmdLine -match 'vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete') {
            [PSCustomObject]@{
                Time     = $_.TimeCreated
                User     = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
                Command  = $cmdLine
                Alert    = "RANSOMWARE INDICATOR"
            }
        }
    } | Format-Table -AutoSize -Wrap

# Method 3: Check current VSS status
$shadows = Get-CimInstance Win32_ShadowCopy
if ($shadows.Count -eq 0) {
    Write-Host "[ALERT] NO shadow copies exist — they may have been deleted!" -ForegroundColor Red
} else {
    Write-Host "[INFO] $($shadows.Count) shadow copies found" -ForegroundColor Green
    $shadows | Select-Object ID, InstallDate, VolumeName | Format-Table -AutoSize
}
```

### Sample Output
```
Time                     User     Command                                          Alert
----                     ----     -------                                          -----
3/29/2026 2:00:00 AM     SYSTEM   vssadmin delete shadows /all /quiet              RANSOMWARE INDICATOR
3/29/2026 2:00:01 AM     SYSTEM   bcdedit /set {default} recoveryenabled no        RANSOMWARE INDICATOR
3/29/2026 2:00:02 AM     SYSTEM   wbadmin delete catalog -quiet                    RANSOMWARE INDICATOR
```

### Tips & Warnings
> ⚠️ `vssadmin delete shadows /all /quiet` + `bcdedit /set recoveryenabled no` = **ransomware is executing NOW**. Isolate immediately.

> 💡 Monitor for `wmic process call create` as well — some ransomware uses WMI to execute these commands.

---

## 3. Detecting Process Hollowing

### What it does
Ransomware frequently uses process hollowing to hide inside legitimate Windows processes.

### Detection Script
```powershell
$expectedPaths = @{
    'svchost.exe'    = 'C:\Windows\System32\svchost.exe'
    'explorer.exe'   = 'C:\Windows\explorer.exe'
    'lsass.exe'      = 'C:\Windows\System32\lsass.exe'
    'csrss.exe'      = 'C:\Windows\System32\csrss.exe'
    'services.exe'   = 'C:\Windows\System32\services.exe'
    'RuntimeBroker.exe' = 'C:\Windows\System32\RuntimeBroker.exe'
}

Get-CimInstance Win32_Process |
    Where-Object { $expectedPaths.ContainsKey($_.Name) } |
    ForEach-Object {
        $expected = $expectedPaths[$_.Name]
        if ($_.ExecutablePath -and $_.ExecutablePath -ne $expected) {
            [PSCustomObject]@{
                ProcessName  = $_.Name
                PID          = $_.ProcessId
                ExpectedPath = $expected
                ActualPath   = $_.ExecutablePath
                CommandLine  = $_.CommandLine
                ALERT        = "PROCESS HOLLOWING SUSPECTED"
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Tips & Warnings
> ⚠️ Path mismatches for system processes are a critical finding — the process has been replaced by malware.

---

## 4. Backup Tool Termination Detection

### What it does
Ransomware kills backup and database services before encryption to prevent recovery. This script detects those services being stopped.

### Detection Script
```powershell
# Services commonly targeted by ransomware
$targetServices = @(
    'vss', 'sql', 'svc$', 'memtas', 'mepocs', 'sophos', 'veeam',
    'backup', 'GxVss', 'GxBlr', 'GxFWD', 'GxCVD', 'GxCIMgr',
    'MSSQL', 'SQLAgent', 'SQLBrowser', 'SQLWriter', 'MsDtsServer',
    'ReportServer', 'SSAS', 'SSRS'
)

# Check for recently stopped services
$stoppedServices = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 7036  # Service Control Manager — service state change
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'stopped' } |
    ForEach-Object {
        $svcName = if ($_.Message -match '"(.+)" service') { $Matches[1] } else { "Unknown" }
        foreach ($target in $targetServices) {
            if ($svcName -match $target) {
                [PSCustomObject]@{
                    Time     = $_.TimeCreated
                    Service  = $svcName
                    Status   = "STOPPED"
                    Risk     = "RANSOMWARE PRE-ENCRYPTION"
                }
            }
        }
    }

if ($stoppedServices) {
    Write-Host "[CRITICAL] Backup/database services terminated:" -ForegroundColor Red
    $stoppedServices | Format-Table -AutoSize
} else {
    Write-Host "[OK] No suspicious service terminations" -ForegroundColor Green
}
```

### Sample Output
```
[CRITICAL] Backup/database services terminated:

Time                     Service              Status   Risk
----                     -------              ------   ----
3/29/2026 2:00:00 AM     Veeam Backup         STOPPED  RANSOMWARE PRE-ENCRYPTION
3/29/2026 2:00:01 AM     SQL Server (MSSQLSERVER) STOPPED  RANSOMWARE PRE-ENCRYPTION
3/29/2026 2:00:02 AM     Volume Shadow Copy   STOPPED  RANSOMWARE PRE-ENCRYPTION
```

### Tips & Warnings
> ⚠️ Multiple backup/database services stopping within seconds = ransomware pre-encryption activity.

---

## 5. Isolating Infected Hosts

### What it does
Emergency isolation of a ransomware-infected host to prevent lateral spread.

### Isolation Script
```powershell
function Invoke-RansomwareIsolation {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [switch]$LocalExecution
    )

    $isolationBlock = {
        Write-Host "[1/3] Disabling network adapters..." -ForegroundColor Red
        # Keep management adapter if possible
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            Disable-NetAdapter -Name $_.Name -Confirm:$false
            Write-Host "  Disabled: $($_.Name)"
        }

        # Alternative: Firewall-based isolation (keeps management access)
        # New-NetFirewallRule -DisplayName "RANSOMWARE-ISOLATE" -Direction Outbound -Action Block -Enabled True
        # New-NetFirewallRule -DisplayName "RANSOMWARE-ISOLATE-IN" -Direction Inbound -Action Block -Enabled True

        Write-Host "[2/3] Killing suspicious processes..." -ForegroundColor Yellow
        # Kill known ransomware-associated processes
        $suspiciousProcs = Get-Process | Where-Object {
            $_.Path -and (
                $_.Path -match 'Temp|AppData|ProgramData|Public' -and
                $_.Path -match '\.exe$'
            )
        }
        foreach ($proc in $suspiciousProcs) {
            Write-Host "  Killing: $($proc.ProcessName) (PID: $($proc.Id)) — $($proc.Path)"
            Stop-Process -Id $proc.Id -Force
        }

        Write-Host "[3/3] Disabling task scheduler to prevent re-execution..." -ForegroundColor Yellow
        Stop-Service -Name "Schedule" -Force -ErrorAction SilentlyContinue

        Write-Host "=== HOST ISOLATED ===" -ForegroundColor Green
    }

    if ($LocalExecution) {
        & $isolationBlock
    } else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $isolationBlock
    }
}

# Usage (remote)
Invoke-RansomwareIsolation -ComputerName "INFECTED-PC01"

# Usage (local — run on infected machine)
Invoke-RansomwareIsolation -LocalExecution
```

### Tips & Warnings
> ⚠️ **Isolate FIRST, investigate AFTER.** Every minute of delay allows encryption to spread.

> 💡 Prefer firewall-based isolation over disabling adapters — it preserves remote management access.

---

## 6. Collecting Evidence Pre-Remediation

### What it does
Captures critical forensic data before rebuilding or restoring from backup — essential for root cause analysis and insurance claims.

### Collection Script
```powershell
$evidencePath = "E:\forensics\ransomware_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null

Write-Host "Collecting ransomware evidence to $evidencePath" -ForegroundColor Yellow

# 1. Ransom note
Get-ChildItem C:\ -Recurse -Include "README*","DECRYPT*","RESTORE*","HOW_TO*","*ransom*" -ErrorAction SilentlyContinue |
    Select-Object -First 5 | Copy-Item -Destination $evidencePath

# 2. Encrypted file samples (for decryptor identification)
Get-ChildItem C:\Users -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match '^\.(encrypted|locked|crypto|crypt|lockbit|blackcat)$' } |
    Select-Object -First 3 |
    Copy-Item -Destination $evidencePath

# 3. Process list
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
    Export-Csv "$evidencePath\processes.csv" -NoTypeInformation

# 4. Network connections
Get-NetTCPConnection | Select-Object * | Export-Csv "$evidencePath\network.csv" -NoTypeInformation

# 5. Scheduled tasks
Get-ScheduledTask | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.TaskName; Path = $_.TaskPath; Actions = ($_.Actions.Execute -join '; ')
    }
} | Export-Csv "$evidencePath\scheduled_tasks.csv" -NoTypeInformation

# 6. Event logs
wevtutil epl Security "$evidencePath\Security.evtx"
wevtutil epl System "$evidencePath\System.evtx"
wevtutil epl Application "$evidencePath\Application.evtx"

# 7. Registry autoruns
$autorunKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
foreach ($key in $autorunKeys) {
    if (Test-Path $key) {
        Get-ItemProperty $key | Out-File "$evidencePath\autoruns.txt" -Append
    }
}

# 8. PowerShell history
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histFile) { Copy-Item $histFile "$evidencePath\ps_history.txt" }

Write-Host "Evidence collection complete: $evidencePath" -ForegroundColor Green
Get-ChildItem $evidencePath | Format-Table Name, Length, LastWriteTime
```

### Tips & Warnings
> ⚠️ **Collect evidence BEFORE reimaging.** Once you rebuild, the evidence is gone forever.

> 💡 Submit ransom note and encrypted file sample to [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) to identify the variant and check for free decryptors.

---

## 7. VSS Shadow Copy Restoration

### What it does
Recovers files from Volume Shadow Copies — if the ransomware didn't delete them, this is the fastest recovery path.

### Recovery Script
```powershell
# List available shadow copies
$shadows = Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending
if ($shadows.Count -eq 0) {
    Write-Host "[ALERT] No shadow copies available — ransomware likely deleted them" -ForegroundColor Red
    return
}

Write-Host "Available shadow copies:" -ForegroundColor Green
$shadows | Select-Object ID, InstallDate, VolumeName | Format-Table -AutoSize

# Mount the most recent shadow copy
$latestShadow = $shadows[0]
$shadowPath = $latestShadow.DeviceObject + "\"
$mountPoint = "C:\ShadowRestore"

# Create symbolic link to access shadow copy
if (Test-Path $mountPoint) { cmd /c rmdir $mountPoint }
cmd /c mklink /d $mountPoint "$shadowPath"

Write-Host "Shadow copy mounted at: $mountPoint" -ForegroundColor Green
Write-Host "Browse and copy needed files from $mountPoint"

# Example: Restore a specific directory
# Copy-Item "$mountPoint\Users\jsmith\Documents\*" "C:\Restored\Documents\" -Recurse
```

### Tips & Warnings
> 💡 Shadow copies are read-only — copy files out, don't try to modify them in place.

> ⚠️ If ALL shadow copies are gone, check offline backups, cloud backups, or OneDrive/SharePoint previous versions.

---

## 8. Identifying Patient Zero

### What it does
Traces the ransomware infection back to the first compromised machine by analyzing process trees, login events, and file modification timestamps.

### Investigation Script
```powershell
# Step 1: Find the earliest encrypted file across network shares
$shares = @("\\fileserver\shared", "\\dc01\netlogon")
$earliestFile = $null

foreach ($share in $shares) {
    Get-ChildItem $share -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '^\.(encrypted|locked|lockbit|blackcat)$' } |
        Sort-Object LastWriteTime |
        Select-Object -First 1 |
        ForEach-Object {
            if (-not $earliestFile -or $_.LastWriteTime -lt $earliestFile.LastWriteTime) {
                $earliestFile = $_
            }
        }
}

if ($earliestFile) {
    Write-Host "Earliest encrypted file:" -ForegroundColor Yellow
    Write-Host "  File: $($earliestFile.FullName)"
    Write-Host "  Time: $($earliestFile.LastWriteTime)"
    Write-Host "  Check who accessed this share at this time"
}

# Step 2: Check SMB access logs around that time
$targetTime = $earliestFile.LastWriteTime
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 5140, 5145
    StartTime = $targetTime.AddMinutes(-30)
    EndTime = $targetTime.AddMinutes(5)
} -MaxEvents 100 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time    = $_.TimeCreated
            User    = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
            Source  = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
            Share   = ($xml.Event.EventData.Data | Where-Object Name -eq 'ShareName').'#text'
        }
    } | Format-Table -AutoSize

Write-Host "The source IP above is likely Patient Zero" -ForegroundColor Red
```

### Tips & Warnings
> 💡 Patient Zero identification helps determine the initial access vector (phishing, RDP, VPN compromise, etc.).

---

## 9. Hunting Ransomware Persistence

### What it does
Searches for persistence mechanisms used by ransomware to survive reboots and re-encrypt after cleanup.

### Hunt Script
```powershell
$findings = @()

# Registry Run keys
$runKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        (Get-ItemProperty $key).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            if ($_.Value -match 'Temp|AppData|ProgramData|Public|\.bat|\.cmd|\.vbs|powershell.*-enc') {
                $findings += [PSCustomObject]@{ Type="Registry"; Location=$key; Name=$_.Name; Value=$_.Value }
            }
        }
    }
}

# Scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $actions = $_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
    if ($actions -match 'Temp|AppData|ProgramData|encrypt|ransom|lock') {
        $findings += [PSCustomObject]@{ Type="ScheduledTask"; Location=$_.TaskPath; Name=$_.TaskName; Value=($actions -join ' | ') }
    }
}

# WMI subscriptions
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    $findings += [PSCustomObject]@{ Type="WMI"; Location="CommandLineEventConsumer"; Name=$_.Name; Value=$_.CommandLineTemplate }
}

# Services
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -match 'Temp|AppData|ProgramData|Public' -and $_.StartMode -eq 'Auto'
} | ForEach-Object {
    $findings += [PSCustomObject]@{ Type="Service"; Location="Services"; Name=$_.Name; Value=$_.PathName }
}

if ($findings) {
    Write-Host "[ALERT] Ransomware persistence found:" -ForegroundColor Red
    $findings | Format-Table -AutoSize -Wrap
} else {
    Write-Host "[OK] No ransomware persistence mechanisms detected" -ForegroundColor Green
}
```

### Tips & Warnings
> ⚠️ Remove ALL persistence before restoring files — otherwise ransomware will re-encrypt after reboot.

---

## 10. Common Ransomware TTP Detection

### What it does
Detects behavioral patterns specific to well-known ransomware families (Conti, LockBit, BlackCat/ALPHV).

### Detection Script
```powershell
Write-Host "=== Ransomware TTP Scanner ===" -ForegroundColor Yellow

# === Conti Indicators ===
Write-Host "`n[Conti]" -ForegroundColor Cyan
# Conti uses net.exe for enumeration
$contiEnum = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5000 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
    } | Where-Object { $_ -match 'net (view|share|user|group|localgroup)' }
if ($contiEnum) { Write-Host "  [ALERT] Network enumeration detected (Conti pattern)" -ForegroundColor Red }

# === LockBit Indicators ===
Write-Host "`n[LockBit]" -ForegroundColor Cyan
# LockBit disables Windows Defender
$lockbitDefender = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5000 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
    } | Where-Object { $_ -match 'Set-MpPreference.*-DisableRealtimeMonitoring|powershell.*Defender.*disable' }
if ($lockbitDefender) { Write-Host "  [ALERT] Defender tampering detected (LockBit pattern)" -ForegroundColor Red }

# LockBit creates .lockbit extension
$lockbitFiles = Get-ChildItem C:\Users -Recurse -Filter "*.lockbit" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($lockbitFiles) { Write-Host "  [CRITICAL] .lockbit encrypted files found!" -ForegroundColor Red }

# === BlackCat/ALPHV Indicators ===
Write-Host "`n[BlackCat/ALPHV]" -ForegroundColor Cyan
# BlackCat is written in Rust, often propagates via PsExec
$blackcatPsexec = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5000 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
    } | Where-Object { $_ -match 'psexec.*-s.*-d|psexesvc' }
if ($blackcatPsexec) { Write-Host "  [ALERT] PsExec lateral movement detected (BlackCat pattern)" -ForegroundColor Red }

# === General Ransomware TTPs ===
Write-Host "`n[General TTPs]" -ForegroundColor Cyan
# Check for mass service termination
$svcKills = Get-WinEvent -FilterHashtable @{LogName='System';Id=7036;StartTime=(Get-Date).AddHours(-1)} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'stopped' }
if ($svcKills.Count -gt 10) {
    Write-Host "  [ALERT] $($svcKills.Count) services stopped in last hour — pre-encryption activity!" -ForegroundColor Red
}

# Check for encryption indicators
$ransomNotes = Get-ChildItem C:\ -Recurse -Include "README*DECRYPT*","RESTORE*FILES*","HOW*DECRYPT*","*RANSOM*NOTE*" -ErrorAction SilentlyContinue
if ($ransomNotes) {
    Write-Host "  [CRITICAL] Ransom notes found:" -ForegroundColor Red
    $ransomNotes | Select-Object -First 3 | ForEach-Object { Write-Host "    $($_.FullName)" }
}

Write-Host "`n=== Scan Complete ===" -ForegroundColor Yellow
```

### Sample Output
```
=== Ransomware TTP Scanner ===

[Conti]
  [ALERT] Network enumeration detected (Conti pattern)

[LockBit]
  [ALERT] Defender tampering detected (LockBit pattern)
  [CRITICAL] .lockbit encrypted files found!

[BlackCat/ALPHV]

[General TTPs]
  [ALERT] 23 services stopped in last hour — pre-encryption activity!
  [CRITICAL] Ransom notes found:
    C:\Users\jsmith\Desktop\RESTORE-MY-FILES.txt

=== Scan Complete ===
```

### Tips & Warnings
> ⚠️ If the TTP scanner finds active ransomware indicators, **isolate immediately** — do not wait for further analysis.

> 💡 Keep this script on a USB drive or network share for rapid deployment during incidents.

> 💡 After containment, submit samples to:
> - [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) — identify the variant
> - [No More Ransom](https://www.nomoreransom.org/) — check for free decryptors
> - Your cyber insurance provider — they may have negotiation resources

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [26 — Cloud Security Multicloud](26-Cloud-Security-Multicloud.md) | [README](../README.md) | — (End of series) |
