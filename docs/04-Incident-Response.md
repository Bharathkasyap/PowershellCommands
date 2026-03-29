# 04 — Incident Response

> **Run as:** Local Administrator (some commands require elevated privileges)  
> **Modules:** Built-in PowerShell cmdlets; `ActiveDirectory` for AD queries

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-Process` | List running processes with PID, CPU, memory |
| `Stop-Process` | Terminate a process by PID or name |
| `Get-ScheduledTask` | List scheduled tasks (common persistence mechanism) |
| `Get-WinEvent` | Query Windows Event logs for IOCs |
| `query user` / `Get-RDUserSession` | List logged-on users and sessions |
| `Get-LocalUser` | List local user accounts |
| `Get-NetTCPConnection` | Active network connections (see also: 03-Network-Security) |
| `Get-ComputerInfo` | Collect system information for forensics |

---

## 1. `Get-Process`

### What it does
Lists all currently running processes on the machine. Each process entry includes the Process ID (PID), name, CPU usage, memory consumption, and the path to the executable. During incident response, you compare this list against known-good baselines to spot malicious processes.

### Full Syntax
```powershell
Get-Process
    [[-Name] <String[]>]
    [-Id <Int32[]>]
    [-ComputerName <String[]>]
    [-IncludeUserName]
    [-FileVersionInfo]
    [-Module]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Name` | Filter by process name (supports wildcards: `"power*"`) |
| `-Id` | Filter by PID |
| `-IncludeUserName` | Show which user context the process runs under (requires admin) |
| `-FileVersionInfo` | Include file version and company name from the executable |
| `-ComputerName` | Query a remote computer |

### Real-World Example
**Scenario:** An endpoint detection alert fires for suspicious activity. You need to see all running processes, who launched them, and their full executable paths.

```powershell
Get-Process -IncludeUserName |
    Select-Object Name, Id, UserName, CPU,
        @{n='WorkingSetMB'; e={[math]::Round($_.WorkingSet64 / 1MB, 2)}},
        @{n='Path'; e={$_.Path}} |
    Sort-Object CPU -Descending |
    Format-Table -AutoSize
```

### Sample Output
```
Name        Id    UserName             CPU   WorkingSetMB  Path
----        --    --------             ---   ------------  ----
chrome      4832  CORP\jsmith         45.2  312.55        C:\Program Files\Chrome\chrome.exe
powershell  1337  CORP\bthompson       8.1   65.22         C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
svchost     892   NT AUTHORITY\SYSTEM  1.3   12.40         C:\Windows\System32\svchost.exe
```

### Tips & Warnings
> ⚠️ Look for **processes in unusual directories** — legitimate Windows processes like `svchost.exe` always run from `C:\Windows\System32\`. If you see `svchost.exe` in `C:\Users\` or `C:\Temp\`, it's almost certainly malware masquerading as a system process.

> ⚠️ **Unsigned processes** running as SYSTEM or in sensitive contexts deserve scrutiny:
> ```powershell
> Get-Process | Where-Object { $_.Path -ne $null } |
>     Get-AuthenticodeSignature |
>     Where-Object { $_.Status -ne 'Valid' } |
>     Select-Object Path, Status
> ```

> 💡 Cross-reference PIDs with `Get-NetTCPConnection` to find processes with suspicious external connections.

---

## 2. `Stop-Process`

### What it does
Terminates a running process immediately. Use this during incident response to kill malicious processes, but **always document before terminating** — some forensic evidence exists only in memory.

### Full Syntax
```powershell
Stop-Process
    [-Id] <Int32[]>
    [-Force]
    [-PassThru]
    [-WhatIf]
    [-Confirm]

# OR by name:
Stop-Process -Name <String[]> [-Force]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Id` | PID of the process to kill (preferred — unambiguous) |
| `-Name` | Kill all processes with this name (use carefully — could kill multiple) |
| `-Force` | Kill without prompting; also forcibly terminates protected processes |
| `-WhatIf` | Preview what would be killed without actually doing it |

### Real-World Example
**Scenario:** You've confirmed PID 1337 is a reverse shell. Before killing it, you capture its memory information, then terminate it.

```powershell
# Step 1: Capture information about the process before killing it
$malProc = Get-Process -Id 1337 -IncludeUserName
$malProc | Select-Object Name, Id, Path, UserName, StartTime |
    Export-Csv -Path "C:\IR\killed_process_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# Step 2: Kill the process
Stop-Process -Id 1337 -Force
Write-Host "Process 1337 ($($malProc.Name)) terminated."
```

### Sample Output
```
Process 1337 (powershell) terminated.
```

### Tips & Warnings
> ⚠️ **Dump memory before killing** if this is a forensic investigation. Memory-resident malware leaves no trace on disk after termination. Use tools like `procdump` (Sysinternals) or `Out-Minidump`.

> ⚠️ `-Name` can kill multiple processes simultaneously (e.g., all `chrome` windows). Use `-Id` for precision.

---

## 3. `Get-ScheduledTask`

### What it does
Lists Windows Scheduled Tasks — automated jobs that run programs or scripts on a schedule or at system events. Scheduled tasks are a **primary persistence mechanism** for malware — attackers create a task to re-execute their malware every time the system boots or a user logs in.

### Full Syntax
```powershell
Get-ScheduledTask
    [[-TaskName] <String[]>]
    [[-TaskPath] <String[]>]
    [-CimSession <CimSession[]>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-TaskName` | Filter by task name (supports wildcards) |
| `-TaskPath` | Filter by folder path in Task Scheduler (e.g., `\Microsoft\Windows\`) |

### Real-World Example
**Scenario:** You suspect malware has established persistence via a scheduled task. Audit all non-Microsoft tasks.

```powershell
Get-ScheduledTask |
    Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    Select-Object TaskName, TaskPath, State,
        @{n='Action'; e={$_.Actions.Execute}},
        @{n='Arguments'; e={$_.Actions.Arguments}},
        @{n='RunAs'; e={$_.Principal.UserId}} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
TaskName          TaskPath  State    Action                              Arguments  RunAs
--------          --------  -----    ------                              ---------  -----
BackupJob         \Custom\  Running  C:\Windows\System32\cmd.exe         /c ...     SYSTEM
UpdaterTask       \         Ready    C:\Users\jsmith\AppData\Temp\upd.exe           CORP\jsmith
WindowsUpdater    \         Ready    powershell.exe                      -enc JAB... SYSTEM
```

### Tips & Warnings
> ⚠️ **Tasks with `powershell.exe -enc` or `-encodedcommand`** arguments are suspicious — the `-enc` flag runs base64-encoded PowerShell to evade detection.

> ⚠️ **Tasks running from `%APPDATA%`, `%TEMP%`, or user profile directories** are highly suspicious. Legitimate Windows tasks run from `System32` or `Program Files`.

> 💡 Decode a base64 argument to inspect it:
> ```powershell
> $encodedCmd = "JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdA..."
> [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedCmd))
> ```

---

## 4. `Get-WinEvent` for IOCs

### What it does
Queries Windows Event Logs — Security, System, Application, and others. This is the primary source of evidence for incident response. Each security event has an **Event ID** that tells you exactly what happened (logon, process creation, service installation, etc.).

### Full Syntax
```powershell
Get-WinEvent
    [-LogName <String[]>]
    [-FilterHashtable <Hashtable>]
    [-FilterXPath <String>]
    [-MaxEvents <Int64>]
    [-ComputerName <String>]
    [-Credential <PSCredential>]
    [-Oldest]
```

### Key Security Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Logon with explicit credentials (runas) |
| 4688 | Security | New process created (requires audit policy) |
| 4697 | Security | Service installed |
| 4720 | Security | User account created |
| 4740 | Security | Account locked out |
| 7045 | System | New service installed |

### Real-World Example
**Scenario:** Investigate suspicious activity — look for failed logons followed by success (brute force), and any new services installed in the last 24 hours.

```powershell
$since = (Get-Date).AddHours(-24)

# Failed logon attempts
$failedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $since
} -ErrorAction SilentlyContinue

Write-Host "Failed logons in last 24h: $($failedLogons.Count)"

# New services installed
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 7045
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id,
        @{n='ServiceName'; e={$_.Properties[0].Value}},
        @{n='ImagePath'; e={$_.Properties[1].Value}},
        @{n='StartType'; e={$_.Properties[2].Value}} |
    Format-Table -AutoSize
```

### Sample Output
```
Failed logons in last 24h: 47

TimeCreated              Id    ServiceName       ImagePath                      StartType
-----------              --    -----------       ---------                      ---------
3/29/2026 3:14:00 AM     7045  WindowsUpdater    C:\Users\Public\payload.exe    Auto
```

### Tips & Warnings
> ⚠️ 47 failed logons followed by a new service installation at 3 AM is a classic brute-force-then-persist pattern. Escalate this immediately.

> 💡 Process creation events (4688) require audit policy to be enabled:
> ```powershell
> auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
> ```

---

## 5. `query user` — List Active Sessions

### What it does
Lists all currently logged-on users and their session details (Session ID, state, idle time). This is a classic command-line tool exposed as a PowerShell command. Useful for confirming whether a user is currently active or identifying unauthorized remote sessions.

### Full Syntax
```powershell
query user [username] [/server:<ComputerName>]

# PowerShell wrapper to get structured output:
(query user) -split '\n' | Select-Object -Skip 1 | ForEach-Object {
    if ($_.Trim()) {
        [PSCustomObject]@{
            Username  = $_.Substring(1,22).Trim()
            SessionName = $_.Substring(23,19).Trim()
            Id        = $_.Substring(42,4).Trim()
            State     = $_.Substring(46,8).Trim()
            IdleTime  = $_.Substring(54,11).Trim()
        }
    }
}
```

### Real-World Example
**Scenario:** You receive a report of unusual activity. Check who is currently logged on to the affected server.

```powershell
# On local machine
query user

# On remote machine
query user /server:SERVER01
```

### Sample Output
```
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>jsmith                console             1  Active  none       3/29/2026 8:00 AM
 bthompson             rdp-tcp#2           2  Active  00:45      3/29/2026 2:30 AM
```

### Tips & Warnings
> ⚠️ **`bthompson` connected via RDP at 2:30 AM** and has been idle for 45 minutes. If this is outside business hours and unexpected, it warrants investigation.

> 💡 To forcibly log off a suspicious session:
> ```powershell
> logoff 2 /server:SERVER01
> ```

---

## 6. `Get-LocalUser`

### What it does
Lists all local user accounts on a machine — including built-in accounts (Administrator, Guest), service accounts, and any additional accounts created. Attackers sometimes create local accounts as a backdoor.

### Full Syntax
```powershell
Get-LocalUser
    [[-Name] <String[]>]
    [-SID <SecurityIdentifier[]>]
```

### Real-World Example
**Scenario:** After an intrusion, check whether any unauthorized local accounts were created.

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
    PasswordNeverExpires, Description |
    Sort-Object Enabled -Descending |
    Format-Table -AutoSize
```

### Sample Output
```
Name           Enabled  LastLogon              PasswordLastSet         PasswordNeverExpires
----           -------  ---------              ---------------         --------------------
Administrator  False    1/1/2024 12:00:00 AM   1/1/2024 12:00:00 AM   False
Guest          False    Never                  Never                   False
jsmith         True     3/29/2026 8:00:00 AM   2/1/2026 9:00:00 AM    False
support_acc    True     3/29/2026 3:15:00 AM   3/29/2026 3:14:00 AM   True
```

### Tips & Warnings
> ⚠️ **`support_acc`** was created and immediately used at 3:14-3:15 AM with a password that never expires. This is a backdoor account — investigate and remove immediately.

> 💡 Check which local accounts are in the Administrators group:
> ```powershell
> Get-LocalGroupMember -Group "Administrators"
> ```

---

## 7. Collecting System Information for Forensics

### What it does
`Get-ComputerInfo` provides a comprehensive snapshot of system information — OS version, hostname, last boot time, hardware, and more. Collecting this data early in an incident preserves context before potential system changes.

### Real-World Example
**Scenario:** You're called to respond to a potential compromise. Capture a full system snapshot before any remediation.

```powershell
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputDir = "C:\IR\$env:COMPUTERNAME-$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force

# System info
Get-ComputerInfo | Out-File "$outputDir\system_info.txt"

# Running processes with paths
Get-Process -IncludeUserName | Select-Object Name, Id, Path, UserName, StartTime |
    Export-Csv "$outputDir\processes.csv" -NoTypeInformation

# Active connections
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Export-Csv "$outputDir\connections.csv" -NoTypeInformation

# Scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
    @{n='Action'; e={$_.Actions.Execute}} |
    Export-Csv "$outputDir\scheduled_tasks.csv" -NoTypeInformation

# Local users
Get-LocalUser | Export-Csv "$outputDir\local_users.csv" -NoTypeInformation

# Active sessions
query user | Out-File "$outputDir\active_sessions.txt"

# Recent security events (last 4 hours)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-4)} `
    -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Export-Csv "$outputDir\security_events.csv" -NoTypeInformation

Write-Host "IR data collected to: $outputDir" -ForegroundColor Green
```

### Tips & Warnings
> 💡 Run this script as one of the **first actions** on a suspected compromised machine — before rebooting, remediating, or scanning (which can overwrite artifacts).

> 💡 Copy the output directory to a separate investigation machine or evidence share immediately.

> ⚠️ Do not run remediation (delete files, kill services) until evidence is preserved.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [03 — Network Security](03-Network-Security.md) | [README](../README.md) | [05 — Threat Hunting](05-Threat-Hunting.md) |
