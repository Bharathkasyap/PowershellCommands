# 14 — Windows Registry Security

> **Philosophy:** The Windows registry is both the backbone of system configuration and an attacker's favorite persistence playground. Proactive hunting across registry hives exposes backdoors, hijacks, and misconfigurations before they become incidents.  
> **Run as:** Local or Domain Administrator. Most queries require elevated privileges to read `HKLM` hives and security descriptors.

---

## ⚡ Quick Reference

| Hunt | What You're Looking For |
|------|------------------------|
| [Run/RunOnce/RunServices Keys](#1-hunting-persistence-in-runrunoncerunservices-keys) | Classic startup persistence |
| [COM Hijacking](#2-detecting-com-hijacking) | Hijacked COM objects loading attacker DLLs |
| [Registry ACL Auditing](#3-auditing-registry-acls) | Weak permissions on sensitive keys |
| [AppInit_DLLs](#4-appinit_dlls-detection) | DLL injection via AppInit mechanism |
| [IFEO Debugger Keys](#5-image-file-execution-options-ifeo-debugger-keys) | Process interception via debugger redirection |
| [Winlogon Hijacking](#6-winlogon-hijacking-detection) | Persistence through the logon process |
| [LSA Protection Keys](#7-lsa-protection-keys) | Credential theft protection validation |
| [All Autorun Locations](#8-comprehensive-autorun-registry-scan-15-locations) | Full sweep of 15+ autorun registry paths |
| [CLSID Hijacking](#9-clsid-hijacking) | Rogue CLSID entries pointing to attacker binaries |
| [Disable SMBv1/LLMNR/WPAD](#10-disabling-smbv1llmnrwpad-via-registry) | Protocol hardening against poisoning attacks |
| [Secure Channel Hardening](#11-secure-channel-hardening) | TLS/SSL and Schannel configuration audit |

---

## 1. Hunting Persistence in Run/RunOnce/RunServices Keys

### What you're looking for
Run and RunOnce keys are the most abused persistence mechanism in Windows. Red flags:
- Executables in `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, or user-writable paths
- PowerShell or `cmd.exe` with encoded arguments
- RunServices keys (legacy — rarely legitimate on modern systems)

### Hunt Query

```powershell
$persistKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
)

$persistKeys | Where-Object { Test-Path $_ } | ForEach-Object {
    $key = $_
    Get-ItemProperty $key -EA SilentlyContinue | ForEach-Object { $_.PSObject.Properties } |
        Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            [PSCustomObject]@{
                Key = $key; Name = $_.Name; Value = $_.Value
                Suspicious = $_.Value -match 'temp|appdata|public|users\\|enc|bypass|hidden|IEX|\.vbs|\.ps1|cmd\.exe'
            }
        }
} | Sort-Object Suspicious -Descending | Format-Table -AutoSize -Wrap
```

### Sample Output
```
Key                          Name           Value                                       Suspicious
---                          ----           -----                                       ----------
HKCU:\SOFTWARE\...\Run       xupdate        C:\Users\Public\xupdate.exe -silent          True
HKCU:\SOFTWARE\...\RunOnce   tmploader      powershell.exe -w hidden -ep bypass ...      True
HKLM:\SOFTWARE\...\Run       SecurityHealth %ProgramFiles%\Windows Defender\MSASCuiL.exe False
```

### Tips & Warnings
> ⚠️ RunServices and RunServicesOnce keys are legacy (Windows 9x/NT era). Any entry here on a modern system is almost certainly malicious.

> 💡 Compare findings across your fleet to spot outliers — one machine with a unique Run key entry is far more suspicious than a value present on every endpoint.

---

## 2. Detecting COM Hijacking

### What you're looking for
COM hijacking abuses the COM resolution order. Windows checks `HKCU\Software\Classes\CLSID` before `HKLM`, so an attacker can plant a rogue DLL under the user hive that loads instead of the legitimate system COM object.

### Hunt Query

```powershell
Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
    $clsid   = $_.PSChildName
    $userDll = (Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    $sysDll  = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'

    if ($userDll) {
        [PSCustomObject]@{
            CLSID       = $clsid
            UserDLL     = $userDll
            SystemDLL   = $sysDll
            IsShadowing = ($null -ne $sysDll)
            Suspicious  = $userDll -match 'temp|appdata|public|users\\|\.tmp'
        }
    }
} | Where-Object { $_.IsShadowing -or $_.Suspicious } | Format-Table -AutoSize -Wrap
```

### Sample Output
```
CLSID                                  UserDLL                           SystemDLL                       IsShadowing
-----                                  -------                           ---------                       -----------
{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7} C:\Users\jdoe\AppData\Local\r.dll C:\Windows\System32\shell32.dll True
```

### Tips & Warnings
> ⚠️ A CLSID under `HKCU` shadowing a legitimate `HKLM` COM object with a DLL in a user-writable directory is a textbook COM hijack. Verify with `Get-AuthenticodeSignature`.

> 💡 Autoruns (Sysinternals) enumerates COM hijacks graphically, but the PowerShell approach scales across endpoints via `Invoke-Command`.

---

## 3. Auditing Registry ACLs

### What you're looking for
Weak registry permissions allow non-admin users to modify security-critical keys. Audit keys that control services, drivers, and security policy.

### Hunt Query

```powershell
$criticalKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
)

foreach ($key in $criticalKeys) {
    (Get-Acl $key -ErrorAction SilentlyContinue).Access |
        Where-Object {
            $_.IdentityReference -match 'Everyone|Users|Authenticated Users' -and
            $_.RegistryRights -match 'FullControl|SetValue|WriteKey'
        } | ForEach-Object {
            [PSCustomObject]@{
                Key      = $key; Identity = $_.IdentityReference.Value
                Rights   = $_.RegistryRights; Type = $_.AccessControlType
            }
        }
} | Format-Table -AutoSize -Wrap
```

### Sample Output
```
Key                                     Identity          Rights   Type
---                                     --------          ------   ----
HKLM:\SYSTEM\CurrentControlSet\Services BUILTIN\Users     SetValue Allow
```

### Tips & Warnings
> ⚠️ If `BUILTIN\Users` or `Everyone` has `SetValue` or `FullControl` on service keys, any authenticated user can plant a service-based backdoor. Remediate immediately.

> 💡 Use `Set-Acl` with `RegistryAccessRule` to programmatically remove weak ACEs. Always back up the existing ACL with `Get-Acl | Export-Clixml` before modifying.

---

## 4. AppInit_DLLs Detection

### What you're looking for
`AppInit_DLLs` causes Windows to load a specified DLL into every process that loads `user32.dll` — nearly every GUI application. Attackers abuse this for system-wide DLL injection.

### Hunt Query

```powershell
@(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
) | ForEach-Object {
    $props = Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Key              = $_
        AppInit_DLLs     = $props.AppInit_DLLs
        LoadEnabled      = $props.LoadAppInit_DLLs
        RequireSigned    = $props.RequireSignedAppInit_DLLs
        Suspicious       = ($props.LoadAppInit_DLLs -eq 1 -and ![string]::IsNullOrWhiteSpace($props.AppInit_DLLs))
    }
} | Format-List
```

### Sample Output
```
Key              : HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
AppInit_DLLs     : C:\Windows\Temp\inject.dll
LoadEnabled      : 1
RequireSigned    : 0
Suspicious       : True
```

### Tips & Warnings
> ⚠️ If `LoadAppInit_DLLs` is **1** and `AppInit_DLLs` contains a path, every GUI application is loading that DLL. Isolate and analyze immediately.

> 💡 Hardening — set `LoadAppInit_DLLs` to **0** and `RequireSignedAppInit_DLLs` to **1**:
> ```powershell
> $p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
> Set-ItemProperty $p -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
> Set-ItemProperty $p -Name "RequireSignedAppInit_DLLs" -Value 1 -Type DWord -Force
> ```

---

## 5. Image File Execution Options (IFEO) Debugger Keys

### What you're looking for
IFEO allows a "debugger" to be attached to any process at launch. Attackers redirect execution so the debugger runs instead of the target — hijacking `sethc.exe` (Sticky Keys), `utilman.exe`, or security tools.

### Hunt Query

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" `
    -ErrorAction SilentlyContinue | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($dbg) {
        [PSCustomObject]@{
            Target     = $_.PSChildName
            Debugger   = $dbg
            Suspicious = $dbg -match 'cmd\.exe|powershell|wscript|mshta|rundll32'
        }
    }
} | Format-Table -AutoSize -Wrap
```

### Sample Output
```
Target        Debugger                     Suspicious
------        --------                     ----------
sethc.exe     C:\Windows\System32\cmd.exe  True
utilman.exe   C:\Windows\System32\cmd.exe  True
MsMpEng.exe   C:\Users\Public\kill.exe     True
```

### Tips & Warnings
> ⚠️ **Sticky Keys backdoor:** `sethc.exe → cmd.exe` gives an attacker a SYSTEM shell from the login screen (T1546.008).

> ⚠️ IFEO targeting `MsMpEng.exe` (Defender) is defense evasion — the AV never starts.

> 💡 Monitor IFEO changes with Sysmon Event ID 12/13 filtered to the IFEO path.

---

## 6. Winlogon Hijacking Detection

### What you're looking for
The Winlogon key controls logon behavior. Attackers modify `Shell`, `Userinit`, or `Notify` values to run malicious code at every logon.

### Hunt Query

```powershell
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$props = Get-ItemProperty $winlogon -ErrorAction SilentlyContinue
$expected = @{ Shell = "explorer.exe"; Userinit = "C:\Windows\system32\userinit.exe," }

@("Shell", "Userinit") | ForEach-Object {
    [PSCustomObject]@{
        Value = $_; Expected = $expected[$_]; Actual = $props.$_
        Suspicious = ($props.$_ -ne $expected[$_])
    }
} | Format-Table -AutoSize

# Notify subkeys should not exist on modern systems
if (Test-Path "$winlogon\Notify") {
    Write-Warning "Notify subkeys found — likely malicious on modern OS"
    Get-ChildItem "$winlogon\Notify"
}
```

### Sample Output
```
Value    Expected                           Actual                                         Suspicious
-----    --------                           ------                                         ----------
Shell    explorer.exe                       explorer.exe, C:\Users\Public\backdoor.exe     True
Userinit C:\Windows\system32\userinit.exe,  C:\Windows\system32\userinit.exe,              False
```

### Tips & Warnings
> ⚠️ `Shell` supports comma-separated entries — an attacker can **append** a malicious binary after `explorer.exe`. Both will launch.

> 💡 Also check `HKCU:\...\Winlogon` for per-user overrides not visible in system-wide scans.

---

## 7. LSA Protection Keys

### What you're looking for
LSA protection controls determine whether credential-stealing tools like Mimikatz can dump passwords from memory. Validating these keys confirms credential theft defenses are active.

### Hunt Query

```powershell
$props = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue

[PSCustomObject]@{
    RunAsPPL        = if ($props.RunAsPPL -eq 1) { "PROTECTED" } else { "VULNERABLE" }
    LmCompat        = if ($props.LmCompatibilityLevel -ge 5) { "NTLMv2 only (Best)" } else { "WEAK ($($props.LmCompatibilityLevel))" }
    NoLMHash        = if ($props.NoLMHash -eq 1) { "Good" } else { "VULNERABLE" }
    RestrictedAdmin = if ($props.DisableRestrictedAdmin -eq 0) { "Good" } else { "Disabled" }
} | Format-List

# Flag rogue authentication packages
$known = @('msv1_0','kerberos','wdigest','tspkg','pku2u','schannel','cloudAP')
$props.('Authentication Packages') | Where-Object { $_ -notin $known -and $_ -ne '' } |
    ForEach-Object { Write-Warning "UNKNOWN Auth Package: $_" }
```

### Sample Output
```
RunAsPPL        : PROTECTED
LmCompat        : NTLMv2 only (Best)
NoLMHash        : Good
RestrictedAdmin : Good

WARNING: UNKNOWN Auth Package: mimilib
```

### Tips & Warnings
> ⚠️ An **unknown authentication package** (like `mimilib`) is a critical IoC — Mimikatz installs itself as an SSP to capture plaintext credentials.

> ⚠️ `RunAsPPL` not set to 1 means LSASS is unprotected against memory-dumping tools.

> 💡 Harden: `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force`

---

## 8. Comprehensive Autorun Registry Scan (15+ Locations)

### What you're looking for
Beyond standard Run keys, Windows has numerous lesser-known autorun locations. Sweep them all.

### Hunt Query

```powershell
# 16 autorun locations — standard, policy, legacy, and boot-time persistence
$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",       "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",       "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
)

$autorunPaths | Where-Object { Test-Path $_ } | ForEach-Object {
    $path = $_
    Get-ItemProperty $path -EA SilentlyContinue | ForEach-Object { $_.PSObject.Properties } |
        Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            [PSCustomObject]@{
                Path = $path -replace 'HKLM:\\SOFTWARE\\', 'HKLM:\...\'
                Name = $_.Name
                Value = if ($_.Value -is [array]) { $_.Value -join "; " } else { $_.Value }
            }
        }
} | Format-Table -AutoSize -Wrap
```

### Sample Output
```
Path                                  Name           Value
----                                  ----           -----
HKLM:\...\CurrentVersion\Run         SecurityHealth %ProgramFiles%\Windows Defender\MSASCuiL.exe
HKLM:\...\Session Manager\BootExecute BootExecute   autocheck autochk *
HKLM:\...\Winlogon                   Shell          explorer.exe
```

### Tips & Warnings
> ⚠️ `BootExecute` runs before Windows fully loads. The legitimate value is `autocheck autochk *`. Anything else is highly suspicious.

> 💡 Export baseline results to CSV and diff periodically:
> ```powershell
> $results | Export-Csv ".\autorun_baseline_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
> ```

---

## 9. CLSID Hijacking

### What you're looking for
CLSID hijacking targets specific class identifiers. Attackers replace the `InprocServer32` or `LocalServer32` path so their DLL loads whenever that COM class is instantiated by Explorer, Office, or other trusted processes.

### Hunt Query

```powershell
$suspiciousPaths = 'temp|appdata|downloads|public|users\\[^\\]+\\desktop'

Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
    $inproc = (Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    $local  = (Get-ItemProperty "$($_.PSPath)\LocalServer32" -ErrorAction SilentlyContinue).'(default)'
    $server = if ($inproc) { $inproc } elseif ($local) { $local } else { $null }

    if ($server -and $server -match $suspiciousPaths) {
        [PSCustomObject]@{
            CLSID  = $_.PSChildName
            Server = $server
            Type   = if ($inproc) { "InprocServer32" } else { "LocalServer32" }
            Signed = (Get-AuthenticodeSignature $server -ErrorAction SilentlyContinue).Status -eq 'Valid'
        }
    }
} | Format-Table -AutoSize -Wrap
```

### Sample Output
```
CLSID                                  Server                              Type           Signed
-----                                  ------                              ----           ------
{a352cd1-4f9b-11d1-8e00-00c04fb611c7}  C:\Users\Public\legit_update.dll    InprocServer32 False
```

### Tips & Warnings
> ⚠️ An unsigned DLL in a system CLSID entry is a high-confidence IoC. Quarantine and analyze.

> 💡 Cross-reference with MITRE ATT&CK T1546.015 (COM Hijacking).

---

## 10. Disabling SMBv1/LLMNR/WPAD via Registry

### What you're looking for
Legacy protocols like SMBv1, LLMNR, and WPAD are actively exploited for relay attacks, poisoning, and remote code execution. Validate these are disabled.

### Detection & Hardening Script

```powershell
$smb1    = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -EA SilentlyContinue).SMB1
$llmnr   = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -EA SilentlyContinue).EnableMulticast
$wpad    = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -EA SilentlyContinue).Start
$netbios = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -EA SilentlyContinue).NodeType

[PSCustomObject]@{
    SMBv1   = if ($smb1 -eq 0) { "Disabled" } else { "ENABLED — VULNERABLE" }
    LLMNR   = if ($llmnr -eq 0) { "Disabled" } else { "ENABLED — POISONING RISK" }
    WPAD    = if ($wpad -eq 4) { "Disabled" } else { "ENABLED — VULNERABLE" }
    NetBIOS = if ($netbios -eq 2) { "Disabled" } else { "ENABLED — RELAY RISK" }
} | Format-List
```

### Hardening Commands

```powershell
# Disable SMBv1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force
# Disable LLMNR
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force
# Disable WPAD service
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 4 -Type DWord -Force
# Disable NetBIOS broadcast (P-node)
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Force
```

### Tips & Warnings
> ⚠️ **SMBv1 is the protocol exploited by WannaCry/EternalBlue.** Disable it everywhere — there is no legitimate modern use case.

> ⚠️ **LLMNR and NetBIOS** are abused by Responder/Inveigh to capture NTLMv2 hashes on the local network.

> 💡 After disabling, verify by running a Responder scan from a test machine to confirm no hosts answer LLMNR/NBT-NS queries.

---

## 11. Secure Channel Hardening

### What you're looking for
Schannel registry keys control TLS/SSL protocol versions. Weak configurations allow downgrade attacks (POODLE, BEAST). This audit validates legacy protocols are disabled.

### Detection Script

```powershell
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

foreach ($proto in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")) {
    foreach ($role in @("Client", "Server")) {
        $path     = "$base\$proto\$role"
        $enabled  = (Get-ItemProperty $path -ErrorAction SilentlyContinue).Enabled
        $disabled = (Get-ItemProperty $path -ErrorAction SilentlyContinue).DisabledByDefault
        $status   = if ($enabled -eq 0 -or $disabled -eq 1) { "Disabled" }
                    elseif ($enabled -eq 1) { "Enabled" } else { "OS Default" }
        $risk     = if ($proto -match "SSL|TLS 1\.[01]" -and $status -ne "Disabled") { "HIGH" } else { "OK" }
        [PSCustomObject]@{ Protocol = $proto; Role = $role; Status = $status; Risk = $risk }
    }
} | Format-Table -AutoSize
```

### Sample Output
```
Protocol Role   Status     Risk
-------- ----   ------     ----
SSL 3.0  Server OS Default HIGH
TLS 1.0  Server Disabled   OK
TLS 1.2  Server Enabled    OK
TLS 1.3  Server OS Default OK
```

### Hardening Script

```powershell
$base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# Disable legacy; enable modern
$config = @{ "SSL 2.0"=0; "SSL 3.0"=0; "TLS 1.0"=0; "TLS 1.1"=0; "TLS 1.2"=1; "TLS 1.3"=1 }
foreach ($proto in $config.Keys) {
    foreach ($role in @("Client","Server")) {
        $p = "$base\$proto\$role"; New-Item $p -Force | Out-Null
        Set-ItemProperty $p -Name "Enabled" -Value $config[$proto] -Type DWord -Force
        Set-ItemProperty $p -Name "DisabledByDefault" -Value ([int](!$config[$proto])) -Type DWord -Force
    }
}
```

### Tips & Warnings
> ⚠️ **SSL 2.0/3.0 and TLS 1.0/1.1** are cryptographically broken — disable all four. Test legacy app compatibility before deploying.

> 💡 Deploy fleet-wide via Group Policy: `Computer Configuration → Administrative Templates → Network → SSL Configuration Settings`

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [13 — Privileged Access Management](13-Privileged-Access-Management.md) | [README](../README.md) | [15 — PowerShell Security and Hardening](15-PowerShell-Security-and-Hardening.md) |
