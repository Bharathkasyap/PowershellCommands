# 07 — Endpoint Security

> **Modules required:** `Defender` (built-in), `BitLocker` (built-in on supported SKUs), `AppLocker` (Enterprise/Education), `NetSecurity`  
> **Run as:** Local Administrator for most commands.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-MpComputerStatus` | Check Windows Defender AV status and signature versions |
| `Update-MpSignature` | Force Windows Defender signature update |
| `Get-MpThreat` | List threats detected by Defender |
| `Get-AppLockerPolicy` | View AppLocker rules (application allow-listing) |
| `manage-bde` | Manage BitLocker Drive Encryption |
| `Get-NetFirewallProfile` | Check firewall profile (Domain/Private/Public) status |
| `Get-WindowsDriver` | List installed drivers |

---

## 1. `Get-MpComputerStatus`

### What it does
Returns the current status of Windows Defender Antivirus — whether it is enabled and up to date, the last time it scanned, the signature version and age, and whether real-time protection is active. A quick health check for the most fundamental endpoint security control.

### Full Syntax
```powershell
Get-MpComputerStatus
    [-CimSession <CimSession[]>]
    [-AsJob]
```

### Real-World Example
**Scenario:** You want to verify that all workstations have Defender enabled, real-time protection on, and recent signatures — especially before a scheduled penetration test.

```powershell
# Local check
Get-MpComputerStatus | Select-Object `
    AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, `
    RealTimeProtectionEnabled, `
    AntivirusSignatureLastUpdated, `
    AntivirusSignatureVersion, `
    @{n='SignatureAgeDays'; e={((Get-Date) - $_.AntivirusSignatureLastUpdated).Days}}, `
    LastFullScanEndTime, QuickScanEndTime

# Check across multiple machines
$computers = "PC01","PC02","SERVER01"
$computers | ForEach-Object {
    $comp = $_
    try {
        $status = Invoke-Command -ComputerName $comp -ScriptBlock { Get-MpComputerStatus }
        [PSCustomObject]@{
            Computer            = $comp
            AVEnabled           = $status.AntivirusEnabled
            RealTimeProtection  = $status.RealTimeProtectionEnabled
            SignatureAge        = [int]((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalDays
            LastScan            = $status.LastFullScanEndTime
        }
    } catch {
        [PSCustomObject]@{ Computer = $comp; AVEnabled = "ERROR"; RealTimeProtection = "ERROR" }
    }
} | Format-Table -AutoSize
```

### Sample Output
```
Computer  AVEnabled  RealTimeProtection  SignatureAge  LastScan
--------  ---------  ------------------  ------------  --------
PC01      True       True                0             3/28/2026 9:00 PM
PC02      True       False               4             3/25/2026 1:00 AM
SERVER01  True       True                1             3/27/2026 11:00 PM
```

### Tips & Warnings
> ⚠️ **PC02 has Real-Time Protection disabled** — this is a critical finding. Real-time protection is the primary control that stops malware from executing. Investigate why it's disabled (user override? policy? tamper?).

> ⚠️ **Signatures more than 3 days old** leave the endpoint exposed to recent threats. Signatures should update daily.

> 💡 Check if Defender has been tampered with (exclusions added by malware):
> ```powershell
> Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess
> ```

---

## 2. `Update-MpSignature`

### What it does
Forces Windows Defender to download and install the latest antivirus and antispyware signature updates immediately, without waiting for the scheduled update cycle.

### Full Syntax
```powershell
Update-MpSignature
    [-UpdateSource <UpdateSource>]
    [-CimSession <CimSession[]>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-UpdateSource` | `MicrosoftUpdateServer` (default), `MMPC`, `InternalDefinitionUpdateServer` (WSUS), `FileShares` |

### Real-World Example
**Scenario:** A major threat campaign was announced today. Before your next scheduled update, push an immediate signature update to all endpoints.

```powershell
# Update local machine
Update-MpSignature
Write-Host "Signatures updated: $(((Get-MpComputerStatus).AntivirusSignatureLastUpdated))"

# Update all domain workstations remotely
$computers = Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=corp,DC=local" |
    Select-Object -ExpandProperty Name

Invoke-Command -ComputerName $computers -ScriptBlock {
    Update-MpSignature
    $v = (Get-MpComputerStatus).AntivirusSignatureVersion
    Write-Host "$env:COMPUTERNAME updated to signature: $v"
} -ThrottleLimit 20
```

### Tips & Warnings
> 💡 Use `-UpdateSource InternalDefinitionUpdateServer` in air-gapped or WSUS-managed environments to update from your internal server rather than the internet.

---

## 3. `Get-MpThreat`

### What it does
Retrieves the history of threats detected by Windows Defender. Shows the threat name, severity, detection date, and remediation status. Important for post-incident review and compliance reporting.

### Full Syntax
```powershell
Get-MpThreat
    [-ThreatID <Int64[]>]
    [-CimSession <CimSession[]>]

# Active (not yet remediated) threats:
Get-MpThreatDetection
```

### Real-World Example
**Scenario:** After an alert, review what Defender has found on a machine.

```powershell
# Get all detected threats
Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive, 
    @{n='Severity'; e={
        switch ($_.SeverityID) {
            1 { 'Low' } 2 { 'Moderate' } 4 { 'High' } 5 { 'Severe' } default { 'Unknown' }
        }
    }},
    Resources | Format-Table -AutoSize

# Get active (not remediated) threats — urgent
Get-MpThreatDetection | Where-Object { $_.ThreatStatusID -ne 1 } |
    Select-Object ThreatName, DomainUser, ProcessName, Resources, InitialDetectionTime |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
ThreatName                            SeverityID  IsActive  Severity  Resources
----------                            ----------  --------  --------  ---------
Trojan:Win32/Meterpreter.A            5           False     Severe    file:C:\Users\Public\shell.exe
HackTool:Win32/Mimikatz!gen1          5           True      Severe    file:C:\Temp\mimi.exe; process:4832
```

### Tips & Warnings
> ⚠️ **Active Mimikatz detection** — credential dumping tool. This is a critical security incident. Isolate the machine immediately and begin IR procedures.

> 💡 Start a manual quick scan:
> ```powershell
> Start-MpScan -ScanType QuickScan
> # Or a full scan (takes much longer):
> Start-MpScan -ScanType FullScan
> ```

---

## 4. `Get-AppLockerPolicy`

### What it does
Retrieves the current AppLocker policy — rules that control which applications, scripts, and installers are allowed or denied from running. AppLocker is an application allow-listing control that prevents unauthorized software (including malware) from executing.

### Full Syntax
```powershell
Get-AppLockerPolicy
    -Local
    -Effective
    -Domain
    [-Xml]
    [-LDAP <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Local` | Get the locally configured AppLocker policy |
| `-Effective` | Get the effective (merged local + domain) policy |
| `-Domain` | Get the domain-applied AppLocker policy |
| `-Xml` | Return the policy as XML for export or comparison |

### Real-World Example
**Scenario:** Verify that AppLocker is configured with rules to block execution from user-writable directories.

```powershell
# View all effective rules
Get-AppLockerPolicy -Effective | Select-Xml -XPath "//FilePathRule" |
    Select-Object -ExpandProperty Node |
    Select-Object Name, Description, Action,
        @{n='Path'; e={$_.Conditions.FilePathCondition.Path}} |
    Format-Table -AutoSize -Wrap

# Check if AppLocker service is running (required for enforcement)
Get-Service -Name AppIDSvc | Select-Object Name, Status, StartType
```

### Sample Output
```
Name                    Action  Path
----                    ------  ----
Allow Windows           Allow   %WINDIR%\*
Allow Program Files     Allow   %PROGRAMFILES%\*
Block AppData scripts   Deny    %APPDATA%\*.exe
Default Deny            Deny    *

Name       Status   StartType
----       ------   ---------
AppIDSvc   Running  Automatic
```

### Tips & Warnings
> ⚠️ If `AppIDSvc` is **not running**, AppLocker rules are **not enforced** even if they're configured.

> 💡 Test what AppLocker would do with a specific file:
> ```powershell
> Get-AppLockerFileInformation -Path "C:\Users\Public\test.exe" |
>     Test-AppLockerPolicy -User Everyone
> ```

---

## 5. `manage-bde` — BitLocker Drive Encryption

### What it does
`manage-bde.exe` is the command-line tool for managing BitLocker — full disk encryption for Windows. BitLocker protects data on lost or stolen drives by requiring a PIN or recovery key to boot. It's a critical control for laptop/endpoint compliance.

> **PowerShell module alternative:** Use `Get-BitLockerVolume`, `Enable-BitLocker`, `Suspend-BitLocker`, `Resume-BitLocker` from the `BitLocker` module.

### Real-World Example
**Scenario:** Check the BitLocker status of all drives and ensure the OS drive is encrypted.

```powershell
# Using PowerShell BitLocker module (preferred)
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus,
    EncryptionPercentage, VolumeType, KeyProtector |
    Format-Table -AutoSize

# Using manage-bde (classic)
manage-bde -status C:
```

### Sample Output
```
MountPoint  VolumeStatus        ProtectionStatus  EncryptionPercentage  VolumeType
----------  ------------        ----------------  --------------------  ----------
C:          FullyEncrypted      On                100                   OperatingSystem
D:          FullyDecrypted      Off               0                     Data
```

### Tips & Warnings
> ⚠️ **Drive D: is not encrypted** — if this is a data drive containing sensitive information, it must be encrypted. Enable BitLocker:
> ```powershell
> Enable-BitLocker -MountPoint "D:" -EncryptionMethod Aes256 `
>     -RecoveryPasswordProtector
> ```

> ⚠️ **Always back up the recovery key to AD or Azure AD** before encrypting:
> ```powershell
> # Back up recovery key to AD
> $BLV = Get-BitLockerVolume -MountPoint "C:"
> BackupToAAD-BitLockerKeyProtector -MountPoint "C:" `
>     -KeyProtectorId ($BLV.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}).KeyProtectorId
> ```

> 💡 Suspend BitLocker temporarily during firmware updates (prevents lockout):
> ```powershell
> Suspend-BitLocker -MountPoint "C:" -RebootCount 1
> ```

---

## 6. `Get-NetFirewallProfile`

### What it does
Returns the configuration of the three Windows Firewall network profiles — **Domain** (connected to the corporate domain), **Private** (home/trusted networks), and **Public** (untrusted networks). You can see whether the firewall is enabled and what the default inbound/outbound behavior is for each profile.

### Full Syntax
```powershell
Get-NetFirewallProfile
    [[-Name] <String[]>]
    [-PolicyStore <String>]
```

### Real-World Example
**Scenario:** Compliance check — verify the firewall is enabled on all profiles, especially Public (for laptops on untrusted networks).

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, 
    DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName |
    Format-Table -AutoSize
```

### Sample Output
```
Name     Enabled  DefaultInboundAction  DefaultOutboundAction  LogAllowed  LogBlocked
----     -------  --------------------  ---------------------  ----------  ----------
Domain   True     Block                 Allow                  False       True
Private  True     Block                 Allow                  False       True
Public   True     Block                 Allow                  False       True
```

### Tips & Warnings
> ⚠️ If any profile shows `Enabled: False`, the firewall is disabled for that network type — a serious security gap.

> 💡 Enable all firewall profiles if they're disabled:
> ```powershell
> Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
> ```

> 💡 Enable firewall logging (useful for forensics and SIEM feeding):
> ```powershell
> Set-NetFirewallProfile -Profile Domain,Private,Public `
>     -LogAllowed True `
>     -LogBlocked True `
>     -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" `
>     -LogMaxSizeKilobytes 32767
> ```

---

## 7. `Get-WindowsDriver`

### What it does
Lists all drivers installed on the system — kernel-mode drivers that run at the highest privilege level. Malicious drivers (rootkits) are the most dangerous form of malware because they run below the OS and can hide from user-space tools. Also useful for identifying outdated or vulnerable drivers.

### Full Syntax
```powershell
Get-WindowsDriver
    -Online
    [-Driver <String[]>]
    [-LogPath <String>]
```

### Real-World Example
**Scenario:** After an intrusion, check whether any unsigned or recently installed kernel drivers are present — a sign of a rootkit.

```powershell
# List all drivers
Get-WindowsDriver -Online | Select-Object Driver, OriginalFileName, 
    ProviderName, Date, Version |
    Sort-Object Date -Descending |
    Format-Table -AutoSize

# Find unsigned drivers (critical security risk)
Get-WindowsDriver -Online |
    Where-Object { -not $_.BootCritical } |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature -FilePath $_.OriginalFileName -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid') {
            [PSCustomObject]@{
                Driver    = $_.Driver
                Path      = $_.OriginalFileName
                SignStatus = $sig.Status
                Date      = $_.Date
            }
        }
    } | Format-Table -AutoSize
```

### Sample Output
```
Driver           Path                           SignStatus  Date
------           ----                           ----------  ----
oem45.inf        C:\Windows\System32\Dr\mal.sys  NotSigned   3/29/2026
```

### Tips & Warnings
> ⚠️ **Unsigned drivers** (`NotSigned`) are a serious finding. Windows Kernel Patch Protection (PatchGuard) on 64-bit systems requires signed drivers, but attackers can bypass this with BYOVD (Bring Your Own Vulnerable Driver) attacks.

> 💡 Check if Windows Driver Signature Enforcement is enabled:
> ```powershell
> bcdedit /enum | Select-String "nointegritychecks|testsigning"
> # If either is "Yes", driver signing is disabled — investigate immediately
> ```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [06 — Vulnerability Management](06-Vulnerability-Management.md) | [README](../README.md) | [08 — Cloud Security: Azure](08-Cloud-Security-Azure.md) |
