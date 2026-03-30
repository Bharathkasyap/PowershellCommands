# 23 — Credential Security and LAPS

> **Modules required:** `LAPS` (Windows LAPS), `ActiveDirectory` (RSAT)  
> **Run as:** LAPS password readers need delegated rights; credential auditing requires local admin or Domain Admin.

---

## ⚡ Quick Reference

| Command / Technique | Purpose |
|---------------------|---------|
| `Get-LapsADPassword` | Retrieve the LAPS-managed local admin password |
| `Set-LapsADPasswordExpirationTime` | Force early LAPS password rotation |
| `Reset-LapsPassword` | Immediately rotate the LAPS password |
| Windows Credential Manager via `cmdkey` | Manage stored credentials |
| Credential Exposure Detection | Find passwords in scripts, files, and memory |
| Credential Guard Status | Verify VBS credential isolation |
| Windows Hello for Business | Manage passwordless authentication |
| LSASS Access Detection (Events 4656/10) | Detect credential dumping attempts |
| SAM Database Access Audit | Monitor local account database access |
| DCSync Detection (Event 4662) | Detect replication-based credential theft |
| NTDS.dit Access Detection | Detect AD database theft |
| Mimikatz Artifact Detection | Find evidence of credential tools in logs |

---

## 1. `Get-LapsADPassword`

### What it does
Retrieves the LAPS-managed local administrator password for a computer. Windows LAPS (2023+) stores passwords encrypted in Active Directory and rotates them automatically.

### Full Syntax
```powershell
Get-LapsADPassword
    -Identity <String>
    [-AsPlainText]
    [-Credential <PSCredential>]
    [-DomainController <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Identity` | Computer name to retrieve the password for |
| `-AsPlainText` | Display the password in plaintext (otherwise returns encrypted blob) |
| `-IncludeHistory` | Include previous passwords |

### Real-World Example
**Scenario:** You need the local admin password to investigate a compromised workstation.

```powershell
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText
```

### Sample Output
```
ComputerName    : WORKSTATION01
Password        : x7#mK9!pL2qR
PasswordUpdateTime : 3/28/2026 12:00:00 AM
ExpirationTimestamp : 4/27/2026 12:00:00 AM
Source          : EncryptedPassword
DecryptionStatus : Success
```

### Tips & Warnings
> ⚠️ LAPS password access should be tightly controlled. Audit who reads passwords via Event 4662 on the computer object.

> 💡 View password history for forensics: `Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText -IncludeHistory`

---

## 2. `Set-LapsADPasswordExpirationTime`

### What it does
Sets the LAPS password expiration time for a computer, forcing an early rotation on the next Group Policy refresh.

### Real-World Example
**Scenario:** After an incident, force all affected workstations to rotate their local admin passwords immediately.

```powershell
# Force immediate rotation
Set-LapsADPasswordExpirationTime -Identity "WORKSTATION01" -WhenEffective (Get-Date)

# Bulk rotation for all machines in an OU
Get-ADComputer -SearchBase "OU=Incident,DC=corp,DC=local" -Filter * |
    ForEach-Object {
        Set-LapsADPasswordExpirationTime -Identity $_.Name -WhenEffective (Get-Date)
        Write-Host "Queued rotation: $($_.Name)"
    }
```

### Tips & Warnings
> 💡 The password doesn't rotate instantly — it happens at the next GP refresh. Force it with: `Invoke-GPUpdate -Computer "WORKSTATION01" -Force`

---

## 3. `Reset-LapsPassword`

### What it does
Immediately triggers a LAPS password rotation on the local machine (must run on the target computer).

### Real-World Example
```powershell
# Run on the target machine
Reset-LapsPassword

# Verify the new password from a DC
Get-LapsADPassword -Identity $env:COMPUTERNAME -AsPlainText
```

### Tips & Warnings
> ⚠️ After a password reset, any cached credentials for the old local admin password are invalidated.

---

## 4. Windows Credential Manager — `cmdkey`

### What it does
Manages stored credentials in Windows Credential Manager. Attackers often find cached credentials here.

### Audit Script
```powershell
# List all stored credentials
& cmdkey /list

# PowerShell alternative — enumerate credential vault
$vault = [Windows.Security.Credentials.PasswordVault]::new()
$creds = $vault.RetrieveAll()
$creds | ForEach-Object {
    [PSCustomObject]@{
        Resource = $_.Resource
        UserName = $_.UserName
    }
} | Format-Table -AutoSize

# Remove a specific stored credential
# & cmdkey /delete:targetname
```

### Sample Output
```
Currently stored credentials:
    Target: Domain:target=fileserver.corp.local
    Type: Domain Password
    User: CORP\jsmith

    Target: MicrosoftAccount:user=admin@contoso.com
    Type: Generic
    User: admin@contoso.com
```

### Tips & Warnings
> ⚠️ Stored domain credentials are prime targets for credential theft. Audit and minimize stored credentials.

---

## 5. Credential Exposure Detection

### What it does
Searches for credentials exposed in scripts, configuration files, and other plaintext locations.

### Detection Script
```powershell
# Search for passwords in PowerShell scripts
$searchPaths = @("C:\Scripts", "C:\Users", "C:\Scheduled", "$env:ProgramData")
$patterns = @('password\s*=', 'pwd\s*=', 'ConvertTo-SecureString.*-AsPlainText', 'credential', 'secret\s*=', 'apikey\s*=')

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path -Recurse -Include "*.ps1","*.psm1","*.bat","*.cmd","*.xml","*.config","*.json","*.txt","*.ini" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $file = $_
                $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
                foreach ($pattern in $patterns) {
                    $matches = $content | Select-String -Pattern $pattern
                    foreach ($match in $matches) {
                        [PSCustomObject]@{
                            File    = $file.FullName
                            Line    = $match.LineNumber
                            Content = $match.Line.Trim().Substring(0, [Math]::Min(80, $match.Line.Trim().Length))
                        }
                    }
                }
            }
    }
}
```

### Tips & Warnings
> ⚠️ Any `ConvertTo-SecureString -AsPlainText` in production scripts means passwords are stored in plaintext.

> 💡 Use Azure Key Vault, CyberArk, or Windows Credential Store instead of hardcoded passwords.

---

## 6. Credential Guard Status

### What it does
Verifies whether Windows Credential Guard (VBS-based credential isolation) is active. Credential Guard prevents credential dumping from LSASS.

### Check Script
```powershell
# Check Credential Guard status
$devGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

[PSCustomObject]@{
    VBSEnabled              = $devGuard.VirtualizationBasedSecurityStatus -eq 2
    CredentialGuardRunning  = 1 -in $devGuard.SecurityServicesRunning
    SecureBoot              = $devGuard.RequiredSecurityProperties -contains 2
    Status                  = if (1 -in $devGuard.SecurityServicesRunning) { "PROTECTED" } else { "NOT PROTECTED" }
} | Format-List
```

### Sample Output
```
VBSEnabled             : True
CredentialGuardRunning : True
SecureBoot             : True
Status                 : PROTECTED
```

### Tips & Warnings
> ⚠️ If Credential Guard is NOT running on workstations, LSASS can be dumped with tools like Mimikatz.

> 💡 Enable via GPO: `Computer Configuration → Admin Templates → System → Device Guard → Enable Virtualization Based Security`

---

## 7. LSASS Access Detection — Events 4656 / Sysmon 10

### What it does
Detects processes attempting to open handles to LSASS (Local Security Authority Subsystem Service) — the primary target for credential dumping.

### Detection Script
```powershell
# Sysmon Event 10 — Process Access to LSASS
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 10
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 500 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $target = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetImage').'#text'
        if ($target -match 'lsass\.exe') {
            [PSCustomObject]@{
                Time       = $_.TimeCreated
                Source     = ($xml.Event.EventData.Data | Where-Object Name -eq 'SourceImage').'#text'
                SourcePID  = ($xml.Event.EventData.Data | Where-Object Name -eq 'SourceProcessId').'#text'
                Access     = ($xml.Event.EventData.Data | Where-Object Name -eq 'GrantedAccess').'#text'
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Sample Output
```
Time                     Source                                       SourcePID  Access
----                     ------                                       ---------  ------
3/29/2026 3:14:22 PM     C:\Users\jsmith\Desktop\procdump.exe        5678       0x1FFFFF
3/29/2026 3:14:25 PM     C:\Temp\mimikatz.exe                        9012       0x1010
```

### Tips & Warnings
> ⚠️ Access mask `0x1FFFFF` (PROCESS_ALL_ACCESS) to LSASS is a critical alert — immediate investigation required.

> 💡 Legitimate LSASS access comes from `csrss.exe`, `services.exe`, and `WerFault.exe`. Anything else is suspicious.

---

## 8. SAM Database Access Audit

### What it does
Monitors access to the SAM (Security Account Manager) database and registry hive, which stores local account password hashes.

### Detection Script
```powershell
# Check for SAM hive access attempts
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4656
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 1000 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $objectName = ($xml.Event.EventData.Data | Where-Object Name -eq 'ObjectName').'#text'
        if ($objectName -match 'SAM|SECURITY|SYSTEM') {
            [PSCustomObject]@{
                Time     = $_.TimeCreated
                User     = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
                Object   = $objectName
                Process  = ($xml.Event.EventData.Data | Where-Object Name -eq 'ProcessName').'#text'
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Tips & Warnings
> ⚠️ `reg save HKLM\SAM` or `reg save HKLM\SYSTEM` from command line = credential theft in progress.

---

## 9. DCSync Detection — Event 4662

### What it does
Detects DCSync attacks where an attacker replicates password hashes from Active Directory by impersonating a domain controller.

### Detection Script
```powershell
# DCSync uses DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
# These map to GUIDs:
# 1131f6aa-... = DS-Replication-Get-Changes
# 1131f6ad-... = DS-Replication-Get-Changes-All

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4662
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 5000 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $properties = ($xml.Event.EventData.Data | Where-Object Name -eq 'Properties').'#text'
        if ($properties -match '1131f6ad|1131f6aa') {
            $user = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
            # Filter out actual DCs
            if ($user -notmatch '\$$') {  # DCs end with $
                [PSCustomObject]@{
                    Time   = $_.TimeCreated
                    User   = $user
                    Rights = if ($properties -match '1131f6ad') { "Get-Changes-All (FULL)" } else { "Get-Changes" }
                    Alert  = "POTENTIAL DCSYNC"
                }
            }
        }
    } | Format-Table -AutoSize
```

### Tips & Warnings
> ⚠️ Non-DC accounts performing replication = **DCSync attack confirmed**. Disable the account immediately.

---

## 10. NTDS.dit Access Detection

### What it does
Detects attempts to access or copy the NTDS.dit file, which contains all Active Directory password hashes.

### Detection Script
```powershell
# Check for Volume Shadow Copy creation (common NTDS.dit theft method)
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'VSS'
    StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Where-Object { $_.Message -match 'shadow copy' } |
    Format-Table -AutoSize -Wrap

# Check for ntdsutil usage
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 10000 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $cmdLine = ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
        if ($cmdLine -match 'ntdsutil|ifm|"create full"') {
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                User    = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
                Command = $cmdLine
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Tips & Warnings
> ⚠️ `ntdsutil "activate instance ntds" "ifm" "create full"` = attacker extracting the entire AD database.

---

## 11. Virtual Accounts and gMSA Management

### What it does
Managed Service Accounts (gMSA) eliminate password management for service accounts by having AD automatically rotate 240-character passwords.

### Management Script
```powershell
# Create a gMSA
New-ADServiceAccount -Name "gMSA_SQL" `
    -DNSHostName "gmsa_sql.corp.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "SQLServers" `
    -KerberosEncryptionType AES256

# Install on target server
Install-ADServiceAccount -Identity "gMSA_SQL"

# Test the gMSA
Test-ADServiceAccount -Identity "gMSA_SQL"

# Audit all gMSAs
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, Created |
    Select-Object Name, Enabled, Created,
        @{n='AllowedHosts';e={$_.PrincipalsAllowedToRetrieveManagedPassword -join '; '}} |
    Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Migrate all service accounts to gMSAs where possible — they eliminate the #1 Kerberoasting target.

---

## 12. Mimikatz Artifact Detection in Logs

### What it does
Searches event logs for evidence of Mimikatz or similar credential dumping tools being used.

### Detection Script
```powershell
# Search Script Block Logging for Mimikatz patterns (Event 4104)
$mimikatzPatterns = @(
    'sekurlsa', 'kerberos::list', 'lsadump', 'dpapi::',
    'token::elevate', 'privilege::debug', 'mimikatz',
    'Invoke-Mimikatz', 'DumpCreds', 'DumpCerts'
)

$patternRegex = ($mimikatzPatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
    StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 5000 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $patternRegex } |
    Select-Object TimeCreated,
        @{n='Pattern';e={
            foreach ($p in $mimikatzPatterns) { if ($_.Message -match $p) { $p; break } }
        }},
        @{n='ScriptBlock';e={$_.Message.Substring(0, [Math]::Min(100, $_.Message.Length))}} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
TimeCreated              Pattern          ScriptBlock
-----------              -------          -----------
3/28/2026 3:14:22 PM     Invoke-Mimikatz  Invoke-Mimikatz -DumpCreds -ComputerName DC01...
3/28/2026 3:15:00 PM     sekurlsa         sekurlsa::logonpasswords...
```

### Tips & Warnings
> ⚠️ **Any Mimikatz pattern in logs is a confirmed compromise.** Immediately isolate the host and reset all credentials accessed.

> 💡 Script Block Logging must be enabled to catch these — see [15 — PowerShell Security and Hardening](15-PowerShell-Security-and-Hardening.md).

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [22 — Network Forensics and Monitoring](22-Network-Forensics-and-Monitoring.md) | [README](../README.md) | [24 — SOC Automation and Playbooks](24-SOC-Automation-and-Playbooks.md) |
