# 13 — Privileged Access Management

> **Modules required:** `ActiveDirectory` (RSAT), `LAPS` (Windows LAPS module), `PSDesiredStateConfiguration`.  
> **Run as:** Domain Admin or delegated Tier-0 administrator. JEA configuration requires local admin on the endpoint. LAPS operations require the `LAPS Password Reader` or `LAPS Password Reset` permissions delegated in AD.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `New-PSSessionConfigurationFile` | Create a JEA session configuration file (.pssc) |
| `Register-PSSessionConfiguration` | Register a JEA endpoint on a target machine |
| `Get-LapsADPassword` | Retrieve the current LAPS-managed local admin password from AD |
| `Set-LapsADPasswordExpiry` | Modify the scheduled LAPS password rotation timestamp |
| `Reset-LapsPassword` | Force an immediate LAPS password rotation on a computer |
| `Get-ADGroupMember` | Audit privileged group membership for tiered admin enforcement |
| `Get-WinEvent` | Monitor for privileged group changes and escalation events (4672/4673/4674) |
| `Add-ADGroupMember` | Manage Protected Users group membership |
| `klist purge` | Clear cached Kerberos credentials on an endpoint |

---

## 1. JEA — `New-PSSessionConfigurationFile`

### What it does
Creates a PowerShell Session Configuration file (`.pssc`) that defines the constraints for a Just Enough Administration (JEA) endpoint. This file controls which modules are loaded, the session type, the execution policy, and which Role Capability files map to connecting users or groups. Think of it as the blueprint for a locked-down remote admin session.

### Full Syntax
```powershell
New-PSSessionConfigurationFile
    [-Path] <String>
    [-SessionType <SessionType>]
    [-TranscriptDirectory <String>]
    [-RunAsVirtualAccount]
    [-RunAsVirtualAccountGroups <String[]>]
    [-RoleDefinitions <IDictionary>]
    [-LanguageMode <PSLanguageMode>]
    [-ExecutionPolicy <ExecutionPolicy>]
    [-ModulesToImport <Object[]>]
    [-VisibleCmdlets <Object[]>]
    [-VisibleFunctions <Object[]>]
    [-VisibleProviders <String[]>]
    [-MountUserDrive]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Path` | String | Output path for the `.pssc` file (must end in `.pssc`) |
| `-SessionType` | Enum | `RestrictedRemoteServer` (JEA), `Default`, or `Empty` |
| `-TranscriptDirectory` | String | Folder for automatic session transcripts — critical for audit trails |
| `-RunAsVirtualAccount` | Switch | Runs the session under a temporary local admin virtual account |
| `-RoleDefinitions` | IDictionary | Maps AD groups or users to Role Capability (`.psrc`) file names |
| `-LanguageMode` | Enum | `NoLanguage` (most restrictive), `ConstrainedLanguage`, `FullLanguage` |
| `-ModulesToImport` | Object[] | Modules available inside the JEA session |
| `-VisibleCmdlets` | Object[] | Explicit list of cmdlets the connected user can run |

### Real-World Example
**Scenario:** You need to allow your help-desk team to restart services and check event logs on servers — but nothing else. You create a JEA session config that maps the `HelpDesk-Operators` AD group to a role capability file.

```powershell
New-PSSessionConfigurationFile -Path "C:\JEA\HelpDesk.pssc" `
    -SessionType RestrictedRemoteServer `
    -TranscriptDirectory "C:\JEA\Transcripts" `
    -RunAsVirtualAccount `
    -RoleDefinitions @{
        'CORP\HelpDesk-Operators' = @{ RoleCapabilities = 'HelpDeskRole' }
    } `
    -LanguageMode NoLanguage `
    -ModulesToImport @('Microsoft.PowerShell.Management') `
    -ExecutionPolicy RemoteSigned
```

### Sample Output
```
(No output on success — the file C:\JEA\HelpDesk.pssc is created)
```

### Tips & Warnings
> ⚠️ **Always set `-TranscriptDirectory`.** Without transcripts you have no audit trail of what operators executed inside the JEA session. Compliance frameworks (SOC 2, PCI-DSS) require this.

> ⚠️ **Use `NoLanguage` mode** for JEA endpoints. `FullLanguage` allows arbitrary script execution, defeating the purpose of JEA entirely.

> 💡 **Tip:** Test your `.pssc` file before deploying:
> ```powershell
> Test-PSSessionConfigurationFile -Path "C:\JEA\HelpDesk.pssc"
> ```

---

## 2. JEA — `Register-PSSessionConfiguration` and Role Capabilities

### What it does
Registers a JEA endpoint on a machine so that remote users can connect to it via `Enter-PSSession` or `Invoke-Command`. Before registering, you also need a Role Capability file (`.psrc`) that defines exactly which commands the session exposes. Together, these two pieces form a complete JEA deployment.

### Full Syntax
```powershell
# Create the Role Capability file
New-PSRoleCapabilityFile
    [-Path] <String>
    [-VisibleCmdlets <Object[]>]
    [-VisibleFunctions <Object[]>]
    [-VisibleExternalCommands <String[]>]
    [-FunctionDefinitions <IDictionary[]>]

# Register the endpoint
Register-PSSessionConfiguration
    [-Name] <String>
    [-Path <String>]
    [-Force]
    [-NoServiceRestart]
    [-AccessMode <PSSessionConfigurationAccessMode>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Path` (Role) | String | Output path for the `.psrc` file inside a `RoleCapabilities` subfolder |
| `-VisibleCmdlets` | Object[] | Cmdlets the role can execute; supports wildcard parameter restrictions |
| `-VisibleFunctions` | Object[] | Custom or module functions exposed to the role |
| `-VisibleExternalCommands` | String[] | Full paths to external executables the role may call |
| `-Name` (Register) | String | The endpoint name users connect to (e.g., `JEA_HelpDesk`) |
| `-Path` (Register) | String | Path to the `.pssc` session configuration file |
| `-Force` | Switch | Overwrites an existing endpoint registration |

### Real-World Example
**Scenario:** Following on from the session config above, you create the role capability and register the JEA endpoint on a file server.

```powershell
# Step 1 — Create the RoleCapabilities folder inside a module
$modulePath = "C:\Program Files\WindowsPowerShell\Modules\HelpDeskJEA"
New-Item -Path "$modulePath\RoleCapabilities" -ItemType Directory -Force

# Step 2 — Create the Role Capability file
New-PSRoleCapabilityFile -Path "$modulePath\RoleCapabilities\HelpDeskRole.psrc" `
    -VisibleCmdlets @(
        'Restart-Service',
        'Get-Service',
        'Get-EventLog',
        @{ Name = 'Stop-Service'; Parameters = @{ Name = 'Name'; ValidateSet = 'Spooler','W3SVC' } }
    ) `
    -VisibleExternalCommands @('C:\Windows\System32\ipconfig.exe')

# Step 3 — Register the JEA endpoint
Register-PSSessionConfiguration -Name "JEA_HelpDesk" `
    -Path "C:\JEA\HelpDesk.pssc" `
    -Force

# Step 4 — Test connectivity
Enter-PSSession -ComputerName localhost -ConfigurationName JEA_HelpDesk
```

### Sample Output
```
WARNING: Register-PSSessionConfiguration may need to restart the WinRM service.
WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Plugin

Name          Type     Keys
----          ----     ----
JEA_HelpDesk  Plugin   {Name=JEA_HelpDesk}
```

### Tips & Warnings
> ⚠️ **Role Capability files must live in a `RoleCapabilities` folder** inside a PowerShell module directory. If the folder structure is wrong, JEA silently fails to load the role.

> ⚠️ **Restrict `Stop-Service` with `ValidateSet`** — an unrestricted `Stop-Service` allows operators to halt critical services like `WinRM` or `DNS`.

> 💡 **Tip:** Audit active JEA endpoints on a machine:
> ```powershell
> Get-PSSessionConfiguration | Where-Object { $_.SessionType -eq 'RestrictedRemoteServer' } |
>     Select-Object Name, Permission, RunAsVirtualAccount
> ```

---

## 3. LAPS — `Get-LapsADPassword`

### What it does
Retrieves the current Windows LAPS-managed local administrator password for a computer object from Active Directory. This is the primary way authorized admins securely access unique local admin passwords that LAPS rotates automatically.

### Full Syntax
```powershell
Get-LapsADPassword
    [-Identity] <String[]>
    [-AsPlainText]
    [-Credential <PSCredential>]
    [-DomainController <String>]
    [-IncludeHistory]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String[] | Computer name(s) or Distinguished Name(s) to retrieve passwords for |
| `-AsPlainText` | Switch | Returns the password in clear text instead of a `SecureString` |
| `-Credential` | PSCredential | Alternate credentials with LAPS read permissions |
| `-DomainController` | String | Target a specific DC for the query |
| `-IncludeHistory` | Switch | Returns previously rotated passwords (if history is enabled) |

### Real-World Example
**Scenario:** A server named `FILE-SVR01` is unresponsive to domain authentication. You need the local admin password to log in directly and troubleshoot.

```powershell
Get-LapsADPassword -Identity "FILE-SVR01" -AsPlainText
```

### Sample Output
```
ComputerName       : FILE-SVR01
DistinguishedName  : CN=FILE-SVR01,OU=Servers,DC=corp,DC=local
Account            : Administrator
Password           : x7$kQ!9mPz@2wL4n
PasswordUpdateTime : 3/15/2026 2:00:00 AM
ExpirationTime     : 4/14/2026 2:00:00 AM
Source             : CleartextPassword
```

### Tips & Warnings
> ⚠️ **`-AsPlainText` displays the password on screen.** Only use this in secure, audited sessions. In scripts, omit this flag and work with the `SecureString` object instead.

> ⚠️ **LAPS read permissions are sensitive.** Ensure only authorized groups (e.g., `LAPS-Password-Readers`) are granted the `Read ms-Mcs-AdmPwd` or `Read msLAPS-Password` extended right on the relevant OUs.

> 💡 **Tip:** Bulk-retrieve passwords for an entire OU for a break-glass binder:
> ```powershell
> Get-ADComputer -SearchBase "OU=Servers,DC=corp,DC=local" -Filter * |
>     ForEach-Object { Get-LapsADPassword -Identity $_.Name -AsPlainText } |
>     Select-Object ComputerName, Account, Password, ExpirationTime |
>     Export-Csv -Path "C:\secure\laps_passwords.csv" -NoTypeInformation
> ```

---

## 4. LAPS — `Set-LapsADPasswordExpiry`

### What it does
Modifies the password expiration timestamp for a LAPS-managed computer account in Active Directory. This lets you schedule an early rotation (e.g., after an incident) or extend the current password's lifetime during a maintenance window.

### Full Syntax
```powershell
Set-LapsADPasswordExpiry
    [-Identity] <String[]>
    [-NewExpirationTime <DateTime>]
    [-Credential <PSCredential>]
    [-DomainController <String>]
    [-WhatIf]
    [-Confirm]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String[] | Computer name(s) or Distinguished Name(s) |
| `-NewExpirationTime` | DateTime | The new expiration timestamp; set to a past time to force rotation at next GP refresh |
| `-Credential` | PSCredential | Alternate credentials with LAPS password-reset permissions |
| `-DomainController` | String | Target a specific DC |
| `-WhatIf` | Switch | Preview the change without applying it |

### Real-World Example
**Scenario:** A contractor who had access to `WEB-SVR03`'s local admin password has been terminated. You need to force a password rotation before the next scheduled change.

```powershell
# Set expiration to now — LAPS will rotate the password at the next GP refresh
Set-LapsADPasswordExpiry -Identity "WEB-SVR03" -NewExpirationTime (Get-Date)

# Verify the new expiry
Get-LapsADPassword -Identity "WEB-SVR03" -AsPlainText |
    Select-Object ComputerName, ExpirationTime
```

### Sample Output
```
ComputerName    ExpirationTime
------------    --------------
WEB-SVR03       3/29/2026 4:32:15 PM
```

### Tips & Warnings
> ⚠️ **Setting expiry to a past date does not rotate the password instantly.** The client must process Group Policy first. Run `gpupdate /force` on the target machine or wait for the next GP cycle.

> 💡 **Tip:** Expire LAPS passwords across an entire OU after a breach:
> ```powershell
> Get-ADComputer -SearchBase "OU=Workstations,DC=corp,DC=local" -Filter * |
>     ForEach-Object { Set-LapsADPasswordExpiry -Identity $_.Name -NewExpirationTime (Get-Date) }
> ```

---

## 5. LAPS — `Reset-LapsPassword`

### What it does
Triggers an immediate local admin password rotation on the target computer. Unlike `Set-LapsADPasswordExpiry` (which sets a future timestamp), this command contacts the machine and forces a password change right now.

### Full Syntax
```powershell
Reset-LapsPassword
    [-Identity] <String[]>
    [-Credential <PSCredential>]
    [-DomainController <String>]
    [-WhatIf]
    [-Confirm]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String[] | Computer name(s) to force a password reset on |
| `-Credential` | PSCredential | Alternate credentials if needed |
| `-DomainController` | String | Target DC for the AD password update |
| `-WhatIf` | Switch | Preview without executing |

### Real-World Example
**Scenario:** During incident response, you suspect the local admin password for `DC-BACKUP01` has been compromised. You need an immediate rotation — not a scheduled one.

```powershell
# Force immediate rotation
Reset-LapsPassword -Identity "DC-BACKUP01"

# Confirm the new password and updated timestamp
Get-LapsADPassword -Identity "DC-BACKUP01" -AsPlainText |
    Select-Object ComputerName, Password, PasswordUpdateTime
```

### Sample Output
```
ComputerName       Password            PasswordUpdateTime
------------       --------            ------------------
DC-BACKUP01        Tn!4pR@8yWq$6kZm    3/29/2026 4:45:22 PM
```

### Tips & Warnings
> ⚠️ **The target computer must be online and reachable.** If the machine is powered off or network-isolated, this command fails. Use `Set-LapsADPasswordExpiry` instead so rotation occurs when the machine comes back.

> 💡 **Tip:** Combine with incident response to rotate passwords on all machines in a compromised OU:
> ```powershell
> Get-ADComputer -SearchBase "OU=DMZ,DC=corp,DC=local" -Filter * |
>     ForEach-Object {
>         try {
>             Reset-LapsPassword -Identity $_.Name
>             Write-Host "[OK] Rotated: $($_.Name)" -ForegroundColor Green
>         } catch {
>             Write-Host "[FAIL] Offline: $($_.Name)" -ForegroundColor Red
>         }
>     }
> ```

---

## 6. Tiered Admin Enforcement Auditing

### What it does
In a tiered administration model (Tier 0 = Domain Controllers, Tier 1 = Servers, Tier 2 = Workstations), privileged accounts should only authenticate to their designated tier. This audit detects Tier-0 accounts logging into Tier-1 or Tier-2 machines — a violation that exposes credentials to theft.

### Real-World Example
**Scenario:** Your security team mandates that Domain Admin accounts must never log into workstations. You need a weekly report of any violations.

```powershell
# Define Tier-0 accounts
$tier0Accounts = (Get-ADGroupMember -Identity "Domain Admins" -Recursive).SamAccountName

# Define Tier-2 machines (workstations OU)
$workstations = (Get-ADComputer -SearchBase "OU=Workstations,DC=corp,DC=local" -Filter *).Name

# Query logon events (Event ID 4624) on workstations for Tier-0 accounts
$violations = foreach ($ws in $workstations) {
    try {
        Get-WinEvent -ComputerName $ws -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = (Get-Date).AddDays(-7)
        } -ErrorAction SilentlyContinue |
        Where-Object {
            $xml = [xml]$_.ToXml()
            $user = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } |
                Select-Object -ExpandProperty '#text'
            $user -in $tier0Accounts
        } | Select-Object @{n='Workstation';e={$ws}},
            @{n='Account';e={$user}},
            TimeCreated, Id
    } catch { }
}

$violations | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
```

### Sample Output
```
Workstation   Account        TimeCreated              Id
-----------   -------        -----------              --
WKS-PC042     adminjsmith    3/27/2026 9:15:32 AM     4624
WKS-PC018     svc_tier0mgmt  3/25/2026 11:02:47 PM    4624
```

### Tips & Warnings
> ⚠️ **Any result here is a policy violation.** Tier-0 credentials on a workstation can be harvested with Mimikatz within seconds. Investigate every occurrence immediately.

> 💡 **Tip:** Enforce tiering with Authentication Policy Silos (Windows Server 2012 R2+) to block logons at the protocol level rather than relying solely on detection:
> ```powershell
> New-ADAuthenticationPolicySilo -Name "Tier0-Silo" `
>     -UserAllowedToAuthenticateTo "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"Tier0-Silo`"))" `
>     -Enforce $true
> ```

---

## 7. Privileged Group Change Monitoring

### What it does
Monitors Active Directory security event logs for changes to high-value groups — Domain Admins, Enterprise Admins, Schema Admins, and Administrators. Event ID 4728 (member added to global group), 4729 (member removed), and 4756 (member added to universal group) are the key indicators.

### Real-World Example
**Scenario:** You need a daily alert of any additions to privileged groups across all domain controllers.

```powershell
$privilegedGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators'
)

$domainControllers = (Get-ADDomainController -Filter *).HostName

$changes = foreach ($dc in $domainControllers) {
    Get-WinEvent -ComputerName $dc -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4728, 4729, 4732, 4733, 4756, 4757
        StartTime = (Get-Date).AddDays(-1)
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        $targetGroup = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        if ($targetGroup -in $privilegedGroups) {
            [PSCustomObject]@{
                TimeCreated  = $_.TimeCreated
                DomainController = $dc
                EventId      = $_.Id
                GroupName    = $targetGroup
                MemberAdded  = ($data | Where-Object { $_.Name -eq 'MemberName' }).'#text'
                ChangedBy    = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            }
        }
    }
}

$changes | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
```

### Sample Output
```
TimeCreated              DomainController   EventId  GroupName        MemberAdded                           ChangedBy
-----------              ----------------   -------  ---------        -----------                           ---------
3/29/2026 3:45:10 PM     DC01.corp.local    4728     Domain Admins    CN=TempAdmin,OU=Users,DC=corp,DC=local  adminjsmith
3/28/2026 11:20:05 AM    DC02.corp.local    4756     Enterprise Admins CN=SVC-Test,OU=SAs,DC=corp,DC=local    svc_deploy
```

### Tips & Warnings
> ⚠️ **A service account adding itself to Enterprise Admins is a critical indicator of compromise.** Correlate with logon events and investigate the source machine immediately.

> ⚠️ **Enable "Audit Security Group Management"** in Advanced Audit Policy or these events will not be generated:
> ```
> Computer Configuration → Policies → Windows Settings → Security Settings →
>   Advanced Audit Policy → Account Management → Audit Security Group Management → Success, Failure
> ```

> 💡 **Tip:** Pipe results to `Send-MailMessage` or a webhook for real-time alerting:
> ```powershell
> if ($changes) {
>     $body = $changes | ConvertTo-Html -Fragment | Out-String
>     Send-MailMessage -To "soc@corp.local" -From "alerts@corp.local" `
>         -Subject "ALERT: Privileged Group Change Detected" `
>         -Body $body -BodyAsHtml -SmtpServer "smtp.corp.local"
> }
> ```

---

## 8. Detecting Privilege Escalation Events (4672 / 4673 / 4674)

### What it does
Windows logs specific Security events when privileged operations occur. Event **4672** fires when an account logs on with special privileges (e.g., SeDebugPrivilege). Event **4673** fires when a privileged service is called. Event **4674** fires when an operation is attempted on a privileged object. Hunting these events reveals accounts exercising elevated rights — either legitimately or as part of an attack.

### Real-World Example
**Scenario:** You want to detect any non-standard account that received `SeDebugPrivilege` in the last 24 hours — a hallmark of credential-dumping tools.

```powershell
$knownAdmins = @('Administrator', 'adminjsmith', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')

$escalationEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4672
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $account = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $privileges = ($data | Where-Object { $_.Name -eq 'PrivilegeList' }).'#text'

    if ($account -notin $knownAdmins -and $privileges -match 'SeDebugPrivilege') {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account     = $account
            Domain      = ($data | Where-Object { $_.Name -eq 'SubjectDomainName' }).'#text'
            Privileges  = $privileges.Trim()
            LogonId     = ($data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
        }
    }
}

$escalationEvents | Format-Table -AutoSize
```

### Sample Output
```
TimeCreated              Account      Domain  Privileges                              LogonId
-----------              -------      ------  ----------                              -------
3/29/2026 2:14:55 PM     tempuser     CORP    SeDebugPrivilege SeImpersonatePrivilege  0x3E7A9F
3/29/2026 1:02:33 PM     svc_deploy   CORP    SeDebugPrivilege                         0x4B12C8
```

### Tips & Warnings
> ⚠️ **`SeDebugPrivilege` on a non-admin account is almost always malicious.** This privilege allows reading the memory of any process, including LSASS — the first step in credential dumping.

> ⚠️ **Event 4672 is high-volume on domain controllers.** Filter aggressively by excluding known service accounts and SYSTEM to reduce noise.

> 💡 **Tip:** Extend the hunt to Event 4673/4674 for privileged service and object access:
> ```powershell
> Get-WinEvent -FilterHashtable @{
>     LogName   = 'Security'
>     Id        = 4673, 4674
>     StartTime = (Get-Date).AddHours(-24)
> } | Where-Object {
>     $_.Message -match 'SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege'
> } | Select-Object TimeCreated, Id, Message | Format-List
> ```

---

## 9. Managing the Protected Users Group

### What it does
The **Protected Users** security group (Windows Server 2012 R2+) enforces hardened security for its members: no NTLM authentication, no DES or RC4 in Kerberos, no credential delegation, no caching of credentials, and TGTs limited to 4 hours. Adding all Tier-0 admin accounts to this group is a critical defense against credential theft.

### Real-World Example
**Scenario:** Your security team mandates that all Domain Admin accounts must be in the `Protected Users` group. You need to audit compliance and add missing accounts.

```powershell
# Step 1 — Get current Protected Users members
$protected = (Get-ADGroupMember -Identity "Protected Users").SamAccountName

# Step 2 — Get all Domain Admin accounts
$domainAdmins = (Get-ADGroupMember -Identity "Domain Admins" -Recursive).SamAccountName

# Step 3 — Find accounts NOT in Protected Users
$missing = $domainAdmins | Where-Object { $_ -notin $protected }

# Step 4 — Report
if ($missing) {
    Write-Host "`n[WARNING] The following Domain Admins are NOT in Protected Users:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }

    # Step 5 — Add missing accounts (with confirmation)
    $missing | ForEach-Object {
        Add-ADGroupMember -Identity "Protected Users" -Members $_ -Confirm
        Write-Host "[ADDED] $_ → Protected Users" -ForegroundColor Green
    }
} else {
    Write-Host "[OK] All Domain Admins are in the Protected Users group." -ForegroundColor Green
}
```

### Sample Output
```
[WARNING] The following Domain Admins are NOT in Protected Users:
  - adminbthompson
  - svc_backup

[ADDED] adminbthompson → Protected Users
[ADDED] svc_backup → Protected Users
```

### Tips & Warnings
> ⚠️ **Do NOT add service accounts to Protected Users** unless they support Kerberos AES and do not rely on delegation. NTLM-dependent services will break immediately. In the example above, `svc_backup` should be validated first.

> ⚠️ **Protected Users does not protect accounts logging into Windows Server 2008 R2 or earlier DCs.** The protections are enforced by the DC, so all DCs must be 2012 R2+ for full coverage.

> 💡 **Tip:** Schedule a weekly compliance check as a scheduled task:
> ```powershell
> $missing = (Get-ADGroupMember "Domain Admins" -Recursive).SamAccountName |
>     Where-Object { $_ -notin (Get-ADGroupMember "Protected Users").SamAccountName }
> if ($missing) {
>     Send-MailMessage -To "security@corp.local" -From "audit@corp.local" `
>         -Subject "Protected Users Compliance Gap" `
>         -Body ("Accounts missing: " + ($missing -join ', ')) `
>         -SmtpServer "smtp.corp.local"
> }
> ```

---

## 10. Clearing Cached Credentials

### What it does
When administrators log into machines, Windows caches Kerberos tickets and (optionally) password hashes for offline logon. These cached credentials are a primary target for attackers using tools like Mimikatz. Clearing them after privileged sessions limits the exposure window.

### Real-World Example
**Scenario:** After performing emergency maintenance on a workstation using a Tier-0 account, you need to purge all cached Kerberos tickets from the session before disconnecting.

```powershell
# Purge all Kerberos tickets for the current session
klist purge

# Verify no tickets remain
klist

# Also clear cached credentials from Credential Manager
cmdkey /list | Select-String "Target:" | ForEach-Object {
    $target = ($_ -split ":\s+")[1].Trim()
    cmdkey /delete:$target
    Write-Host "Deleted cached credential: $target"
}
```

### Sample Output
```
Current LogonId is 0:0x3e7

        Deleting all tickets:
        Ticket(s) purged!

Current LogonId is 0:0x3e7
Cached Tickets: (0)

Deleted cached credential: Domain:target=TERMSRV/DC01
Deleted cached credential: Domain:target=TERMSRV/FILE-SVR01
```

### Tips & Warnings
> ⚠️ **`klist purge` only clears tickets for the current logon session.** If an attacker has injected tickets into another session (e.g., via Pass-the-Ticket), those tickets persist. Use `klist -li 0x3e7 purge` to target the SYSTEM session or reboot the machine.

> ⚠️ **Cached domain logon credentials** (used for offline logon) are controlled by the `CachedLogonsCount` registry value. Reduce this on servers to `0` and on workstations to `1`:
> ```powershell
> Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
>     -Name "CachedLogonsCount" -Value "1"
> ```

> 💡 **Tip:** In a full incident response, force a credential purge remotely on compromised machines:
> ```powershell
> $computers = @('WKS-PC042', 'WKS-PC018')
> Invoke-Command -ComputerName $computers -ScriptBlock {
>     klist purge
>     # Invalidate cached logon tokens by rotating the machine account password
>     Reset-ComputerMachinePassword
>     Write-Host "$env:COMPUTERNAME — credentials purged, machine password rotated"
> }
> ```

---

## 🔍 Additional Useful Commands

```powershell
# List all JEA endpoints on the local machine
Get-PSSessionConfiguration | Where-Object { $_.Permission -match 'NT AUTHORITY' } |
    Select-Object Name, RunAsUser, Permission

# Unregister a JEA endpoint
Unregister-PSSessionConfiguration -Name "JEA_HelpDesk" -Force

# Verify LAPS is deployed — check for the LAPS client-side extension
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime |
    Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -eq $null } |
    Select-Object Name, DistinguishedName

# Find accounts with AdminCount=1 (have been or are in admin groups)
Get-ADUser -Filter "AdminCount -eq 1" -Properties AdminCount, MemberOf |
    Select-Object Name, SamAccountName,
        @{n='Groups';e={ ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join '; ' }}

# Detect Kerberos ticket-granting ticket (TGT) anomalies — tickets older than policy
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4768 } -MaxEvents 100 |
    Select-Object TimeCreated, @{n='Account';e={
        ([xml]$_.ToXml()).Event.EventData.Data |
        Where-Object { $_.Name -eq 'TargetUserName' } |
        Select-Object -ExpandProperty '#text'
    }}
```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [12 — Active Directory Attack Detection](12-Active-Directory-Attack-Detection.md) | [README](../README.md) | [14 — Windows Registry Security](14-Windows-Registry-Security.md) |
