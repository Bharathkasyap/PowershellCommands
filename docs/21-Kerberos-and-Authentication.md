# 21 — Kerberos and Authentication

> **Module required:** `ActiveDirectory` (RSAT)  
> **Run as:** Domain Admin or Security Administrator for most queries; some detection scripts need local admin.

---

## ⚡ Quick Reference

| Command / Technique | Purpose |
|---------------------|---------|
| `klist` via PowerShell | Display cached Kerberos tickets |
| `Test-ComputerSecureChannel` | Verify the machine's trust with the domain |
| `Get-ADServiceAccount` / `Set-ADServiceAccount` | Manage SPNs and service accounts |
| Kerberos Delegation Types | Audit unconstrained, constrained, and RBCD delegation |
| Kerberoastable Account Detection | Find accounts with SPNs vulnerable to offline cracking |
| NTLM Audit (Event 4776) | Detect NTLM authentication usage |
| Restrict NTLM via Registry | Harden environment by blocking NTLM |
| NTLMv1 Detection | Find legacy NTLMv1 usage |
| Smart Card Management | Manage smart card logon requirements |
| `Get-ADTrust` | Audit domain and forest trusts |
| Authentication Policy Silos | Enforce tiered authentication isolation |
| Protected Users Group | Harden accounts against credential theft |
| Pass-the-Ticket Detection | Detect stolen Kerberos ticket reuse |

---

## 1. `klist` — Viewing Cached Kerberos Tickets

### What it does
Displays the Kerberos tickets cached on the local machine. During incident response, this shows which services the user has authenticated to and whether any tickets have unusual lifetimes or encryption types.

### Full Syntax
```powershell
# View current user tickets
& klist

# View tickets for a specific logon session
& klist -li 0x3e7    # SYSTEM session

# Purge all cached tickets
& klist purge
```

### Real-World Example
**Scenario:** During an investigation, check if a user has suspicious Kerberos tickets (e.g., tickets with unusually long lifetimes that may indicate a Golden Ticket).

```powershell
$tickets = & klist
$tickets | ForEach-Object { Write-Output $_ }

# Check for TGTs with abnormally long lifetimes (Golden Ticket indicator)
# Normal TGT lifetime is 10 hours; Golden Tickets often have 10+ years
```

### Sample Output
```
Current LogonId is 0:0x1a2b3c

Cached Tickets: (3)

#0>  Client: jsmith @ CORP.LOCAL
     Server: krbtgt/CORP.LOCAL @ CORP.LOCAL
     KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
     Start Time: 3/29/2026 8:00:00 (local)
     End Time:   3/29/2026 18:00:00 (local)
     Renew Time: 4/5/2026 8:00:00 (local)

#1>  Client: jsmith @ CORP.LOCAL
     Server: cifs/fileserver.corp.local @ CORP.LOCAL
     KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
     Start Time: 3/29/2026 8:05:00 (local)
     End Time:   3/29/2026 18:00:00 (local)
```

### Tips & Warnings
> ⚠️ A TGT with `RC4-HMAC` encryption when AES is available indicates a possible forged ticket or downgrade attack.

> 💡 Purge tickets during incident response to force re-authentication: `& klist purge`

---

## 2. `Test-ComputerSecureChannel`

### What it does
Tests and optionally repairs the trust relationship between the local computer and its Active Directory domain. A broken secure channel prevents the machine from authenticating to domain resources.

### Full Syntax
```powershell
Test-ComputerSecureChannel
    [-Server <String>]
    [-Repair]
    [-Credential <PSCredential>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Server` | Target a specific domain controller |
| `-Repair` | Attempt to reset the machine account password and restore the trust |
| `-Credential` | Admin credentials for the repair operation |

### Real-World Example
**Scenario:** A workstation keeps showing "trust relationship failed" errors. Verify and repair.

```powershell
# Test the secure channel
if (Test-ComputerSecureChannel) {
    Write-Host "Secure channel is healthy" -ForegroundColor Green
} else {
    Write-Host "Secure channel BROKEN — attempting repair..." -ForegroundColor Red
    Test-ComputerSecureChannel -Repair -Credential (Get-Credential)
}
```

### Sample Output
```
True
```

### Tips & Warnings
> 💡 If `-Repair` fails, you may need to reset the computer account in AD and rejoin the domain.

> ⚠️ Multiple machines with broken secure channels simultaneously could indicate an attacker resetting machine passwords.

---

## 3. SPN Management — `Get-ADServiceAccount` / `Set-ADServiceAccount`

### What it does
Manages Service Principal Names (SPNs) which tie services to accounts. Mismanaged SPNs create Kerberoasting attack surfaces.

### Real-World Example
**Scenario:** Audit all SPNs in the domain to find Kerberoastable accounts.

```powershell
# Find all user accounts with SPNs (Kerberoastable)
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName, PasswordLastSet, Enabled |
    Select-Object SamAccountName, Enabled,
        @{n='SPNs';e={$_.ServicePrincipalName -join '; '}},
        PasswordLastSet |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
SamAccountName  Enabled  SPNs                                      PasswordLastSet
--------------  -------  ----                                      ---------------
svc_sql         True     MSSQLSvc/sqlserver.corp.local:1433        1/15/2024 9:00 AM
svc_http        True     HTTP/webserver.corp.local                 3/10/2025 2:00 PM
krbtgt          True     kadmin/changepw                           3/29/2026 12:00 AM
```

### Tips & Warnings
> ⚠️ User accounts with SPNs and old passwords are prime Kerberoasting targets. Rotate passwords and use gMSAs.

> 💡 List SPNs with `setspn -L <accountname>` or use:
> ```powershell
> Get-ADUser -Identity svc_sql -Properties ServicePrincipalName | Select-Object -ExpandProperty ServicePrincipalName
> ```

---

## 4. Kerberos Delegation Audit

### What it does
Identifies accounts configured for Kerberos delegation — unconstrained delegation is particularly dangerous as it allows impersonation to any service.

### Detection Script
```powershell
# Unconstrained delegation (most dangerous)
Write-Host "=== Unconstrained Delegation ===" -ForegroundColor Red
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object Name, DNSHostName, TrustedForDelegation

Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object SamAccountName, TrustedForDelegation

# Constrained delegation
Write-Host "`n=== Constrained Delegation ===" -ForegroundColor Yellow
Get-ADObject -Filter { msDS-AllowedToDelegateTo -like '*' } -Properties msDS-AllowedToDelegateTo |
    Select-Object Name, ObjectClass, @{n='DelegateTo';e={$_.'msDS-AllowedToDelegateTo' -join '; '}}

# Resource-Based Constrained Delegation (RBCD)
Write-Host "`n=== Resource-Based Constrained Delegation ===" -ForegroundColor Yellow
Get-ADComputer -Filter { PrincipalsAllowedToDelegateToAccount -ne "$null" } -Properties PrincipalsAllowedToDelegateToAccount |
    Select-Object Name, @{n='AllowedFrom';e={$_.PrincipalsAllowedToDelegateToAccount}}
```

### Sample Output
```
=== Unconstrained Delegation ===
Name        DNSHostName                TrustedForDelegation
----        -----------                --------------------
DC01        dc01.corp.local            True
FILESERVER  fileserver.corp.local      True

=== Constrained Delegation ===
Name       ObjectClass  DelegateTo
----       -----------  ----------
svc_web    user         HTTP/intranet.corp.local
```

### Tips & Warnings
> ⚠️ **Only domain controllers should have unconstrained delegation.** Any other machine with it is a high-risk finding.

> 💡 Migrate from unconstrained to constrained or RBCD wherever possible.

---

## 5. NTLM Audit — Event 4776

### What it does
Detects NTLM authentication usage in your environment. In a Zero Trust model, NTLM should be minimized in favor of Kerberos.

### Detection Script
```powershell
# Find NTLM authentication events (Event 4776)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4776
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 100 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            User      = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
            Source    = ($xml.Event.EventData.Data | Where-Object Name -eq 'Workstation').'#text'
            Status    = ($xml.Event.EventData.Data | Where-Object Name -eq 'Status').'#text'
        }
    } | Format-Table -AutoSize
```

### Sample Output
```
Time                     User            Source         Status
----                     ----            ------         ------
3/29/2026 8:15:00 AM     jsmith          WORKSTATION1   0x0
3/29/2026 8:20:00 AM     legacy_app      LEGACYSVR      0x0
3/29/2026 9:00:00 AM     attacker        UNKNOWN        0xC000006A
```

### Tips & Warnings
> ⚠️ Status `0xC000006A` = bad password. Repeated failures from unknown sources indicate credential stuffing.

> 💡 Enable NTLM auditing before blocking: `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 5`

---

## 6. Restricting NTLM via Registry

### What it does
Hardens the environment by progressively restricting NTLM authentication in favor of Kerberos.

### Hardening Script
```powershell
# Audit NTLM first (don't block yet)
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 1

# After audit period — deny all NTLM (use with caution)
# Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -Value 2

# Force NTLMv2 only (minimum hardening)
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 5

# Verify current settings
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object LMCompatibilityLevel
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" |
    Select-Object AuditReceivingNTLMTraffic, RestrictSendingNTLMTraffic, RestrictReceivingNTLMTraffic
```

### Tips & Warnings
> ⚠️ **Always audit before blocking.** Many legacy applications rely on NTLM — blocking prematurely will cause outages.

> 💡 `LMCompatibilityLevel = 5` means "Send NTLMv2 response only. Refuse LM & NTLM."

---

## 7. NTLMv1 Detection

### What it does
Finds systems still using the insecure NTLMv1 protocol, which can be cracked almost instantly.

### Detection Script
```powershell
# Check event logs for NTLMv1 usage (Event 4624 with LmPackageName showing LM or NTLMv1)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
    StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 5000 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $lmPackage = ($xml.Event.EventData.Data | Where-Object Name -eq 'LmPackageName').'#text'
        if ($lmPackage -match 'LM|NTLMv1') {
            [PSCustomObject]@{
                Time       = $_.TimeCreated
                User       = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
                Source     = ($xml.Event.EventData.Data | Where-Object Name -eq 'WorkstationName').'#text'
                LmPackage  = $lmPackage
            }
        }
    } | Format-Table -AutoSize
```

### Tips & Warnings
> ⚠️ **Any NTLMv1 usage is a critical security finding.** The protocol is trivially crackable.

---

## 8. Smart Card Management

### What it does
Enforces smart card logon requirements for privileged accounts — a key Zero Trust control.

### Configuration Script
```powershell
# Require smart card logon for a user
Set-ADUser -Identity "admin_jsmith" -SmartcardLogonRequired $true

# Find all accounts requiring smart card
Get-ADUser -Filter { SmartcardLogonRequired -eq $true } -Properties SmartcardLogonRequired |
    Select-Object SamAccountName, SmartcardLogonRequired, Enabled |
    Format-Table -AutoSize

# Find privileged accounts NOT requiring smart card
$privGroups = @("Domain Admins","Enterprise Admins","Schema Admins")
foreach ($group in $privGroups) {
    Get-ADGroupMember -Identity $group -Recursive | ForEach-Object {
        Get-ADUser $_.SamAccountName -Properties SmartcardLogonRequired |
            Where-Object { $_.SmartcardLogonRequired -ne $true } |
            Select-Object @{n='Group';e={$group}}, SamAccountName, SmartcardLogonRequired
    }
} | Format-Table -AutoSize
```

### Sample Output
```
Group           SamAccountName  SmartcardLogonRequired
-----           --------------  ----------------------
Domain Admins   admin_backup    False
Domain Admins   svc_sql         False
```

### Tips & Warnings
> ⚠️ Service accounts cannot use smart cards — use gMSAs instead for those.

---

## 9. `Get-ADTrust` — Domain Trust Auditing

### What it does
Lists all domain and forest trusts, revealing potential attack paths through trust relationships.

### Full Syntax
```powershell
Get-ADTrust -Filter *
```

### Real-World Example
**Scenario:** Audit all trusts for security review — look for insecure trust types and SID filtering status.

```powershell
Get-ADTrust -Filter * -Properties * |
    Select-Object Name, Direction, TrustType, ForestTransitive,
        SIDFilteringForestAware, SIDFilteringQuarantined,
        @{n='TrustAttributes';e={$_.TrustAttributes}} |
    Format-Table -AutoSize
```

### Sample Output
```
Name             Direction     TrustType  ForestTransitive  SIDFilteringQuarantined
----             ---------     ---------  ----------------  -----------------------
partner.com      Bidirectional External   False             True
child.corp.local Bidirectional TreeRoot   True              False
```

### Tips & Warnings
> ⚠️ `SIDFilteringQuarantined: False` on external trusts means SID History injection attacks are possible.

> 💡 Enable SID filtering: `netdom trust DOMAIN /domain:PARTNER /quarantine:Yes`

---

## 10. Authentication Policy Silos

### What it does
Authentication Policy Silos restrict where privileged accounts can authenticate — a cornerstone of the tiered admin model that prevents credential exposure.

### Configuration Script
```powershell
# Create an authentication policy
New-ADAuthenticationPolicy -Name "Tier0-Policy" `
    -UserTGTLifetimeMins 240 `
    -Enforce

# Create an authentication policy silo
New-ADAuthenticationPolicySilo -Name "Tier0-Silo" `
    -UserAuthenticationPolicy "Tier0-Policy" `
    -ComputerAuthenticationPolicy "Tier0-Policy" `
    -Enforce

# Assign accounts to the silo
Set-ADUser -Identity "admin_jsmith" -AuthenticationPolicySilo "Tier0-Silo"

# Audit silo assignments
Get-ADUser -Filter { AuthenticationPolicySilo -ne "$null" } -Properties AuthenticationPolicySilo |
    Select-Object SamAccountName, AuthenticationPolicySilo |
    Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Start with audit mode (`-Enforce:$false`) before enforcing — silos can lock out admins if misconfigured.

> ⚠️ Requires Windows Server 2012 R2+ domain functional level.

---

## 11. Protected Users Group

### What it does
Members of the Protected Users group get hardened credential protections: no NTLM authentication, no delegation, no caching, and shorter TGT lifetimes. Essential for all Tier 0 admin accounts.

### Management Script
```powershell
# View current Protected Users members
Get-ADGroupMember -Identity "Protected Users" |
    Select-Object Name, SamAccountName, objectClass |
    Format-Table -AutoSize

# Add a privileged account
Add-ADGroupMember -Identity "Protected Users" -Members "admin_jsmith"

# Find Tier 0 admins NOT in Protected Users
$protectedUsers = (Get-ADGroupMember -Identity "Protected Users").SamAccountName
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object { $protectedUsers -notcontains $_.SamAccountName } |
    Select-Object Name, SamAccountName |
    Format-Table -AutoSize
```

### Sample Output
```
Name            SamAccountName
----            --------------
SVC-SQL         svc_sql
Admin Backup    admin_backup
```

### Tips & Warnings
> ⚠️ **Do NOT add service accounts to Protected Users** — it breaks NTLM and delegation, which services typically need.

> 💡 Protected Users effects: no NTLM, no DES/RC4, no delegation, no credential caching, TGT lifetime = 4 hours.

---

## 12. Pass-the-Ticket Detection

### What it does
Detects pass-the-ticket attacks where an attacker uses a stolen Kerberos ticket to authenticate without knowing the password.

### Detection Script
```powershell
# Look for TGS requests where the client IP doesn't match the ticket's expected IP
# Event 4769 = Kerberos Service Ticket Operations
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4769
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 5000 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time       = $_.TimeCreated
            User       = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
            Service    = ($xml.Event.EventData.Data | Where-Object Name -eq 'ServiceName').'#text'
            ClientIP   = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
            Encryption = ($xml.Event.EventData.Data | Where-Object Name -eq 'TicketEncryptionType').'#text'
            Status     = ($xml.Event.EventData.Data | Where-Object Name -eq 'Status').'#text'
        }
    } |
    # Flag: RC4 encryption (0x17) when AES should be used
    Where-Object { $_.Encryption -eq '0x17' } |
    Format-Table -AutoSize
```

### Tips & Warnings
> ⚠️ RC4 encryption (0x17) in TGS requests is a strong indicator of Kerberoasting or forged tickets.

> 💡 Correlate ticket requests with known IP-to-machine mappings to detect ticket reuse from unexpected sources.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [20 — Forensics and Memory Analysis](20-Forensics-and-Memory-Analysis.md) | [README](../README.md) | [22 — Network Forensics and Monitoring](22-Network-Forensics-and-Monitoring.md) |
