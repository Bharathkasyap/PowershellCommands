# 12 — Active Directory Attack Detection

> **Philosophy:** Active Directory is the crown jewel of every Windows environment — and the primary target of every sophisticated attacker. These hunts assume the adversary already has a foothold and is exploiting AD to escalate privileges, move laterally, or establish persistence.  
> **Modules required:** `ActiveDirectory`, `GroupPolicy`. Many queries also rely on Security event logs with **Advanced Audit Policy** enabled (especially Object Access, DS Access, and Logon/Logoff categories).  
> **Run as:** Domain Administrator or equivalent with read access to AD and domain controller event logs.

---

## ⚡ Quick Reference

| Hunt | What You're Looking For |
|------|------------------------|
| [Kerberoasting](#1-detecting-kerberoasting-spn-accounts) | Harvesting service account TGS tickets for offline cracking |
| [AS-REP Roasting](#2-as-rep-roasting-detection) | Accounts vulnerable to pre-auth bypass ticket harvesting |
| [DCSync](#3-dcsync-via-event-logs) | Replication privilege abuse to extract password hashes |
| [Pass-the-Hash](#4-pass-the-hash-indicators) | NTLM hash reuse for lateral movement |
| [Golden Ticket](#5-golden-ticket-detection-event-4769) | Forged Kerberos TGTs granting domain-wide access |
| [AdminSDHolder Abuse](#6-adminsdholder-abuse) | Backdooring protected group permissions |
| [SID History Injection](#7-sid-history-injection) | Privilege escalation via fabricated SID history |
| [Unconstrained Delegation](#8-unconstrained-delegation-accounts) | Accounts that cache any connecting user's TGT |
| [LDAP Recon](#9-ldap-recon-detection-event-1644) | Expensive LDAP queries typical of enumeration tools |
| [ACL Abuse Paths](#10-acl-abuse-paths-genericallwritedacl) | Dangerous permissions enabling privilege escalation |
| [BloodHound Enumeration](#11-bloodhound-style-enumeration-patterns) | High-volume LDAP/SAMR queries from a single source |

---

## 1. Detecting Kerberoasting (SPN Accounts)

### What you're looking for
Kerberoasting targets service accounts with a Service Principal Name (SPN) set. Any domain user can request a TGS ticket for these accounts, then crack the ticket offline. Red flags include a single user requesting many TGS tickets with RC4 encryption (`0x17`) in a short window, and service accounts with old passwords.

### Hunt Query — Find Vulnerable Accounts

```powershell
# List all user accounts with SPNs set (potential Kerberoasting targets)
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName, PasswordLastSet, Enabled |
    Select-Object SamAccountName, Enabled,
        @{n='SPN'; e={$_.ServicePrincipalName -join '; '}},
        PasswordLastSet |
    Sort-Object PasswordLastSet |
    Format-Table -AutoSize -Wrap
```

### Hunt Query — Detect Active Kerberoasting (DC Event Logs)

```powershell
# Event 4769: TGS ticket requests with RC4 encryption (Kerberoasting indicator)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4769; StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Properties[5].Value -eq '0x17' -and          # RC4 encryption
        $_.Properties[6].Value -notmatch 'krbtgt|\$$'
    } |
    Select-Object TimeCreated,
        @{n='RequestingUser'; e={$_.Properties[0].Value}},
        @{n='ServiceName';    e={$_.Properties[2].Value}},
        @{n='ClientIP';       e={$_.Properties[6].Value}} |
    Group-Object RequestingUser |
    Where-Object { $_.Count -gt 3 } |
    Select-Object Count, Name, @{n='Services'; e={($_.Group.ServiceName | Sort-Object -Unique) -join ', '}} |
    Format-Table -AutoSize
```

### Sample Output
```
Count Name           Services
----- ----           --------
   14 jdoe           MSSQLSvc/SQL01, HTTP/portal, MSSQLSvc/SQL02, HTTP/intranet, FTP/files01
    7 svc_scanner    HTTP/webapp01, MSSQLSvc/SQL03, CIFS/fileserver
```

### Tips & Warnings
> ⚠️ A single user requesting more than **3–5 TGS tickets with RC4 encryption** in a short window is a high-confidence Kerberoasting indicator.

> 💡 **Mitigation:** Enforce AES-only on service accounts and use gMSAs with automatic password rotation:
> ```powershell
> Set-ADUser -Identity svc_sql -KerberosEncryptionType AES128,AES256
> ```

---

## 2. AS-REP Roasting Detection

### What you're looking for
AS-REP Roasting targets accounts where Kerberos pre-authentication is disabled (`DONT_REQUIRE_PREAUTH`). An attacker can request an AS-REP without knowing the password, then crack the encrypted portion offline.

### Hunt Query — Find Vulnerable Accounts

```powershell
# Accounts with Kerberos pre-auth disabled (AS-REP Roastable)
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth, PasswordLastSet, Enabled, MemberOf |
    Select-Object SamAccountName, Enabled, DoesNotRequirePreAuth, PasswordLastSet,
        @{n='MemberOf'; e={
            ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '
        }} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
SamAccountName  Enabled  DoesNotRequirePreAuth  PasswordLastSet           MemberOf
--------------  -------  ---------------------  ---------------           --------
svc_backup      True     True                   1/15/2024 09:00:00 AM    Backup Operators
old_admin       False    True                   6/03/2022 11:30:00 AM    Domain Admins
```

### Tips & Warnings
> ⚠️ **No legitimate reason exists** for pre-authentication to be disabled on modern accounts. Every account found should be remediated immediately.

> 💡 Fix vulnerable accounts in bulk:
> ```powershell
> Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } |
>     Set-ADAccountControl -DoesNotRequirePreAuth $false
> ```

---

## 3. DCSync via Event Logs

### What you're looking for
DCSync abuses AD replication privileges (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) to request password hashes directly from a DC — mimicking a legitimate replication partner. Tools like Mimikatz use this to extract the `krbtgt` hash or any user's NTLM hash.

### Hunt Query — Identify Accounts with Replication Rights

```powershell
$domainDN = (Get-ADDomain).DistinguishedName
$replGUIDs = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')

(Get-Acl "AD:\$domainDN").Access |
    Where-Object { $_.ObjectType -in $replGUIDs -and $_.AccessControlType -eq 'Allow' } |
    Select-Object @{n='Principal'; e={$_.IdentityReference}},
        @{n='Right'; e={
            if ($_.ObjectType -match '6aa') { 'Get-Changes' } else { 'Get-Changes-All' }
        }} |
    Where-Object { $_.Principal -notmatch 'Domain Controllers|Enterprise Read-only|SYSTEM' } |
    Format-Table -AutoSize
```

### Hunt Query — Detect DCSync in Event Logs

```powershell
# Event 4662: DS-Access audit — replication by non-DC accounts
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4662; StartTime = (Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Properties[9].Value -match '1131f6aa|1131f6ad' -and
        $_.Properties[1].Value -notmatch '\$$'
    } |
    Select-Object TimeCreated,
        @{n='Account';   e={$_.Properties[1].Value}},
        @{n='Operation'; e={$_.Properties[9].Value}},
        @{n='ObjectDN';  e={$_.Properties[6].Value}} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
TimeCreated              Account         Operation                              ObjectDN
-----------              -------         ---------                              --------
4/02/2026 02:41:00 AM    compromised01   {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} DC=corp,DC=local
```

### Tips & Warnings
> ⚠️ A **non-machine account** triggering replication GUIDs in event 4662 is a near-certain DCSync indicator.

> 💡 Enable DS Access auditing: `auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable`

---

## 4. Pass-the-Hash Indicators

### What you're looking for
Pass-the-Hash (PtH) allows attackers to authenticate using an NTLM hash without knowing the password. Key indicators include Event 4624 logon type 3 with NTLM authentication from unusual sources, and the same account authenticating from multiple IPs in rapid succession.

### Hunt Query

```powershell
# Detect NTLM network logons from unusual sources (potential PtH)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Properties[8].Value -eq 3 -and                   # Logon Type 3 (Network)
        $_.Properties[14].Value -eq 'NtLmSsp' -and          # NTLM authentication
        $_.Properties[18].Value -notmatch '127\.0\.0\.1|::1'
    } |
    Select-Object TimeCreated,
        @{n='Account';  e={$_.Properties[5].Value}},
        @{n='SourceIP'; e={$_.Properties[18].Value}} |
    Group-Object Account |
    Where-Object { ($_.Group.SourceIP | Sort-Object -Unique).Count -gt 2 } |
    Select-Object @{n='Account'; e={$_.Name}},
        @{n='UniqueSourceIPs'; e={($_.Group.SourceIP | Sort-Object -Unique).Count}},
        @{n='SourceIPs'; e={($_.Group.SourceIP | Sort-Object -Unique) -join ', '}} |
    Format-Table -AutoSize
```

### Sample Output
```
Account        UniqueSourceIPs SourceIPs
-------        --------------- ---------
admin_jdoe                   4 10.0.1.50, 10.0.2.12, 10.0.3.88, 192.168.5.22
svc_deploy                   3 10.0.1.50, 10.0.2.12, 10.0.3.88
```

### Tips & Warnings
> ⚠️ A single account authenticating via NTLM from **3+ unique source IPs within 24 hours** is highly suspicious — especially for privileged accounts.

> 💡 **Long-term fix:** Restrict NTLM via Group Policy → *Network security: Restrict NTLM: NTLM authentication in this domain* → **Deny All**.

---

## 5. Golden Ticket Detection (Event 4769)

### What you're looking for
A Golden Ticket is a forged Kerberos TGT created with the `krbtgt` account hash, granting unlimited domain access. Detection focuses on TGS requests (4769) where the account has no corresponding recent TGT request (4768) — because the TGT was forged, not legitimately issued.

### Hunt Query

```powershell
# Look for TGS requests that lack a corresponding recent TGT request
# A Golden Ticket user won't have a 4768 because the TGT was forged
$tgtUsers = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4768; StartTime = (Get-Date).AddDays(-2)
} -ErrorAction SilentlyContinue |
    ForEach-Object { $_.Properties[0].Value } | Sort-Object -Unique

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4769; StartTime = (Get-Date).AddDays(-2)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[0].Value -notmatch '\$$' } |
    Select-Object TimeCreated,
        @{n='Account';  e={$_.Properties[0].Value}},
        @{n='Service';  e={$_.Properties[2].Value}},
        @{n='ClientIP'; e={$_.Properties[6].Value}} |
    Where-Object { $_.Account -notin $tgtUsers } |
    Group-Object Account |
    Select-Object Count, Name,
        @{n='Services'; e={($_.Group.Service | Sort-Object -Unique) -join ', '}},
        @{n='ClientIPs'; e={($_.Group.ClientIP | Sort-Object -Unique) -join ', '}} |
    Format-Table -AutoSize
```

### Sample Output
```
Count Name          Services                          ClientIPs
----- ----          --------                          ---------
   23 fakeadmin     krbtgt/CORP.LOCAL, CIFS/DC01      10.0.1.200
    8 psychonaut    LDAP/DC01, HOST/DC01              10.0.3.77
```

### Tips & Warnings
> ⚠️ An account generating TGS requests (4769) **without any matching TGT request (4768)** in the same window strongly suggests a forged ticket. Investigate the source IP immediately.

> 💡 Rotate the `krbtgt` password **twice** (to invalidate both current and previous keys) to neutralize all Golden Tickets. Wait 12+ hours between resets.

---

## 6. AdminSDHolder Abuse

### What you're looking for
The `AdminSDHolder` container holds the security descriptor template applied to all protected groups (Domain Admins, Enterprise Admins, etc.) every 60 minutes by `SDProp`. An attacker who modifies the AdminSDHolder ACL gains persistent backdoor access to every protected group.

### Hunt Query

```powershell
# Audit the AdminSDHolder ACL for unexpected principals
$adminSDHolder = "AD:\CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)"
(Get-Acl $adminSDHolder).Access |
    Where-Object {
        $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|NT AUTHORITY' -and
        $_.AccessControlType -eq 'Allow'
    } |
    Select-Object @{n='Principal'; e={$_.IdentityReference}},
        ActiveDirectoryRights, AccessControlType, IsInherited |
    Format-Table -AutoSize -Wrap
```

### Hunt Query — Detect SDProp Modification Events

```powershell
# Event 5136: Directory object modified — AdminSDHolder changes
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 5136; StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'AdminSDHolder' } |
    Select-Object TimeCreated,
        @{n='Account';  e={$_.Properties[3].Value}},
        @{n='ObjectDN'; e={$_.Properties[8].Value}},
        @{n='Attribute'; e={$_.Properties[11].Value}} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
Principal              ActiveDirectoryRights  AccessControlType  IsInherited
---------              ---------------------  -----------------  -----------
CORP\backd00r_user     GenericAll             Allow              False
```

### Tips & Warnings
> ⚠️ **Any non-standard principal** in the AdminSDHolder ACL is almost certainly a backdoor. SDProp propagates this ACL to all protected groups every 60 minutes, giving the attacker persistent control.

> 💡 Remove rogue ACEs with `Get-Acl` / `RemoveAccessRule` / `Set-Acl` on the AdminSDHolder object.

---

## 7. SID History Injection

### What you're looking for
SID History is a legitimate migration feature that lets users retain access from a source domain. Attackers inject privileged SIDs (like Domain Admins, RID 512) into a low-privileged account's `sIDHistory`, granting silent privilege escalation.

### Hunt Query

```powershell
# Find accounts with SID History populated
Get-ADUser -Filter { SIDHistory -like '*' } -Properties SIDHistory, MemberOf |
    ForEach-Object {
        foreach ($sid in $_.SIDHistory) {
            [PSCustomObject]@{
                Account         = $_.SamAccountName
                SIDHistoryEntry = $sid.Value
                IsDomainAdmin   = $sid.Value -match '-512$'
                IsEntAdmin      = $sid.Value -match '-519$'
            }
        }
    } |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
Account      SIDHistoryEntry             IsDomainAdmin  IsEntAdmin
-------      ---------------             -------------  ----------
low_priv01   S-1-5-21-...-512            True           False
migrated01   S-1-5-21-...-1104           False          False
```

### Tips & Warnings
> ⚠️ A SID History entry ending in **-512** (Domain Admins) or **-519** (Enterprise Admins) on a non-admin account is critical — the account silently holds domain admin privileges.

> 💡 Remove malicious entries: `Set-ADUser -Identity low_priv01 -Remove @{SIDHistory='S-1-5-21-...-512'}`

---

## 8. Unconstrained Delegation Accounts

### What you're looking for
Accounts with unconstrained delegation cache the TGT of every user who authenticates to them. If compromised, an attacker can extract cached TGTs and impersonate any user — including Domain Admins.

### Hunt Query

```powershell
# Find all accounts with unconstrained delegation (excluding DCs)
$domainControllers = (Get-ADDomainController -Filter *).Name

Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, OperatingSystem, LastLogonDate |
    Where-Object { $_.Name -notin $domainControllers } |
    Select-Object Name, DNSHostName, OperatingSystem, LastLogonDate,
        @{n='Risk'; e={'HIGH - Unconstrained Delegation (non-DC)'}} |
    Format-Table -AutoSize -Wrap

# Also check user accounts (even more dangerous)
Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, Enabled |
    Select-Object SamAccountName, Enabled,
        @{n='Risk'; e={'CRITICAL - User with unconstrained delegation'}} |
    Format-Table -AutoSize
```

### Sample Output
```
Name       DNSHostName            OperatingSystem              LastLogonDate         Risk
----       -----------            ---------------              -------------         ----
DVLP-WEB01 dvlp-web01.corp.local Windows Server 2019 Standard 4/01/2026 09:12:00 AM HIGH - Unconstrained Delegation
LEGACY-APP legacy-app.corp.local  Windows Server 2012 R2       3/28/2026 02:30:00 PM HIGH - Unconstrained Delegation
```

### Tips & Warnings
> ⚠️ **Every non-DC with unconstrained delegation** is a Tier-0 asset — compromise leads to full domain compromise via TGT theft.

> 💡 Migrate to **constrained delegation**: `Set-ADComputer -Identity DVLP-WEB01 -TrustedForDelegation $false` then configure `msDS-AllowedToDelegateTo` for specific SPNs.

---

## 9. LDAP Recon Detection (Event 1644)

### What you're looking for
Attack tools like BloodHound, SharpHound, and ADRecon perform expensive LDAP queries to map the entire AD environment. Event 1644 (when enabled) logs these expensive or long-running LDAP searches.

### Detection Script — Enable LDAP Diagnostics

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
    -Name '15 Field Engineering' -Value 5 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name 'Expensive Search Results Threshold' -Value 1000 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name 'Inefficient Search Results Threshold' -Value 500 -Type DWord -Force
```

### Hunt Query — Analyze LDAP Search Events

```powershell
# Event 1644: Expensive LDAP queries — common during AD enumeration
Get-WinEvent -FilterHashtable @{
    LogName = 'Directory Service'; Id = 1644; StartTime = (Get-Date).AddHours(-4)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
        @{n='ClientIP';     e={ if ($_.Message -match 'Client IP:\s*(.+)') { $Matches[1].Trim() } }},
        @{n='SearchFilter'; e={ if ($_.Message -match 'Filter:\s*(.+)') { $Matches[1].Trim() } }},
        @{n='ResultCount';  e={ if ($_.Message -match 'Entries Returned:\s*(\d+)') { [int]$Matches[1] } }} |
    Where-Object { $_.ResultCount -gt 100 } |
    Sort-Object ResultCount -Descending |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
TimeCreated              ClientIP       SearchFilter                                    ResultCount
-----------              --------       ------------                                    -----------
4/02/2026 03:15:00 AM    10.0.1.50      (objectClass=user)                              4,287
4/02/2026 03:15:02 AM    10.0.1.50      (objectClass=group)                             1,823
4/02/2026 03:15:05 AM    10.0.1.50      (objectClass=computer)                            892
4/02/2026 03:15:08 AM    10.0.1.50      (&(objectCategory=person)(adminCount=1))           47
```

### Tips & Warnings
> ⚠️ A single IP issuing broad queries like `(objectClass=user)`, `(objectClass=group)`, and `(objectClass=computer)` in rapid succession is a textbook SharpHound collection pattern.

> 💡 Reduce the diagnostic level after your hunting window to avoid excessive logging:
> ```powershell
> Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
>     -Name '15 Field Engineering' -Value 0
> ```

---

## 10. ACL Abuse Paths (GenericAll/WriteDACL)

### What you're looking for
Misconfigured ACLs are a primary privilege escalation path. Attackers look for low-privileged accounts holding `GenericAll`, `WriteDACL`, `WriteOwner`, or `GenericWrite` over privileged objects, enabling password resets, group membership changes, or full object takeover.

### Hunt Query — Scan High-Value Targets for Dangerous ACEs

```powershell
$highValueTargets = @(
    (Get-ADGroup 'Domain Admins').DistinguishedName,
    (Get-ADGroup 'Enterprise Admins').DistinguishedName,
    (Get-ADUser  'krbtgt').DistinguishedName
)
$dangerousRights = 'GenericAll|WriteDacl|WriteOwner|GenericWrite'

foreach ($targetDN in $highValueTargets) {
    (Get-Acl "AD:\$targetDN").Access |
        Where-Object {
            $_.ActiveDirectoryRights -match $dangerousRights -and
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|NT AUTHORITY'
        } |
        Select-Object @{n='Target'; e={$targetDN -replace ',.*',''}},
            @{n='Principal'; e={$_.IdentityReference}},
            ActiveDirectoryRights,
            @{n='Inherited'; e={$_.IsInherited}}
} | Format-Table -AutoSize -Wrap
```

### Sample Output
```
Target              Principal           ActiveDirectoryRights  Inherited
------              ---------           ---------------------  ---------
CN=Domain Admins    CORP\helpdesk_svc   GenericAll             False
CN=krbtgt           CORP\old_svc_acct   GenericWrite           True
```

### Tips & Warnings
> ⚠️ `GenericAll` on Domain Admins is functionally equivalent to being a Domain Admin — the principal can add themselves to the group, reset passwords, or modify any attribute.

> 💡 Remove dangerous ACEs with `Get-Acl` / `RemoveAccessRule` / `Set-Acl` on the target object.

---

## 11. BloodHound-Style Enumeration Patterns

### What you're looking for
BloodHound/SharpHound collectors perform high-volume, structured LDAP and SAMR queries to map AD relationships:
- Thousands of LDAP queries for users, groups, computers, GPOs, and trusts in minutes
- SAMR enumeration of local group membership on many machines (Event 4799)
- Session enumeration via NetSessionEnum to many hosts in rapid succession

### Hunt Query — SAMR Local Group Enumeration

```powershell
# Event 4799: Local group membership enumeration (SharpHound triggers this)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4799; StartTime = (Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
        @{n='CallerAccount'; e={$_.Properties[0].Value}},
        @{n='GroupName';     e={$_.Properties[4].Value}} |
    Group-Object CallerAccount |
    Where-Object { $_.Count -gt 20 } |
    Select-Object Count, Name,
        @{n='GroupsQueried'; e={($_.Group.GroupName | Sort-Object -Unique) -join ', '}} |
    Sort-Object Count -Descending |
    Format-Table -AutoSize
```

### Hunt Query — Detect Mass Session Enumeration

```powershell
# High volume of connections to port 445 from a single source
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 3
    StartTime = (Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[15].Value -eq 445 } |
    Select-Object @{n='SourceIP'; e={$_.Properties[9].Value}},
        @{n='DestIP'; e={$_.Properties[14].Value}} |
    Group-Object SourceIP |
    Where-Object { ($_.Group.DestIP | Sort-Object -Unique).Count -gt 20 } |
    Select-Object @{n='SourceIP'; e={$_.Name}},
        @{n='UniqueTargets'; e={($_.Group.DestIP | Sort-Object -Unique).Count}} |
    Format-Table -AutoSize
```

### Sample Output
```
Count Name     GroupsQueried                                                SourceIP    UniqueTargets
----- ----     -------------                                                --------    -------------
  347 jdoe     Administrators, Remote Desktop Users, Distributed COM Users  10.0.1.50   142
   52 scanner  Administrators                                               10.0.3.22    38
```

### Tips & Warnings
> ⚠️ A single account querying local group membership on **20+ hosts in under 2 hours** strongly indicates SharpHound collection. Correlate with LDAP event 1644 from the same source IP.

> 💡 **Canary detection:** Create a decoy OU with an auditing SACL — any enumeration tool will touch it:
> ```powershell
> New-ADOrganizationalUnit -Name "Finance-Servers" -Path "OU=Servers,DC=corp,DC=local"
> $acl = Get-Acl "AD:\OU=Finance-Servers,OU=Servers,DC=corp,DC=local"
> $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
> $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
>     $everyone, 'ReadProperty', 'Success', 'All')
> $acl.AddAuditRule($rule)
> Set-Acl -Path "AD:\OU=Finance-Servers,OU=Servers,DC=corp,DC=local" -AclObject $acl
> ```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [11 — PKI and Certificate Management](11-PKI-and-Certificate-Management.md) | [README](../README.md) | [13 — Privileged Access Management](13-Privileged-Access-Management.md) |
