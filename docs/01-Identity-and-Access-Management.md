# 01 — Identity and Access Management

> **Module required:** `ActiveDirectory` (part of RSAT)  
> **Run as:** Domain user with appropriate delegated rights; some commands require Domain Admin.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-ADUser` | Query Active Directory user accounts |
| `New-ADUser` | Create a new AD user account |
| `Set-ADUser` | Modify attributes of an existing AD user |
| `Disable-ADAccount` | Disable an AD account (user or computer) |
| `Get-ADGroupMember` | List members of an AD group |
| `Add-ADGroupMember` | Add a user or computer to an AD group |
| `Get-ADDefaultDomainPasswordPolicy` | View the default domain password policy |
| `Set-ADAccountPassword` | Reset or change a user's password |
| `Search-ADAccount` | Find accounts matching specific criteria (locked, expired, inactive) |

---

## 1. `Get-ADUser`

### What it does
Queries Active Directory for user account objects. You can search for a single user by their username (SamAccountName) or search broadly with filters. Think of it as looking up employee records in a company directory.

### Full Syntax
```powershell
Get-ADUser
    [-Identity] <ADUser>
    [-Properties <String[]>]
    [-Server <String>]
    [-Credential <PSCredential>]

# OR filter multiple accounts:
Get-ADUser
    -Filter <String>
    [-SearchBase <String>]
    [-SearchScope <ADSearchScope>]
    [-Properties <String[]>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Identity` | String | The user to look up — SamAccountName, UPN, DN, or GUID |
| `-Filter` | String | LDAP-style filter to match multiple users (e.g., `"Enabled -eq $true"`) |
| `-Properties` | String[] | Extra attributes to return. Use `*` for all. Default returns only basic fields |
| `-SearchBase` | String | Limits the search to a specific OU (Distinguished Name) |
| `-SearchScope` | Enum | `Base`, `OneLevel`, or `Subtree` (default) |
| `-Server` | String | Target a specific Domain Controller |

### Real-World Example
**Scenario:** A help-desk ticket says user `jsmith` can't log in. You need to check whether the account is enabled, when the password expires, and whether it's locked out.

```powershell
Get-ADUser -Identity jsmith -Properties Enabled, PasswordExpired, LockedOut, LastLogonDate, PasswordLastSet |
    Select-Object Name, SamAccountName, Enabled, PasswordExpired, LockedOut, LastLogonDate, PasswordLastSet
```

### Sample Output
```
Name              : John Smith
SamAccountName    : jsmith
Enabled           : True
PasswordExpired   : False
LockedOut         : True
LastLogonDate     : 3/28/2026 8:45:02 AM
PasswordLastSet   : 1/15/2026 9:00:00 AM
```

### Tips & Warnings
> ⚠️ **Default properties are limited.** If you don't specify `-Properties`, many useful fields (like `LastLogonDate`, `LockedOut`) will be empty or `$null`. Always add `-Properties` for the fields you need.

> 💡 **Tip:** To find all disabled accounts in a specific OU:
> ```powershell
> Get-ADUser -Filter "Enabled -eq $false" -SearchBase "OU=Employees,DC=corp,DC=local"
> ```

### Common Variations
```powershell
# Find all users whose password never expires
Get-ADUser -Filter "PasswordNeverExpires -eq $true" -Properties PasswordNeverExpires

# Find all inactive accounts (no logon in 90 days)
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter "LastLogonDate -lt '$cutoff'" -Properties LastLogonDate

# Export all users to CSV
Get-ADUser -Filter * -Properties Department, Title, Mail |
    Select-Object Name, SamAccountName, Department, Title, Mail |
    Export-Csv -Path C:\audit\all_users.csv -NoTypeInformation
```

---

## 2. `New-ADUser`

### What it does
Creates a new user account in Active Directory. Equivalent to the "New User" wizard in Active Directory Users and Computers (ADUC), but scriptable — perfect for bulk onboarding.

### Full Syntax
```powershell
New-ADUser
    [-Name] <String>
    [-SamAccountName <String>]
    [-UserPrincipalName <String>]
    [-GivenName <String>]
    [-Surname <String>]
    [-DisplayName <String>]
    [-Path <String>]
    [-AccountPassword <SecureString>]
    [-Enabled <Boolean>]
    [-ChangePasswordAtLogon <Boolean>]
    [-Department <String>]
    [-Title <String>]
    [-EmailAddress <String>]
    [-Description <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Name` | The CN (Common Name) shown in AD |
| `-SamAccountName` | The legacy logon name (pre-Windows 2000), e.g., `jsmith` |
| `-UserPrincipalName` | The UPN/email-style logon, e.g., `jsmith@corp.local` |
| `-Path` | The OU where the account should be created (Distinguished Name) |
| `-AccountPassword` | Must be a `SecureString`; use `ConvertTo-SecureString` |
| `-Enabled` | `$true` to enable the account immediately |
| `-ChangePasswordAtLogon` | Forces password change at first login |

### Real-World Example
**Scenario:** HR sends you a list of new hires. You need to create accounts for them in the `OU=NewHires,OU=Employees,DC=corp,DC=local` OU.

```powershell
$password = ConvertTo-SecureString "TempP@ss2026!" -AsPlainText -Force

New-ADUser `
    -Name "Jane Doe" `
    -GivenName "Jane" `
    -Surname "Doe" `
    -SamAccountName "jdoe" `
    -UserPrincipalName "jdoe@corp.local" `
    -DisplayName "Jane Doe" `
    -Department "Finance" `
    -Title "Financial Analyst" `
    -EmailAddress "jdoe@corp.local" `
    -Path "OU=NewHires,OU=Employees,DC=corp,DC=local" `
    -AccountPassword $password `
    -Enabled $true `
    -ChangePasswordAtLogon $true
```

### Sample Output
```
(No output on success — run Get-ADUser -Identity jdoe to confirm)
```

### Tips & Warnings
> ⚠️ **Never hardcode passwords** in production scripts. Prompt for the password interactively with `Read-Host -AsSecureString` or retrieve it from a secrets vault.

> ⚠️ **Password complexity** must meet the domain policy or the command will fail with an error about password constraints.

> 💡 **Bulk creation from CSV:** Create a CSV with columns `GivenName,Surname,SamAccountName,Department` and loop:
> ```powershell
> Import-Csv C:\newusers.csv | ForEach-Object {
>     New-ADUser -Name "$($_.GivenName) $($_.Surname)" `
>         -GivenName $_.GivenName -Surname $_.Surname `
>         -SamAccountName $_.SamAccountName `
>         -Department $_.Department `
>         -Path "OU=NewHires,OU=Employees,DC=corp,DC=local" `
>         -Enabled $false
> }
> ```

---

## 3. `Set-ADUser`

### What it does
Modifies attributes of an existing Active Directory user. Use it to update a title, phone number, manager, description — or to unlock/re-enable an account.

### Full Syntax
```powershell
Set-ADUser
    [-Identity] <ADUser>
    [-Add <Hashtable>]
    [-Remove <Hashtable>]
    [-Replace <Hashtable>]
    [-Clear <String[]>]
    [-Description <String>]
    [-Department <String>]
    [-Title <String>]
    [-Manager <ADUser>]
    [-Enabled <Boolean>]
    [-SmartcardLogonRequired <Boolean>]
    [-Server <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Identity` | Target user (SamAccountName, DN, UPN, or GUID) |
| `-Replace` | Hashtable of attribute/value pairs to overwrite |
| `-Add` | Hashtable of multi-value attributes to append values to |
| `-Remove` | Hashtable of multi-value attributes to remove specific values from |
| `-Clear` | List of attribute names to blank out entirely |

### Real-World Example
**Scenario:** John Smith was promoted. You need to update his title, department, and manager in AD.

```powershell
Set-ADUser -Identity jsmith `
    -Title "Senior Security Engineer" `
    -Department "Cybersecurity" `
    -Manager "mwilliams" `
    -Description "Promoted 2026-03-01"
```

### Sample Output
```
(No output on success)
```

### Tips & Warnings
> 💡 To update attributes not exposed as named parameters (like `extensionAttribute1`), use `-Replace`:
> ```powershell
> Set-ADUser -Identity jsmith -Replace @{ extensionAttribute1 = "SEC-TEAM" }
> ```

> ⚠️ Use `-Clear` carefully — it removes all values from the attribute, including ones set by other systems.

---

## 4. `Disable-ADAccount`

### What it does
Disables an Active Directory account, preventing the user (or computer) from authenticating. The account and all its data remain in AD — it is just blocked from logging in. This is the standard first step when offboarding an employee or responding to a compromised account.

### Full Syntax
```powershell
Disable-ADAccount
    [-Identity] <ADAccount>
    [-Server <String>]
    [-Credential <PSCredential>]
    [-WhatIf]
    [-Confirm]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Identity` | The account to disable — SamAccountName, DN, UPN, or GUID |
| `-WhatIf` | Preview what would happen without actually disabling |
| `-Confirm` | Prompt for confirmation before executing |

### Real-World Example
**Scenario:** A security alert fires for user `bthompson` who is suspected of data exfiltration. You need to immediately lock out the account.

```powershell
# Disable the account
Disable-ADAccount -Identity bthompson

# Confirm it worked
Get-ADUser -Identity bthompson -Properties Enabled | Select-Object Name, Enabled
```

### Sample Output
```
Name           Enabled
----           -------
Bob Thompson   False
```

### Tips & Warnings
> ⚠️ **Disabling is reversible**; deleting is not. Always disable first, then delete after the retention period elapses.

> 💡 **Bulk disable** accounts from a list:
> ```powershell
> Get-Content C:\terminated_users.txt | ForEach-Object {
>     Disable-ADAccount -Identity $_ -Confirm:$false
>     Write-Host "Disabled: $_"
> }
> ```

> 💡 After disabling, also consider **moving the account** to a "Disabled Accounts" OU:
> ```powershell
> Move-ADObject -Identity (Get-ADUser bthompson).DistinguishedName `
>     -TargetPath "OU=Disabled,DC=corp,DC=local"
> ```

---

## 5. `Get-ADGroupMember`

### What it does
Lists all members of an Active Directory group. Useful for auditing who has access to sensitive systems, verifying privileged group membership, or confirming that a user was added/removed correctly.

### Full Syntax
```powershell
Get-ADGroupMember
    [-Identity] <ADGroup>
    [-Recursive]
    [-Server <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Identity` | The group name, DN, SID, or GUID |
| `-Recursive` | Expands nested groups to show all effective members |

### Real-World Example
**Scenario:** During a quarterly access review, you need to verify who is in the `Domain Admins` group.

```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, objectClass |
    Sort-Object objectClass, Name
```

### Sample Output
```
Name              SamAccountName   objectClass
----              --------------   -----------
Administrator     Administrator    user
John Smith        jsmith           user
SVC-Backup        svc_backup       user
```

### Tips & Warnings
> ⚠️ **Always use `-Recursive`** when auditing privileged groups. Attackers often gain Domain Admin through nested group membership that is invisible without this flag.

> 💡 **Export privileged group membership to CSV for audits:**
> ```powershell
> $groups = "Domain Admins","Enterprise Admins","Schema Admins","Administrators"
> foreach ($g in $groups) {
>     Get-ADGroupMember -Identity $g -Recursive |
>         Select-Object @{n='Group';e={$g}}, Name, SamAccountName |
>         Export-Csv -Path "C:\audit\privileged_groups.csv" -Append -NoTypeInformation
> }
> ```

---

## 6. `Add-ADGroupMember`

### What it does
Adds one or more users (or computers, or groups) to an Active Directory group. The reverse operation is `Remove-ADGroupMember`.

### Full Syntax
```powershell
Add-ADGroupMember
    [-Identity] <ADGroup>
    [-Members] <ADPrincipal[]>
    [-Server <String>]
    [-Credential <PSCredential>]
    [-WhatIf]
    [-Confirm]
```

### Real-World Example
**Scenario:** A developer needs temporary read-only access to the file server. You add them to the `FileServer-ReadOnly` group.

```powershell
Add-ADGroupMember -Identity "FileServer-ReadOnly" -Members "jdeveloper"

# Verify
Get-ADGroupMember -Identity "FileServer-ReadOnly" | Select-Object Name
```

### Sample Output
```
Name
----
Jane Developer
```

### Tips & Warnings
> 💡 Add multiple members at once:
> ```powershell
> Add-ADGroupMember -Identity "VPN-Users" -Members "user1","user2","user3"
> ```

> ⚠️ Group membership changes may take time to replicate across domain controllers and may not take effect until the user logs off and back on.

---

## 7. `Get-ADDefaultDomainPasswordPolicy`

### What it does
Retrieves the default domain-wide password policy — minimum length, complexity requirements, lockout thresholds, and password history. Essential for compliance checks (CIS, NIST, SOC 2).

### Full Syntax
```powershell
Get-ADDefaultDomainPasswordPolicy
    [[-Identity] <ADDefaultDomainPasswordPolicy>]
    [-Server <String>]
```

### Real-World Example
**Scenario:** Your auditor asks you to confirm the domain meets NIST SP 800-63B guidelines (minimum 8 characters, account lockout enabled).

```powershell
Get-ADDefaultDomainPasswordPolicy -Identity "corp.local"
```

### Sample Output
```
ComplexityEnabled           : True
DistinguishedName           : DC=corp,DC=local
LockoutDuration             : 00:30:00
LockoutObservationWindow    : 00:30:00
LockoutThreshold            : 5
MaxPasswordAge              : 90.00:00:00
MinPasswordAge              : 1.00:00:00
MinPasswordLength           : 12
PasswordHistoryCount        : 24
ReversibleEncryptionEnabled : False
```

### Tips & Warnings
> 💡 Fine-Grained Password Policies (PSOs) override the default policy for specific users or groups. Check them with:
> ```powershell
> Get-ADFineGrainedPasswordPolicy -Filter *
> ```

> ⚠️ `ReversibleEncryptionEnabled : True` is a serious security risk — passwords are essentially stored in plaintext.

---

## 8. Password Reset — `Set-ADAccountPassword`

### What it does
Resets a user's Active Directory password. Help desk staff do this constantly; during incident response, you may need to force a password reset on a compromised account immediately.

### Full Syntax
```powershell
Set-ADAccountPassword
    [-Identity] <ADAccount>
    [-NewPassword <SecureString>]
    [-Reset]
    [-OldPassword <SecureString>]
    [-Server <String>]
```

### Real-World Example
**Scenario:** User `jsmith`'s credentials have been found in a breach database. You need to immediately reset their password and force a change at next logon.

```powershell
# Reset password
$newPass = ConvertTo-SecureString "R3set!Temp2026#" -AsPlainText -Force
Set-ADAccountPassword -Identity jsmith -NewPassword $newPass -Reset

# Force password change at next logon
Set-ADUser -Identity jsmith -ChangePasswordAtLogon $true

Write-Host "Password reset complete for jsmith"
```

### Tips & Warnings
> ⚠️ **Use `-Reset`** (admin reset) rather than changing via old password when the old password is unknown or compromised.

> ⚠️ Always use `ConvertTo-SecureString` — never pass passwords as plain strings in `-NewPassword`.

---

## 9. Service Account Auditing

### What it does
Service accounts are non-human AD accounts used by applications and scheduled tasks. They are high-value targets because they often have elevated privileges and passwords that never expire.

### Real-World Example
**Scenario:** During a security review, you need to find all service accounts (by convention, prefixed with `svc_`), check if their passwords never expire, and verify they are not members of overly privileged groups.

```powershell
# Find all service accounts with passwords that never expire
Get-ADUser -Filter "SamAccountName -like 'svc_*'" -Properties PasswordNeverExpires, LastLogonDate, MemberOf |
    Select-Object Name, SamAccountName, PasswordNeverExpires, LastLogonDate,
        @{n='Groups'; e={ ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join '; ' }} |
    Format-Table -AutoSize
```

### Sample Output
```
Name         SamAccountName  PasswordNeverExpires  LastLogonDate           Groups
----         --------------  --------------------  -------------           ------
SVC-Backup   svc_backup      True                  3/28/2026 2:00:00 AM   Backup Operators
SVC-SQL      svc_sql         True                  3/29/2026 6:15:00 AM   Domain Admins; SQL Admins
```

### Tips & Warnings
> ⚠️ **`svc_sql` is in Domain Admins** — this is a serious over-privileged service account. Flag it immediately.

> 💡 Use **Managed Service Accounts (gMSA)** where possible — they rotate their own passwords automatically.

> 💡 To find service accounts that haven't logged on in 90 days (potentially orphaned):
> ```powershell
> $cutoff = (Get-Date).AddDays(-90)
> Get-ADUser -Filter "SamAccountName -like 'svc_*' -and LastLogonDate -lt '$cutoff'" `
>     -Properties LastLogonDate |
>     Select-Object Name, SamAccountName, LastLogonDate
> ```

---

## 🔍 Additional Useful Commands

```powershell
# Unlock a locked account
Unlock-ADAccount -Identity jsmith

# Check if account is locked
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LockedOut

# Find all accounts with passwords expiring in the next 7 days
Search-ADAccount -PasswordExpiring -TimeSpan 7.00:00:00 |
    Select-Object Name, SamAccountName, PasswordExpired

# Find all accounts that have never logged on
Search-ADAccount -AccountNeverLoggedOn | Select-Object Name, SamAccountName

# Get a user's effective group memberships (all nested groups)
(Get-ADUser jsmith -Properties MemberOf).MemberOf |
    Get-ADGroup | Select-Object Name | Sort-Object Name
```

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| — | [README](../README.md) | [02 — GPO Management](02-GPO-Management.md) |
