# 18 — Exchange and Email Security

> **Modules required:** `ExchangeOnlineManagement`, `Microsoft.Graph` (for audit logs)  
> **Run as:** Exchange Administrator or Security Administrator role in Microsoft 365.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Connect-ExchangeOnline` | Authenticate to Exchange Online PowerShell |
| `Get-MessageTrace` | Trace email delivery over the last 10 days |
| `Get-MessageTraceDetail` | Get detailed routing for a specific message |
| `Search-UnifiedAuditLog` | Search M365 audit logs for email events |
| `Set-Mailbox -AuditEnabled` | Enable mailbox audit logging |
| `Get-QuarantineMessage` | List quarantined emails |
| `New-TransportRule` | Create mail flow rules to block threats |
| `Get-DkimSigningConfig` | Check DKIM signing configuration |
| `Get-InboxRule` | Detect auto-forwarding rules on mailboxes |
| `New-ComplianceSearch` | Search and purge phishing emails in bulk |

---

## 1. `Connect-ExchangeOnline`

### What it does
Establishes an authenticated session to Exchange Online PowerShell. All subsequent Exchange commands run through this connection.

### Full Syntax
```powershell
Connect-ExchangeOnline
    [-UserPrincipalName <String>]
    [-Organization <String>]
    [-CertificateThumbprint <String>]
    [-AppId <String>]
    [-ShowBanner <Boolean>]
```

### Real-World Example
**Scenario:** Connect to Exchange Online for phishing investigation.

```powershell
# Interactive login
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com -ShowBanner:$false

# Certificate-based (unattended)
Connect-ExchangeOnline -AppId "app-guid" -CertificateThumbprint "ABCD1234..." -Organization "contoso.onmicrosoft.com"
```

### Sample Output
```
(Connection established — no output on success)
```

### Tips & Warnings
> 💡 Use certificate-based authentication for automated scripts — no interactive prompts.

> ⚠️ Always run `Disconnect-ExchangeOnline -Confirm:$false` when done to release the session.

---

## 2. `Get-MessageTrace`

### What it does
Traces email messages through Exchange Online for the last 10 days. Essential for phishing investigations, delivery troubleshooting, and data loss investigations.

### Full Syntax
```powershell
Get-MessageTrace
    [-SenderAddress <String>]
    [-RecipientAddress <String>]
    [-MessageId <String>]
    [-StartDate <DateTime>]
    [-EndDate <DateTime>]
    [-Status <String>]         # Delivered, Failed, Pending, Expanded, Quarantined, FilteredAsSpam
    [-PageSize <Int32>]
    [-Page <Int32>]
```

### Real-World Example
**Scenario:** A user reported a phishing email from `attacker@evil.com`. Find all recipients who received it.

```powershell
Get-MessageTrace -SenderAddress "attacker@evil.com" `
    -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
    Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, MessageId |
    Format-Table -AutoSize
```

### Sample Output
```
Received              SenderAddress       RecipientAddress      Subject                  Status
--------              -------------       ----------------      -------                  ------
3/28/2026 9:00 AM     attacker@evil.com   user1@contoso.com     Urgent: Verify Account   Delivered
3/28/2026 9:00 AM     attacker@evil.com   user2@contoso.com     Urgent: Verify Account   Quarantined
3/28/2026 9:01 AM     attacker@evil.com   user3@contoso.com     Urgent: Verify Account   Delivered
```

### Tips & Warnings
> ⚠️ `Get-MessageTrace` only covers the last **10 days**. For older messages, use `Start-HistoricalSearch`.

> 💡 Export all results for the incident report:
> ```powershell
> Get-MessageTrace -SenderAddress "attacker@evil.com" -StartDate (Get-Date).AddDays(-10) -EndDate (Get-Date) |
>     Export-Csv C:\ir\phish_trace.csv -NoTypeInformation
> ```

---

## 3. `Search-UnifiedAuditLog` for Email Events

### What it does
Searches the Microsoft 365 Unified Audit Log for mailbox and email-related operations — who accessed a mailbox, forwarding rule changes, delegate additions, and more.

### Full Syntax
```powershell
Search-UnifiedAuditLog
    -StartDate <DateTime>
    -EndDate <DateTime>
    [-Operations <String[]>]
    [-UserIds <String[]>]
    [-RecordType <String>]
    [-ResultSize <Int32>]
```

### Real-World Example
**Scenario:** Investigate whether an attacker created mail forwarding rules on compromised accounts.

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -Operations "New-InboxRule","Set-InboxRule","Set-Mailbox" `
    -ResultSize 1000 |
    Select-Object CreationDate, UserIds, Operations,
        @{n='Details';e={ ($_.AuditData | ConvertFrom-Json).Parameters }} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
CreationDate          UserIds              Operations      Details
------------          -------              ----------      -------
3/27/2026 2:15 AM     jsmith@contoso.com   New-InboxRule   ForwardTo: ext@attacker.com
```

### Tips & Warnings
> ⚠️ **Forwarding rules created at odd hours** to external addresses are a top indicator of compromise.

> 💡 Audit log retention depends on your license — E5 gets 1 year, E3 gets 180 days by default.

---

## 4. Mailbox Audit Logging

### What it does
Enables detailed audit logging on mailboxes so that actions like message reads, deletions, and sends-as are recorded.

### Real-World Example
**Scenario:** Enable audit logging on all mailboxes and verify the configuration.

```powershell
# Enable auditing on all mailboxes
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 365

# Verify a specific mailbox
Get-Mailbox -Identity jsmith@contoso.com | Select-Object DisplayName, AuditEnabled, AuditLogAgeLimit,
    @{n='OwnerActions';e={$_.AuditOwner -join ', '}},
    @{n='DelegateActions';e={$_.AuditDelegate -join ', '}}
```

### Sample Output
```
DisplayName  : John Smith
AuditEnabled : True
AuditLogAgeLimit : 365.00:00:00
OwnerActions : MailboxLogin, HardDelete, SoftDelete, MoveToDeletedItems, UpdateInboxRules
DelegateActions : SendAs, SendOnBehalf, MoveToDeletedItems, HardDelete
```

### Tips & Warnings
> 💡 Microsoft 365 now enables mailbox auditing by default, but the audit actions may be limited. Explicitly setting it ensures comprehensive coverage.

---

## 5. Phishing Response — Quarantine Management

### What it does
View, release, or delete quarantined messages during phishing incidents.

### Real-World Example
**Scenario:** Investigate quarantined phishing emails and release any false positives.

```powershell
# List quarantined messages from suspect sender
Get-QuarantineMessage -SenderAddress "attacker@evil.com" -StartDate (Get-Date).AddDays(-7) |
    Select-Object ReceivedTime, SenderAddress, RecipientAddress, Subject, Type, ReleaseStatus |
    Format-Table -AutoSize

# Release a false positive
Release-QuarantineMessage -Identity "quarantine-message-id" -ReleaseToAll

# Delete a confirmed phishing message
Delete-QuarantineMessage -Identity "quarantine-message-id"
```

### Sample Output
```
ReceivedTime         SenderAddress       RecipientAddress      Subject                Type    ReleaseStatus
------------         -------------       ----------------      -------                ----    -------------
3/28/2026 9:00 AM    attacker@evil.com   user2@contoso.com     Urgent: Verify Account Phish   NotReleased
```

### Tips & Warnings
> ⚠️ Never release confirmed phishing without removing the malicious link/attachment first.

---

## 6. Blocking Senders via Transport Rules

### What it does
Create mail flow (transport) rules to block emails from malicious senders, domains, or containing specific indicators.

### Real-World Example
**Scenario:** Block all email from a known phishing domain and reject with a notification.

```powershell
New-TransportRule -Name "Block evil.com phishing" `
    -SenderDomainIs "evil.com" `
    -RejectMessageReasonText "Blocked: Known phishing domain" `
    -RejectMessageEnhancedStatusCode "5.7.1" `
    -StopRuleProcessing $true

# Block emails containing a specific malicious URL
New-TransportRule -Name "Block malicious URL" `
    -SubjectOrBodyContainsWords "http://evil.com/phish" `
    -DeleteMessage $true
```

### Sample Output
```
Name                    State   Priority
----                    -----   --------
Block evil.com phishing Enabled 0
```

### Tips & Warnings
> 💡 Use `-StopRuleProcessing $true` to ensure no later rules override your block.

> ⚠️ Transport rules apply to ALL mail flow — test with `-Mode Audit` first before enforcing.

---

## 7. DKIM Configuration — `Get-DkimSigningConfig`

### What it does
Checks and manages DomainKeys Identified Mail (DKIM) signing configuration for your domains. DKIM helps prevent email spoofing.

### Real-World Example
**Scenario:** Verify DKIM is enabled for all your domains.

```powershell
Get-DkimSigningConfig | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME |
    Format-Table -AutoSize
```

### Sample Output
```
Domain           Enabled Status   Selector1CNAME                           Selector2CNAME
------           ------- ------   --------------                           --------------
contoso.com      True    Valid    selector1-contoso-com._domainkey.contoso.onmicrosoft.com  selector2-...
marketing.com    False   Invalid  selector1-marketing-com._domainkey...    selector2-...
```

### Tips & Warnings
> ⚠️ `Enabled: False` means outbound emails from that domain are NOT DKIM-signed — enable it immediately:
> ```powershell
> Set-DkimSigningConfig -Identity "marketing.com" -Enabled $true
> ```

---

## 8. Detecting Auto-Forwarding Rules

### What it does
Scans all mailboxes for inbox rules that forward or redirect email externally — a top indicator of Business Email Compromise (BEC).

### Real-World Example
**Scenario:** Audit all mailboxes for suspicious forwarding rules during a BEC investigation.

```powershell
$mailboxes = Get-Mailbox -ResultSize Unlimited
$forwardingRules = foreach ($mbx in $mailboxes) {
    $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue |
        Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }
    foreach ($rule in $rules) {
        [PSCustomObject]@{
            Mailbox    = $mbx.UserPrincipalName
            RuleName   = $rule.Name
            ForwardTo  = ($rule.ForwardTo -join '; ')
            RedirectTo = ($rule.RedirectTo -join '; ')
            Enabled    = $rule.Enabled
        }
    }
}
$forwardingRules | Format-Table -AutoSize
```

### Sample Output
```
Mailbox                RuleName         ForwardTo              RedirectTo  Enabled
-------                --------         ---------              ----------  -------
jsmith@contoso.com     Auto-FWD         ext-acct@gmail.com                 True
cfo@contoso.com        Backup Copy      attacker@evil.com                  True
```

### Tips & Warnings
> ⚠️ **`cfo@contoso.com` forwarding to an external address** is a critical BEC indicator — disable immediately:
> ```powershell
> Disable-InboxRule -Mailbox "cfo@contoso.com" -Identity "Backup Copy" -Confirm:$false
> ```

> 💡 Also check mailbox-level forwarding (not rule-based):
> ```powershell
> Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -ne $null } |
>     Select-Object DisplayName, ForwardingSmtpAddress
> ```

---

## 9. OAuth App Consent Audit

### What it does
Reviews OAuth application consent grants to detect malicious apps that were granted access to mailbox data through phishing consent attacks.

### Real-World Example
**Scenario:** Audit all OAuth apps with mail access permissions.

```powershell
Connect-MgGraph -Scopes "Application.Read.All"
$grants = Get-MgOauth2PermissionGrant -All |
    Where-Object { $_.Scope -match "Mail|Contacts|Calendars" }

foreach ($grant in $grants) {
    $app = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId
    [PSCustomObject]@{
        AppName    = $app.DisplayName
        Scope      = $grant.Scope
        ConsentType = $grant.ConsentType
        PrincipalId = $grant.PrincipalId
    }
} | Format-Table -AutoSize
```

### Sample Output
```
AppName              Scope                          ConsentType  PrincipalId
-------              -----                          -----------  -----------
Outlook Mobile       Mail.ReadWrite Contacts.Read   Principal    user-guid-1
SuspiciousApp        Mail.ReadWrite Mail.Send        Principal    user-guid-2
```

### Tips & Warnings
> ⚠️ Unknown apps with `Mail.Send` or `Mail.ReadWrite` permissions should be investigated and revoked.

---

## 10. Bulk Purging Phishing Emails via Compliance Search

### What it does
Uses compliance search to find and delete phishing emails from all mailboxes in the organization — the "nuclear option" when phishing lands in many inboxes.

### Real-World Example
**Scenario:** A phishing campaign with subject "Urgent: Password Reset Required" was delivered to 500 users. Purge it.

```powershell
# Connect to Security & Compliance
Connect-IPPSSession -UserPrincipalName admin@contoso.com

# Create search
New-ComplianceSearch -Name "Phish Purge - 2026-03-29" `
    -ExchangeLocation All `
    -ContentMatchQuery '(Subject:"Urgent: Password Reset Required") AND (From:attacker@evil.com)'

# Start the search
Start-ComplianceSearch -Identity "Phish Purge - 2026-03-29"

# Check results (wait for completion)
Get-ComplianceSearch -Identity "Phish Purge - 2026-03-29" | Select-Object Name, Status, Items

# Hard delete the results (irreversible!)
New-ComplianceSearchAction -SearchName "Phish Purge - 2026-03-29" -Purge -PurgeType HardDelete -Confirm:$false
```

### Sample Output
```
Name                       Status    Items
----                       ------    -----
Phish Purge - 2026-03-29   Completed 487
```

### Tips & Warnings
> ⚠️ **`HardDelete` is irreversible.** Use `SoftDelete` first to move items to Recoverable Items, then verify before hard-deleting.

> 💡 Always capture the `Items` count before purging — it goes in your incident report.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [17 — Microsoft Defender and Sentinel](17-Microsoft-Defender-and-Sentinel.md) | [README](../README.md) | [19 — Zero Trust and MS Graph](19-Zero-Trust-and-MS-Graph.md) |
