# 19 — Zero Trust and MS Graph

> **Modules required:** `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Users`, `Microsoft.Graph.Identity.Governance`  
> **Run as:** Global Administrator, Security Administrator, or Conditional Access Administrator.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Connect-MgGraph` | Authenticate to Microsoft Graph |
| `Get-MgIdentityConditionalAccessPolicy` | List Conditional Access policies |
| `New-MgIdentityConditionalAccessPolicy` | Create a new Conditional Access policy |
| `Get-MgUserAuthenticationMethod` | Check MFA methods for a user |
| `Get-MgRiskyUser` | List users flagged by Identity Protection |
| `Confirm-MgRiskyUserCompromised` | Mark a risky user as confirmed compromised |
| `Get-MgAuditLogSignIn` | Query Azure AD sign-in logs |
| `Get-MgAuditLogDirectoryAudit` | Query directory audit logs |
| `Get-MgApplication` | Audit app registrations |
| `Get-MgOauth2PermissionGrant` | Audit OAuth consent grants |

---

## 1. `Connect-MgGraph`

### What it does
Authenticates to Microsoft Graph API, establishing a session for all subsequent `Mg*` commands. Supports interactive, device code, certificate, and managed identity authentication.

### Full Syntax
```powershell
Connect-MgGraph
    [-Scopes <String[]>]
    [-ClientId <String>]
    [-TenantId <String>]
    [-CertificateThumbprint <String>]
    [-AccessToken <SecureString>]
    [-UseDeviceCode]
    [-ContextScope <String>]       # Process or CurrentUser
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Scopes` | Permissions to request (e.g., `"User.Read.All"`, `"Policy.Read.All"`) |
| `-ClientId` | App registration ID for app-only authentication |
| `-TenantId` | Azure AD tenant ID |
| `-CertificateThumbprint` | Certificate for unattended app-only auth |
| `-UseDeviceCode` | Device code flow for environments without a browser |

### Real-World Example
**Scenario:** Connect with delegated permissions for a security audit.

```powershell
Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","AuditLog.Read.All",
    "IdentityRiskyUser.Read.All","Directory.Read.All"

# Verify connection
Get-MgContext | Select-Object Account, TenantId, Scopes
```

### Sample Output
```
Account              : admin@contoso.com
TenantId             : a1b2c3d4-e5f6-7890-abcd-ef1234567890
Scopes               : {User.Read.All, Policy.Read.All, AuditLog.Read.All, ...}
```

### Tips & Warnings
> 💡 For automation, use certificate-based app-only auth:
> ```powershell
> Connect-MgGraph -ClientId "app-guid" -TenantId "tenant-guid" -CertificateThumbprint "thumbprint"
> ```

> ⚠️ Request only the scopes you need — principle of least privilege applies to API permissions too.

---

## 2. Conditional Access — List and Review Policies

### What it does
Retrieves all Conditional Access policies in your tenant — essential for Zero Trust posture assessment.

### Full Syntax
```powershell
Get-MgIdentityConditionalAccessPolicy
    [-Filter <String>]
    [-All]
    [-Property <String[]>]
```

### Real-World Example
**Scenario:** Audit all Conditional Access policies and identify any in report-only mode that should be enforced.

```powershell
$policies = Get-MgIdentityConditionalAccessPolicy -All
$policies | Select-Object DisplayName, State,
    @{n='IncludeUsers';e={$_.Conditions.Users.IncludeUsers -join ', '}},
    @{n='GrantControls';e={$_.GrantControls.BuiltInControls -join ', '}} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
DisplayName                    State           IncludeUsers  GrantControls
-----------                    -----           ------------  -------------
Require MFA for All Users      enabled         All           mfa
Block Legacy Auth              enabled         All           block
Require Compliant Device       enabledForReportingButNotEnforced  All  compliantDevice
```

### Tips & Warnings
> ⚠️ Policies in `enabledForReportingButNotEnforced` are NOT protecting you — review and enable them.

> 💡 Export policy configurations for change management:
> ```powershell
> $policies | ConvertTo-Json -Depth 10 | Out-File C:\audit\ca_policies.json
> ```

---

## 3. Creating Conditional Access Policies

### What it does
Programmatically creates Conditional Access policies — enabling infrastructure-as-code for your Zero Trust posture.

### Real-World Example
**Scenario:** Create a policy requiring MFA for all admin roles.

```powershell
$params = @{
    DisplayName = "Require MFA for Admin Roles"
    State = "enabledForReportingButNotEnforced"
    Conditions = @{
        Users = @{
            IncludeRoles = @(
                "62e90394-69f5-4237-9190-012177145e10"  # Global Admin
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"  # SharePoint Admin
                "29232cdf-9323-42fd-ade2-1d097af3e4de"  # Exchange Admin
            )
        }
        Applications = @{ IncludeApplications = @("All") }
    }
    GrantControls = @{
        BuiltInControls = @("mfa")
        Operator = "OR"
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

### Tips & Warnings
> ⚠️ Always create policies in `enabledForReportingButNotEnforced` (report-only) first, then enable after validation.

> 💡 Use role template IDs (GUIDs) — find them with `Get-MgDirectoryRoleTemplate`.

---

## 4. MFA Status — `Get-MgUserAuthenticationMethod`

### What it does
Lists all authentication methods registered by a user — phone, authenticator app, FIDO2 key, email, etc. Essential for MFA gap analysis.

### Full Syntax
```powershell
Get-MgUserAuthenticationMethod
    -UserId <String>
```

### Real-World Example
**Scenario:** Find all users who do NOT have MFA registered.

```powershell
$users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName
$noMfa = foreach ($user in $users) {
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
    # Password is always present; MFA means >1 method
    if ($methods.Count -le 1) {
        [PSCustomObject]@{
            User     = $user.DisplayName
            UPN      = $user.UserPrincipalName
            Methods  = $methods.Count
        }
    }
}
$noMfa | Format-Table -AutoSize
Write-Host "Users without MFA: $($noMfa.Count) / $($users.Count)"
```

### Sample Output
```
User           UPN                       Methods
----           ---                       -------
Guest User     guest@contoso.com         1
Service Acct   svc@contoso.com           1

Users without MFA: 2 / 347
```

### Tips & Warnings
> ⚠️ Users with only 1 method (password) are **not protected by MFA** — prioritize enrollment.

---

## 5. Identity Protection — Risky Users

### What it does
Queries Azure AD Identity Protection for users flagged as risky based on sign-in anomalies, leaked credentials, or suspicious activity.

### Full Syntax
```powershell
Get-MgRiskyUser
    [-Filter <String>]
    [-All]
    [-Property <String[]>]
```

### Real-World Example
**Scenario:** Get all high-risk users for investigation.

```powershell
$riskyUsers = Get-MgRiskyUser -Filter "riskLevel eq 'high'" -All
$riskyUsers | Select-Object UserDisplayName, UserPrincipalName, RiskLevel,
    RiskState, RiskLastUpdatedDateTime, RiskDetail |
    Format-Table -AutoSize
```

### Sample Output
```
UserDisplayName  UserPrincipalName      RiskLevel  RiskState  RiskLastUpdatedDateTime   RiskDetail
---------------  -----------------      ---------  ---------  -----------------------   ----------
John Smith       jsmith@contoso.com     high       atRisk     3/29/2026 1:00:00 AM      none
Admin User       admin@contoso.com      high       atRisk     3/28/2026 11:00:00 PM     none
```

### Tips & Warnings
> 💡 Confirm or dismiss risk after investigation:
> ```powershell
> # Confirm compromised — forces password reset
> Confirm-MgRiskyUserCompromised -UserIds @("user-guid")
> # Dismiss — false positive
> Invoke-MgDismissRiskyUser -UserIds @("user-guid")
> ```

---

## 6. PIM (Privileged Identity Management) via Graph

### What it does
Manages just-in-time privileged role assignments — list eligible assignments, activate roles, and audit activations.

### Real-World Example
**Scenario:** List all eligible PIM role assignments in the tenant.

```powershell
$eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
foreach ($assignment in $eligibleAssignments) {
    $role = Get-MgDirectoryRole -DirectoryRoleId $assignment.RoleDefinitionId -ErrorAction SilentlyContinue
    $user = Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        User       = $user.DisplayName
        Role       = $role.DisplayName
        StartDate  = $assignment.ScheduleInfo.StartDateTime
        EndDate    = $assignment.ScheduleInfo.Expiration.EndDateTime
    }
} | Format-Table -AutoSize
```

### Sample Output
```
User           Role                StartDate               EndDate
----           ----                ---------               -------
Jane Admin     Global Administrator 2026-01-01 00:00:00    2026-07-01 00:00:00
SOC Analyst    Security Reader      2026-03-01 00:00:00    2026-09-01 00:00:00
```

### Tips & Warnings
> 💡 Require justification and approval for high-privilege role activations in PIM settings.

---

## 7. App Registrations Audit

### What it does
Reviews all Azure AD app registrations for security issues — expired credentials, excessive permissions, or unused apps.

### Real-World Example
**Scenario:** Find app registrations with expiring or expired credentials.

```powershell
$apps = Get-MgApplication -All -Property DisplayName, AppId, PasswordCredentials, KeyCredentials
$today = Get-Date
$apps | ForEach-Object {
    $creds = @($_.PasswordCredentials) + @($_.KeyCredentials)
    foreach ($cred in $creds) {
        [PSCustomObject]@{
            AppName   = $_.DisplayName
            AppId     = $_.AppId
            CredType  = if ($cred.KeyId -and $cred.Type) { "Certificate" } else { "Secret" }
            ExpiresOn = $cred.EndDateTime
            Status    = if ($cred.EndDateTime -lt $today) { "EXPIRED" }
                        elseif ($cred.EndDateTime -lt $today.AddDays(30)) { "EXPIRING SOON" }
                        else { "Valid" }
        }
    }
} | Where-Object { $_.Status -ne "Valid" } | Format-Table -AutoSize
```

### Sample Output
```
AppName          AppId       CredType    ExpiresOn                Status
-------          -----       --------    ---------                ------
Legacy App       abc-123     Secret      2026-02-15 00:00:00      EXPIRED
CRM Integration  def-456     Certificate 2026-04-10 00:00:00      EXPIRING SOON
```

### Tips & Warnings
> ⚠️ Expired credentials on active apps cause outages. Expiring credentials are a security risk if not rotated.

---

## 8. OAuth Consent Grants Audit

### What it does
Reviews all OAuth permission grants in the tenant to detect overly permissive or malicious consent grants.

### Real-World Example
**Scenario:** Find all admin-consented OAuth grants with high-privilege permissions.

```powershell
$grants = Get-MgOauth2PermissionGrant -All | Where-Object { $_.ConsentType -eq "AllPrincipals" }
foreach ($grant in $grants) {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId
    [PSCustomObject]@{
        App     = $sp.DisplayName
        Scope   = $grant.Scope
        Type    = "Admin Consent"
    }
} | Where-Object { $_.Scope -match "ReadWrite|FullControl|All" } | Format-Table -AutoSize
```

### Sample Output
```
App                  Scope                                    Type
---                  -----                                    ----
Unknown App          Directory.ReadWrite.All Mail.Send        Admin Consent
HR Portal            User.ReadWrite.All                       Admin Consent
```

### Tips & Warnings
> ⚠️ `Directory.ReadWrite.All` with admin consent is extremely dangerous — review the app's legitimacy.

---

## 9. Sign-in Logs — `Get-MgAuditLogSignIn`

### What it does
Queries Azure AD sign-in logs with powerful filtering — essential for investigating compromised accounts, detecting impossible travel, and monitoring authentication patterns.

### Full Syntax
```powershell
Get-MgAuditLogSignIn
    [-Filter <String>]
    [-Top <Int32>]
    [-All]
    [-Property <String[]>]
```

### Real-World Example
**Scenario:** Investigate failed sign-ins for a specific user in the last 48 hours.

```powershell
$since = (Get-Date).AddHours(-48).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'jsmith@contoso.com' and status/errorCode ne 0 and createdDateTime gt $since" -All |
    Select-Object CreatedDateTime, UserPrincipalName,
        @{n='IP';e={$_.IPAddress}},
        @{n='Location';e={"$($_.Location.City), $($_.Location.CountryOrRegion)"}},
        @{n='Error';e={$_.Status.ErrorCode}},
        @{n='App';e={$_.AppDisplayName}} |
    Format-Table -AutoSize
```

### Sample Output
```
CreatedDateTime           UserPrincipalName      IP              Location         Error  App
---------------           -----------------      --              --------         -----  ---
3/29/2026 2:00:00 AM      jsmith@contoso.com     185.220.101.5   Moscow, RU       50126  Azure Portal
3/29/2026 2:01:00 AM      jsmith@contoso.com     185.220.101.5   Moscow, RU       50126  Azure Portal
3/29/2026 2:02:00 AM      jsmith@contoso.com     185.220.101.5   Moscow, RU       50126  Azure Portal
```

### Tips & Warnings
> ⚠️ Multiple failed sign-ins from an unusual location is a brute-force indicator — correlate with Identity Protection.

> 💡 Error code `50126` = invalid password. Error `50053` = account locked. Error `50076` = MFA required.

---

## 10. Directory Audit Logs — `Get-MgAuditLogDirectoryAudit`

### What it does
Queries the Azure AD directory audit log for administrative changes — role assignments, app registrations, group modifications, and policy changes.

### Real-World Example
**Scenario:** Find all role assignment changes in the last 7 days.

```powershell
$since = (Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add member to role' and activityDateTime gt $since" -All |
    Select-Object ActivityDateTime, ActivityDisplayName,
        @{n='User';e={$_.InitiatedBy.User.UserPrincipalName}},
        @{n='Target';e={$_.TargetResources[0].DisplayName}},
        @{n='Role';e={$_.TargetResources[0].ModifiedProperties |
            Where-Object { $_.DisplayName -eq 'Role.DisplayName' } |
            Select-Object -ExpandProperty NewValue}} |
    Format-Table -AutoSize
```

### Sample Output
```
ActivityDateTime          ActivityDisplayName  User                Target         Role
----------------          -------------------  ----                ------         ----
3/28/2026 3:00:00 PM      Add member to role   admin@contoso.com   Jane Doe       Global Administrator
```

### Tips & Warnings
> ⚠️ Unexpected `Global Administrator` role assignments are a critical alert — investigate immediately.

> 💡 Combine sign-in logs and audit logs for a complete picture of a compromised account's activity.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [18 — Exchange and Email Security](18-Exchange-and-Email-Security.md) | [README](../README.md) | [20 — Forensics and Memory Analysis](20-Forensics-and-Memory-Analysis.md) |
