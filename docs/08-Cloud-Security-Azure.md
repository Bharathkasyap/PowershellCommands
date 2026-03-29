# 08 — Cloud Security: Azure

> **Modules required:** `Az` (Azure PowerShell) and `Microsoft.Graph` (MS Graph PowerShell SDK)  
> **Install:** `Install-Module Az -Scope CurrentUser` and `Install-Module Microsoft.Graph -Scope CurrentUser`  
> **Run as:** Azure AD user with appropriate roles (Security Reader minimum for read operations; Global Admin for changes)

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Connect-AzAccount` | Authenticate to Azure |
| `Get-AzADUser` | List or search Azure AD users |
| `Get-AzRoleAssignment` | List Azure RBAC role assignments |
| `Get-AzPolicyAssignment` | List Azure Policy assignments |
| `Get-AzADServicePrincipal` | List service principals (app identities) |
| `Get-MgUser` (MS Graph) | Query users including MFA registration |
| `Get-MgIdentityConditionalAccessPolicy` | Review Conditional Access policies |

---

## 1. `Connect-AzAccount`

### What it does
Authenticates your PowerShell session to Azure. Required before running any `Az` module commands. Supports interactive login, service principal authentication, managed identity, and certificate-based auth.

### Full Syntax
```powershell
Connect-AzAccount
    [-Tenant <String>]
    [-Subscription <String>]
    [-Environment <String>]
    [-ServicePrincipal]
    [-Credential <PSCredential>]
    [-CertificateThumbprint <String>]
    [-ApplicationId <String>]
```

### Real-World Example
**Scenario:** Connect to your Azure tenant to begin a cloud security audit.

```powershell
# Interactive login (opens browser for MFA)
Connect-AzAccount -Tenant "yourtenant.onmicrosoft.com"

# Service principal (for automated scripts — store creds securely)
$clientId = "your-app-id"
$tenantId = "your-tenant-id"
$secret   = ConvertTo-SecureString "your-secret" -AsPlainText -Force
$cred     = New-Object System.Management.Automation.PSCredential($clientId, $secret)
Connect-AzAccount -ServicePrincipal -Tenant $tenantId -Credential $cred

# Confirm connected context
Get-AzContext | Select-Object Account, Tenant, Subscription
```

### Sample Output
```
Account                      Tenant                       Subscription
-------                      ------                       ------------
admin@corp.onmicrosoft.com   xxxxxxxx-xxxx-xxxx-xxxx-...  Corp Production
```

### Tips & Warnings
> ⚠️ **Never hardcode secrets** in scripts. Use Azure Key Vault, environment variables, or the Secrets Management module.

> 💡 For auditing, connect with a **read-only** account (Security Reader role) to avoid accidental changes.

> 💡 Connect to MS Graph in the same session:
> ```powershell
> Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","AuditLog.Read.All","Directory.Read.All"
> ```

---

## 2. `Get-AzADUser`

### What it does
Retrieves Azure Active Directory (now Microsoft Entra ID) user accounts. Useful for auditing user properties, finding accounts with elevated privileges, or identifying inactive accounts.

### Full Syntax
```powershell
Get-AzADUser
    [-UserPrincipalName <String>]
    [-DisplayName <String>]
    [-StartsWith <String>]
    [-Filter <String>]
    [-First <UInt64>]
    [-Select <String[]>]
```

### Real-World Example
**Scenario:** Find all guest (external) accounts in your Azure AD tenant — these are often over-provisioned and should be reviewed regularly.

```powershell
# Get all guest users
Get-AzADUser -Filter "userType eq 'Guest'" |
    Select-Object DisplayName, UserPrincipalName, Mail, CreatedDateTime |
    Sort-Object CreatedDateTime -Descending |
    Format-Table -AutoSize

# Get all members (internal) with their assigned licenses
Get-AzADUser -Filter "userType eq 'Member'" |
    Select-Object DisplayName, UserPrincipalName, AccountEnabled,
        @{n='CreatedDays'; e={[int]((Get-Date) - $_.CreatedDateTime).TotalDays}} |
    Sort-Object CreatedDays -Descending |
    Format-Table -AutoSize
```

### Sample Output
```
DisplayName        UserPrincipalName                   Mail                    CreatedDateTime
-----------        ----------------                   ----                    ---------------
External Vendor    vendor@partner.com#EXT#@corp...    vendor@partner.com      2024-01-15 09:00
Old Contractor     oldcontract@agency.com#EXT#@corp.. contractor@agency.com   2022-06-01 14:00
```

### Tips & Warnings
> ⚠️ Guest accounts that are years old with no recent activity should be reviewed and removed. Stale external accounts are a common attack vector.

> 💡 Find disabled accounts in Azure AD:
> ```powershell
> Get-AzADUser -Filter "accountEnabled eq false" |
>     Select-Object DisplayName, UserPrincipalName
> ```

---

## 3. `Get-AzRoleAssignment`

### What it does
Lists all Azure RBAC (Role-Based Access Control) role assignments — who has what permissions to which Azure resources. This is the cloud equivalent of checking AD group membership for privileged access. Over-provisioned roles are a leading cause of cloud security breaches.

### Full Syntax
```powershell
Get-AzRoleAssignment
    [-SignInName <String>]
    [-ObjectId <String>]
    [-RoleDefinitionName <String>]
    [-Scope <String>]
    [-ResourceGroupName <String>]
    [-IncludeClassicAdministrators]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-SignInName` | Filter assignments for a specific user (UPN) |
| `-RoleDefinitionName` | Filter by role name (e.g., `"Owner"`) |
| `-Scope` | Filter by resource scope (subscription, resource group, resource) |
| `-IncludeClassicAdministrators` | Include legacy co-admins |

### Real-World Example
**Scenario:** Audit all Owner and Contributor role assignments at the subscription level — these are the most powerful roles.

```powershell
# List all Owner assignments (can do anything, including delete resources)
Get-AzRoleAssignment -RoleDefinitionName "Owner" |
    Select-Object DisplayName, SignInName, ObjectType, Scope |
    Format-Table -AutoSize

# List all privileged roles across all scopes
$privilegedRoles = "Owner","Contributor","User Access Administrator",
    "Security Admin","Global Administrator"

foreach ($role in $privilegedRoles) {
    $assignments = Get-AzRoleAssignment -RoleDefinitionName $role -ErrorAction SilentlyContinue
    foreach ($a in $assignments) {
        [PSCustomObject]@{
            Role        = $role
            DisplayName = $a.DisplayName
            SignInName  = $a.SignInName
            ObjectType  = $a.ObjectType
            Scope       = $a.Scope
        }
    }
} | Export-Csv "C:\audit\azure_role_assignments.csv" -NoTypeInformation
```

### Sample Output
```
DisplayName       SignInName                   ObjectType  Scope
-----------       ----------                   ----------  -----
John Smith        jsmith@corp.com              User        /subscriptions/xxxxx
Legacy Service    svc-legacy@corp.com          User        /subscriptions/xxxxx
All Staff Group   all-staff@corp.onmicrosoft   Group       /subscriptions/xxxxx
```

### Tips & Warnings
> ⚠️ **Owner assigned to a broad scope** (entire subscription) should be minimal — ideally only break-glass emergency accounts.

> ⚠️ **Groups as Owners** (like `All Staff Group`) can give subscription-level Owner to hundreds of users — a massive over-privilege. Always verify group membership.

> 💡 Apply the **Principle of Least Privilege** — replace Owner/Contributor with specific roles where possible (e.g., `Virtual Machine Contributor` instead of `Contributor`).

---

## 4. `Get-AzPolicyAssignment`

### What it does
Lists Azure Policy assignments — guardrails that enforce organizational standards across your Azure environment. Policies can audit for (or enforce) security configurations like requiring encryption, approved VM sizes, mandatory tags, or specific regions.

### Full Syntax
```powershell
Get-AzPolicyAssignment
    [-Name <String>]
    [-Scope <String>]
    [-PolicyDefinitionId <String>]
    [-IncludeDescendent]
```

### Real-World Example
**Scenario:** During a compliance review, check which security policies are assigned to the subscription and identify any non-compliant resources.

```powershell
# List all policy assignments with compliance state
Get-AzPolicyAssignment | Select-Object Name, 
    @{n='DisplayName'; e={$_.Properties.DisplayName}},
    @{n='Scope'; e={$_.Properties.Scope}},
    @{n='EnforcementMode'; e={$_.Properties.EnforcementMode}} |
    Format-Table -AutoSize

# Check compliance state for a specific policy
Get-AzPolicyState -PolicyAssignmentName "Require-Disk-Encryption" |
    Where-Object { $_.ComplianceState -eq "NonCompliant" } |
    Select-Object ResourceGroup, ResourceType, ResourceId, ComplianceState |
    Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Enable the **Microsoft Cloud Security Benchmark** (formerly Azure Security Benchmark) policy initiative — it covers 200+ security controls aligned to CIS and NIST.

---

## 5. `Get-AzADServicePrincipal`

### What it does
Lists service principals — the identities used by applications, automated pipelines, and services to access Azure resources. Service principals with elevated permissions are high-value targets for attackers. Orphaned service principals (from deleted applications) with active secrets are a common security gap.

### Full Syntax
```powershell
Get-AzADServicePrincipal
    [-DisplayName <String>]
    [-ApplicationId <Guid>]
    [-Filter <String>]
    [-First <UInt64>]
    [-Select <String[]>]
```

### Real-World Example
**Scenario:** Audit all service principals, find their role assignments, and identify any with expired or soon-to-expire credentials.

```powershell
# List all service principals
Get-AzADServicePrincipal | Select-Object DisplayName, AppId,
    @{n='CreatedDate'; e={$_.AdditionalProperties.createdDateTime}} |
    Sort-Object DisplayName |
    Format-Table -AutoSize

# Find service principals with secret credentials expiring in next 30 days
Get-AzADServicePrincipal | ForEach-Object {
    $sp = $_
    $creds = Get-AzADServicePrincipalCredential -ObjectId $sp.Id -ErrorAction SilentlyContinue
    foreach ($cred in $creds) {
        $daysLeft = [int]($cred.EndDate - (Get-Date)).TotalDays
        if ($daysLeft -le 30) {
            [PSCustomObject]@{
                ServicePrincipal = $sp.DisplayName
                CredentialType   = $cred.Type
                ExpiresIn        = "$daysLeft days"
                ExpiryDate       = $cred.EndDate
            }
        }
    }
} | Format-Table -AutoSize
```

### Tips & Warnings
> ⚠️ Service principals with **no expiry on their credentials** (or credentials expired long ago but still active) are a security risk. Rotate or remove them.

> 💡 Prefer **Managed Identities** over service principals with secrets wherever possible — managed identities have automatically rotated credentials and no secret to steal.

---

## 6. Checking MFA Registration (Microsoft Graph)

### What it does
Microsoft Graph PowerShell provides access to identity security data not available in the `Az` module — including MFA registration status and authentication methods per user.

### Real-World Example
**Scenario:** The CISO asks for a report on which users do NOT have MFA registered. This is a critical compliance gap.

```powershell
# Requires: Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","User.Read.All"

# Get all users and their authentication methods
$allUsers = Get-MgUser -All -Property "DisplayName,UserPrincipalName,AccountEnabled"

$mfaReport = foreach ($user in $allUsers) {
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
    $hasMFA   = $methods | Where-Object {
        $_.AdditionalProperties['@odata.type'] -match 'microsoftAuthenticator|phoneAuthentication|fido2|softwareOath|windowsHello'
    }

    [PSCustomObject]@{
        DisplayName       = $user.DisplayName
        UPN               = $user.UserPrincipalName
        AccountEnabled    = $user.AccountEnabled
        MFARegistered     = ($null -ne $hasMFA -and $hasMFA.Count -gt 0)
        MethodCount       = $hasMFA.Count
    }
}

# Show users WITHOUT MFA (enabled accounts only)
$mfaReport | Where-Object { $_.AccountEnabled -eq $true -and $_.MFARegistered -eq $false } |
    Sort-Object UPN |
    Export-Csv "C:\audit\users_without_mfa.csv" -NoTypeInformation

Write-Host "Users without MFA: $(($mfaReport | Where-Object { $_.AccountEnabled -and -not $_.MFARegistered }).Count)"
```

### Sample Output
```
Users without MFA: 12

(Saved to C:\audit\users_without_mfa.csv)
```

### Tips & Warnings
> ⚠️ Users without MFA are the easiest targets for credential-based attacks (phishing, password spray, credential stuffing).

> 💡 Cross-reference with sign-in logs to find which of these users have recent successful logins — those are your highest priority to remediate.

---

## 7. Conditional Access Policy Review (Microsoft Graph)

### What it does
Conditional Access (CA) policies are Azure AD's primary Zero Trust enforcement mechanism — they control when, how, and from where users can access cloud resources. Reviewing them ensures your policies actually cover the risks you think they do.

### Real-World Example
**Scenario:** Review all Conditional Access policies to identify any that are disabled, in report-only mode, or missing critical protections.

```powershell
# Requires: Connect-MgGraph -Scopes "Policy.Read.All"

Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State,
    @{n='Users'; e={
        $inc = $_.Conditions.Users.IncludeUsers
        $grp = $_.Conditions.Users.IncludeGroups
        if ($inc -contains 'All') { 'All Users' }
        elseif ($grp) { "Groups: $($grp -join ',')" }
        else { $inc -join ',' }
    }},
    @{n='Apps'; e={
        $apps = $_.Conditions.Applications.IncludeApplications
        if ($apps -contains 'All') { 'All Apps' } else { $apps -join ',' }
    }},
    @{n='Controls'; e={$_.GrantControls.BuiltInControls -join ', '}} |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
DisplayName                    State         Users         Apps     Controls
-----------                    -----         -----         ----     --------
Require MFA for All Users      enabled       All Users     All Apps mfa
Block Legacy Auth              enabled       All Users     All Apps block
Admin MFA Baseline             reportOnly    Admins        All Apps mfa
No CA Policy for Guests        disabled      Guests        All Apps
```

### Tips & Warnings
> ⚠️ **"Admin MFA Baseline" is in `reportOnly` mode** — it's NOT enforcing MFA for admins. This is a critical gap.

> ⚠️ **Disabled policies** (like the guest policy) provide zero protection.

> ⚠️ **Blocking legacy authentication** is critical — legacy protocols (SMTP AUTH, IMAP, POP3, BasicAuth) bypass MFA entirely.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [07 — Endpoint Security](07-Endpoint-Security.md) | [README](../README.md) | [09 — Log Management & SIEM](09-Log-Management-SIEM.md) |
