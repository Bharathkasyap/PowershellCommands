# 10 — Compliance and Auditing

> **Purpose:** Verify that systems meet security standards (CIS Benchmarks, NIST, SOC 2, ISO 27001), identify deviations, and generate evidence reports for auditors.  
> **Run as:** Local or Domain Administrator. Read-only audits may work with lower privileges.

---

## ⚡ Quick Reference

| Command / Technique | Purpose |
|--------------------|---------|
| `Get-Acl` | Read file/folder/registry permissions |
| `Set-Acl` | Modify file/folder/registry permissions |
| `Get-ADDefaultDomainPasswordPolicy` | Verify domain password policy settings |
| `auditpol /get /category:*` | Check Windows audit policy configuration |
| `Get-LocalGroupMember` | Verify local group membership |
| CIS Benchmark checks | Manual compliance verification against benchmarks |
| HTML Report generation | Create formatted audit reports |

---

## 1. `Get-Acl` — Read File and Folder Permissions

### What it does
Retrieves the Access Control List (ACL) for a file, folder, or registry key. An ACL is the security descriptor that defines who can read, write, execute, or delete the object. Reviewing ACLs is fundamental to compliance — many breaches exploit overly permissive file permissions.

### Full Syntax
```powershell
Get-Acl
    [-Path] <String[]>
    [-Audit]
    [-Filter <String>]
    [-Recurse]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Path` | File, folder, or registry key path |
| `-Audit` | Include SACL (System Access Control List — audit entries) |

### Real-World Example
**Scenario:** During an audit, check permissions on the `C:\Finance\Reports` folder to verify only Finance staff have access.

```powershell
# View permissions on a folder
$acl = Get-Acl -Path "C:\Finance\Reports"
$acl.Access | Select-Object IdentityReference, FileSystemRights, AccessControlType |
    Format-Table -AutoSize

# Recursively find folders with overly permissive access (Everyone or Users write access)
Get-ChildItem -Path "C:\Finance" -Recurse -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
        $acl = Get-Acl -Path $_.FullName
        $riskyPerms = $acl.Access |
            Where-Object {
                $_.IdentityReference -match 'Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users' -and
                $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                $_.AccessControlType -eq 'Allow'
            }
        if ($riskyPerms) {
            [PSCustomObject]@{
                Path      = $_.FullName
                Identity  = $riskyPerms.IdentityReference -join '; '
                Rights    = $riskyPerms.FileSystemRights -join '; '
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Sample Output
```
IdentityReference       FileSystemRights       AccessControlType
-----------------       ----------------       -----------------
CORP\Finance-Team       ReadAndExecute         Allow
CORP\Finance-Team       Write                  Allow
BUILTIN\Administrators  FullControl            Allow
Everyone                Modify                 Allow    ← Finding!
```

### Tips & Warnings
> ⚠️ **Everyone: Modify** on a Finance folder is a critical finding. Any authenticated user can modify financial reports.

> 💡 Check registry key permissions (useful for finding keys writable by non-admins):
> ```powershell
> Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\vulnservice" |
>     Select-Object -ExpandProperty Access |
>     Format-Table IdentityReference, RegistryRights, AccessControlType
> ```

---

## 2. `Set-Acl` — Modify Permissions

### What it does
Applies a new Access Control List to a file, folder, or registry key. Use after `Get-Acl` — retrieve the current ACL, modify it, then apply the changes back.

### Full Syntax
```powershell
Set-Acl
    [-Path] <String[]>
    [-AclObject] <Object>
    [-ClearCentralAccessPolicy]
    [-WhatIf]
    [-Confirm]
```

### Real-World Example
**Scenario:** Remove `Everyone` from the Finance folder and restrict access to the Finance-Team group only.

```powershell
$folderPath = "C:\Finance\Reports"
$acl = Get-Acl -Path $folderPath

# Remove Everyone
$everyoneRule = $acl.Access |
    Where-Object { $_.IdentityReference -match 'Everyone' }
foreach ($rule in $everyoneRule) {
    $acl.RemoveAccessRule($rule) | Out-Null
}

# Apply updated ACL
Set-Acl -Path $folderPath -AclObject $acl

# Verify
Write-Host "Updated ACL for $folderPath:"
(Get-Acl $folderPath).Access | Select-Object IdentityReference, FileSystemRights, AccessControlType |
    Format-Table -AutoSize
```

### Tips & Warnings
> ⚠️ Always use `-WhatIf` first when running permission changes on critical paths:
> ```powershell
> Set-Acl -Path "C:\Finance" -AclObject $acl -WhatIf
> ```

> 💡 Use `icacls.exe` for recursive permission inheritance fixes which `Set-Acl` doesn't natively support:
> ```powershell
> icacls "C:\Finance\Reports" /inheritance:r /remove Everyone /grant "CORP\Finance-Team:(OI)(CI)M"
> ```

---

## 3. `Get-ADDefaultDomainPasswordPolicy` (Compliance Check)

### What it does
Verifies the domain password policy meets your compliance standard. See [01 — Identity and Access Management](01-Identity-and-Access-Management.md#7-get-addefaultdomainpasswordpolicy) for full details. Below is a structured compliance check.

### Real-World Example — CIS Benchmark Password Policy Check

```powershell
# CIS Benchmark Level 1 requirements for password policy
$policy = Get-ADDefaultDomainPasswordPolicy

$checks = @(
    @{
        Control   = "CIS 1.1.1 - Min password length >= 14"
        Compliant = $policy.MinPasswordLength -ge 14
        Value     = "Current: $($policy.MinPasswordLength)"
    },
    @{
        Control   = "CIS 1.1.2 - Password complexity enabled"
        Compliant = $policy.ComplexityEnabled -eq $true
        Value     = "Current: $($policy.ComplexityEnabled)"
    },
    @{
        Control   = "CIS 1.1.4 - Max password age <= 365 days"
        Compliant = $policy.MaxPasswordAge.Days -le 365
        Value     = "Current: $($policy.MaxPasswordAge.Days) days"
    },
    @{
        Control   = "CIS 1.1.5 - Password history >= 24"
        Compliant = $policy.PasswordHistoryCount -ge 24
        Value     = "Current: $($policy.PasswordHistoryCount)"
    },
    @{
        Control   = "CIS 1.2.1 - Account lockout threshold <= 10"
        Compliant = $policy.LockoutThreshold -gt 0 -and $policy.LockoutThreshold -le 10
        Value     = "Current: $($policy.LockoutThreshold)"
    },
    @{
        Control   = "CIS 1.2.2 - Lockout duration >= 15 min"
        Compliant = $policy.LockoutDuration.TotalMinutes -ge 15
        Value     = "Current: $($policy.LockoutDuration.TotalMinutes) min"
    }
)

Write-Host "`n=== CIS Benchmark Password Policy Check ===" -ForegroundColor Cyan
foreach ($check in $checks) {
    $status = if ($check.Compliant) { "PASS ✓" } else { "FAIL ✗" }
    $color  = if ($check.Compliant) { "Green" } else { "Red" }
    Write-Host "$status | $($check.Control) | $($check.Value)" -ForegroundColor $color
}
```

### Sample Output
```
=== CIS Benchmark Password Policy Check ===
FAIL ✗ | CIS 1.1.1 - Min password length >= 14 | Current: 8
PASS ✓ | CIS 1.1.2 - Password complexity enabled | Current: True
PASS ✓ | CIS 1.1.4 - Max password age <= 365 days | Current: 90 days
PASS ✓ | CIS 1.1.5 - Password history >= 24 | Current: 24
PASS ✓ | CIS 1.2.1 - Account lockout threshold <= 10 | Current: 5
FAIL ✗ | CIS 1.2.2 - Lockout duration >= 15 min | Current: 0 min
```

---

## 4. `auditpol` — Audit Policy Configuration

### What it does
`auditpol.exe` configures and queries the Windows Security Audit Policy — which security events Windows generates and writes to the Security event log. Without proper audit policy, critical events (like process creation, logon failures, service installation) won't be logged, leaving you blind during incidents.

### Real-World Example
**Scenario:** Check that the required CIS audit policy settings are enabled.

```powershell
# View all audit policy categories
auditpol /get /category:*

# Check specific subcategories
auditpol /get /subcategory:"Logon","Logoff","Account Lockout","Process Creation","Security State Change"
```

### Sample Output
```
System audit policy
Category/Subcategory                      Setting
Account Logon
  Credential Validation                   Success and Failure
  Kerberos Authentication Service         No Auditing
Logon/Logoff
  Logon                                   Success and Failure
  Logoff                                  Success
  Account Lockout                         Success
Object Access
  File System                             No Auditing     ← Gap
Detailed Tracking
  Process Creation                        No Auditing     ← Gap
```

### CIS Benchmark Audit Policy Hardening

```powershell
# Enable required audit subcategories per CIS Benchmark
$auditSettings = @(
    # Category                              Success  Failure
    @("Account Logon",      "Credential Validation",                "enable", "enable"),
    @("Logon/Logoff",       "Logon",                                "enable", "enable"),
    @("Logon/Logoff",       "Logoff",                               "enable", "disable"),
    @("Logon/Logoff",       "Account Lockout",                      "enable", "enable"),
    @("Logon/Logoff",       "Special Logon",                        "enable", "disable"),
    @("Detailed Tracking",  "Process Creation",                     "enable", "enable"),
    @("Account Management", "User Account Management",              "enable", "enable"),
    @("Account Management", "Security Group Management",            "enable", "enable"),
    @("Policy Change",      "Audit Policy Change",                  "enable", "enable"),
    @("System",             "Security State Change",                "enable", "enable"),
    @("DS Access",          "Directory Service Changes",            "enable", "enable")
)

foreach ($setting in $auditSettings) {
    $subcategory = $setting[1]
    $success     = $setting[2]
    $failure     = $setting[3]
    auditpol /set /subcategory:"$subcategory" /success:$success /failure:$failure
}

Write-Host "Audit policy hardened per CIS Benchmark" -ForegroundColor Green
```

### Tips & Warnings
> 💡 Also enable command-line process creation logging (required for 4688 to include the command line):
> ```powershell
> Set-ItemProperty `
>     -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
>     -Name "ProcessCreationIncludeCmdLine_Enabled" `
>     -Value 1 -Type DWord -Force
> ```

---

## 5. `Get-LocalGroupMember` — Local Admin Audit

### What it does
See [06 — Vulnerability Management](06-Vulnerability-Management.md#4-get-localgroupmember-administrators) for full details. Below is a compliance-focused version that generates a finding if non-standard members are present.

```powershell
# Acceptable local admin accounts (customize for your environment)
$allowedAdmins = @("Administrator", "CORP\Domain Admins", "CORP\IT-Admins")

$localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name

$findings = $localAdmins | Where-Object { $_ -notin $allowedAdmins }

if ($findings) {
    Write-Host "FINDING: Unexpected local admins:" -ForegroundColor Red
    $findings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
} else {
    Write-Host "PASS: Local Administrators group is compliant" -ForegroundColor Green
}
```

---

## 6. Comprehensive CIS Benchmark Compliance Script

### What it does
Runs a series of checks against common CIS Benchmark Level 1 controls and reports compliance status for each.

```powershell
$results = [System.Collections.ArrayList]::new()

function Add-Check {
    param($Control, $Description, $Compliant, $CurrentValue, $ExpectedValue)
    $null = $results.Add([PSCustomObject]@{
        Control       = $Control
        Description   = $Description
        Status        = if ($Compliant) { "PASS" } else { "FAIL" }
        CurrentValue  = $CurrentValue
        ExpectedValue = $ExpectedValue
    })
}

# --- Firewall Checks ---
$fwProfiles = Get-NetFirewallProfile
foreach ($profile in $fwProfiles) {
    Add-Check `
        -Control "FW-$($profile.Name)" `
        -Description "Firewall enabled for $($profile.Name) profile" `
        -Compliant ($profile.Enabled -eq $true) `
        -CurrentValue $profile.Enabled `
        -ExpectedValue $true
}

# --- Defender Checks ---
$defender = Get-MpComputerStatus
Add-Check -Control "AV-001" -Description "Antivirus enabled" `
    -Compliant $defender.AntivirusEnabled -CurrentValue $defender.AntivirusEnabled -ExpectedValue $true
Add-Check -Control "AV-002" -Description "Real-time protection enabled" `
    -Compliant $defender.RealTimeProtectionEnabled `
    -CurrentValue $defender.RealTimeProtectionEnabled -ExpectedValue $true
Add-Check -Control "AV-003" -Description "AV signatures updated in last 3 days" `
    -Compliant (((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days -le 3) `
    -CurrentValue "$([int]((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days) days old" `
    -ExpectedValue "<= 3 days"

# --- Password Policy Checks ---
try {
    $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    Add-Check -Control "PW-001" -Description "Min password length >= 14" `
        -Compliant ($policy.MinPasswordLength -ge 14) `
        -CurrentValue $policy.MinPasswordLength -ExpectedValue ">= 14"
    Add-Check -Control "PW-002" -Description "Password complexity enabled" `
        -Compliant $policy.ComplexityEnabled -CurrentValue $policy.ComplexityEnabled -ExpectedValue $true
    Add-Check -Control "PW-003" -Description "Account lockout enabled" `
        -Compliant ($policy.LockoutThreshold -gt 0) `
        -CurrentValue $policy.LockoutThreshold -ExpectedValue "> 0"
} catch {
    Write-Warning "Could not query AD password policy: $_"
}

# --- SMB Signing ---
$smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smbConfig) {
    Add-Check -Control "SMB-001" -Description "SMB signing required (server)" `
        -Compliant ($smbConfig.RequireSecuritySignature -eq $true) `
        -CurrentValue $smbConfig.RequireSecuritySignature -ExpectedValue $true
    Add-Check -Control "SMB-002" -Description "SMBv1 disabled" `
        -Compliant ($smbConfig.EnableSMB1Protocol -eq $false) `
        -CurrentValue $smbConfig.EnableSMB1Protocol -ExpectedValue $false
}

# --- Output Results ---
$passes = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$fails  = ($results | Where-Object { $_.Status -eq "FAIL" }).Count

Write-Host "`n=== CIS Compliance Summary ===" -ForegroundColor Cyan
Write-Host "PASS: $passes | FAIL: $fails | Total: $($results.Count)" -ForegroundColor White

$results | Sort-Object Status | Format-Table -AutoSize
```

---

## 7. Generating HTML Audit Reports

### What it does
Converts PowerShell output into a formatted HTML report that can be shared with auditors, management, or stored as evidence. `ConvertTo-Html` turns objects into HTML tables with CSS styling.

### Real-World Example
**Scenario:** Generate an HTML security audit report combining firewall status, local admins, and AV status.

```powershell
$reportDate = Get-Date -Format "yyyy-MM-dd HH:mm"
$reportPath = "C:\audit\Security_Audit_$(Get-Date -Format 'yyyyMMdd').html"

# Collect data
$firewallStatus = Get-NetFirewallProfile | 
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

$localAdmins = Get-LocalGroupMember -Group "Administrators" | 
    Select-Object Name, ObjectClass, PrincipalSource

$avStatus = Get-MpComputerStatus | 
    Select-Object AntivirusEnabled, RealTimeProtectionEnabled, 
        AntivirusSignatureLastUpdated, AntivirusSignatureVersion

$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | 
    Select-Object -First 10 HotFixID, Description, InstalledOn

# CSS style
$style = @"
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }
  h1   { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
  h2   { color: #16213e; margin-top: 30px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background: white; }
  th   { background: #16213e; color: white; padding: 8px 12px; text-align: left; }
  td   { padding: 6px 12px; border-bottom: 1px solid #ddd; }
  tr:hover { background: #f0f0f0; }
  .pass { color: green; font-weight: bold; }
  .fail { color: red; font-weight: bold; }
  .footer { color: #888; font-size: 0.8em; margin-top: 20px; }
</style>
"@

# Build HTML
$html = @"
$style
<h1>Security Audit Report</h1>
<p>Host: <strong>$env:COMPUTERNAME</strong> | Generated: <strong>$reportDate</strong></p>

<h2>Firewall Status</h2>
$($firewallStatus | ConvertTo-Html -Fragment)

<h2>Local Administrators</h2>
$($localAdmins | ConvertTo-Html -Fragment)

<h2>Antivirus Status</h2>
$($avStatus | ConvertTo-Html -Fragment)

<h2>Recent Patches (Top 10)</h2>
$($hotfixes | ConvertTo-Html -Fragment)

<p class='footer'>Report generated by PowerShell Compliance Script v1.0</p>
"@

$html | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Report saved to: $reportPath" -ForegroundColor Green

# Open in default browser
Start-Process $reportPath
```

### Sample Output
A formatted HTML report opens in the browser showing all four sections as styled tables.

### Tips & Warnings
> 💡 Add color-coding by post-processing the HTML with a regex replace to highlight FAIL values in red:
> ```powershell
> $html = $html -replace '>FAIL<', '><span class="fail">FAIL</span><'
> $html = $html -replace '>PASS<', '><span class="pass">PASS</span><'
> ```

> 💡 For recurring audits, parameterize the script and use `Send-MailMessage` (or `Send-MgUserMail` for Microsoft 365) to email the report automatically after generation.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [09 — Log Management & SIEM](09-Log-Management-SIEM.md) | [README](../README.md) | — (End of series) |
