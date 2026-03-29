# 02 — GPO Management

> **Module required:** `GroupPolicy` (part of RSAT — Group Policy Management Tools)  
> **Run as:** Domain Admin or user with delegated GPO management rights.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-GPO` | List or retrieve a specific Group Policy Object |
| `New-GPO` | Create a new, empty GPO |
| `Set-GPLink` | Link (or unlink) a GPO to an OU, domain, or site |
| `Invoke-GPUpdate` | Force an immediate Group Policy refresh on a remote computer |
| `Get-GPOReport` | Generate an HTML or XML report of a GPO's settings |
| `Backup-GPO` | Back up one or all GPOs to a folder |
| `Restore-GPO` | Restore a GPO from a backup |
| `Get-GPResultantSetOfPolicy` | Show the effective ("resultant") policy applied to a user/computer |

---

## 1. `Get-GPO`

### What it does
Retrieves information about one or all Group Policy Objects in the domain. Think of GPOs as configuration templates pushed to computers and users — `Get-GPO` lets you see what templates exist and their basic properties.

### Full Syntax
```powershell
Get-GPO
    [-Name] <String>
    [-Domain <String>]
    [-Server <String>]

# OR list all GPOs:
Get-GPO -All
    [-Domain <String>]
    [-Server <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Name` | The friendly name of the GPO to retrieve |
| `-All` | Returns all GPOs in the domain |
| `-Guid` | Alternatively identify the GPO by its GUID |
| `-Domain` | Target domain (defaults to current domain) |
| `-Server` | Target a specific Domain Controller |

### Real-World Example
**Scenario:** You need to audit all GPOs in the domain and find ones that haven't been modified recently (potentially orphaned or stale).

```powershell
Get-GPO -All | Select-Object DisplayName, GpoStatus, ModificationTime, Id |
    Sort-Object ModificationTime |
    Format-Table -AutoSize
```

### Sample Output
```
DisplayName                  GpoStatus    ModificationTime        Id
-----------                  ---------    ----------------        --
Default Domain Policy        AllSettingsEnabled  1/5/2025 9:00:00 AM   {31B2...}
Disable USB Storage          AllSettingsEnabled  6/12/2025 2:30:00 PM  {A1C4...}
Workstation Security         AllSettingsEnabled  3/20/2026 11:00:00 AM {5F3D...}
```

### Tips & Warnings
> 💡 `GpoStatus` can be `AllSettingsEnabled`, `UserSettingsDisabled`, `ComputerSettingsDisabled`, or `AllSettingsDisabled`. GPOs with `AllSettingsDisabled` have no effect — flag them for review.

> 💡 Export the list to CSV for documentation:
> ```powershell
> Get-GPO -All | Select-Object DisplayName, GpoStatus, ModificationTime |
>     Export-Csv -Path C:\audit\gpo_inventory.csv -NoTypeInformation
> ```

---

## 2. `New-GPO`

### What it does
Creates a new, empty Group Policy Object in the domain. The new GPO is unlinked by default — you must then link it to an OU with `Set-GPLink` to have it take effect.

### Full Syntax
```powershell
New-GPO
    [-Name] <String>
    [-Comment <String>]
    [-Domain <String>]
    [-Server <String>]
    [-StarterGpoName <String>]
    [-StarterGpoGuid <Guid>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Name` | Unique friendly name for the new GPO |
| `-Comment` | Description/purpose for documentation |
| `-StarterGpoName` | Base the new GPO on an existing Starter GPO template |

### Real-World Example
**Scenario:** You are deploying a new security baseline for workstations. You create a new GPO and then link it to the Workstations OU.

```powershell
# Create the GPO
$gpo = New-GPO -Name "SEC-Workstation-Baseline-2026" `
               -Comment "CIS Level 1 Workstation Baseline - Created 2026-03-29"

# Link it to the Workstations OU (link is disabled by default to allow safe testing)
Set-GPLink -Name "SEC-Workstation-Baseline-2026" `
           -Target "OU=Workstations,DC=corp,DC=local" `
           -LinkEnabled No

Write-Host "GPO created: $($gpo.DisplayName) | ID: $($gpo.Id)"
```

### Sample Output
```
GPO created: SEC-Workstation-Baseline-2026 | ID: {4A2B1C3D-...}
```

### Tips & Warnings
> 💡 Best practice: create the link **disabled**, test in a pilot OU first, then enable the link in production.

> 💡 After creating a GPO, use the Group Policy Management Console (GPMC) or `Set-GPRegistryValue` / `Set-GPPermissions` to configure its settings via PowerShell.

---

## 3. `Set-GPLink`

### What it does
Links an existing GPO to an Active Directory container (OU, domain, or site), enabling the GPO's settings to apply to objects in that container. You can also use it to change the link's order (priority), enable/disable the link, or set it as "enforced."

### Full Syntax
```powershell
Set-GPLink
    [-Name] <String>
    [-Target] <String>
    [-LinkEnabled <EnableLink>]
    [-Enforced <EnforceLink>]
    [-Order <Int32>]
    [-Domain <String>]
    [-Server <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Name` | Name of the GPO to link |
| `-Target` | Distinguished Name of the OU, domain, or site |
| `-LinkEnabled` | `Yes` or `No` — enable or disable the link without deleting it |
| `-Enforced` | `Yes` makes the GPO apply even if a child OU has "Block Inheritance" |
| `-Order` | Processing order — lower numbers are processed last (highest precedence) |

### Real-World Example
**Scenario:** You previously created and tested `SEC-Workstation-Baseline-2026` on a pilot OU. Now you're enabling the link on the production Workstations OU and setting enforcement.

```powershell
Set-GPLink -Name "SEC-Workstation-Baseline-2026" `
           -Target "OU=Workstations,DC=corp,DC=local" `
           -LinkEnabled Yes `
           -Enforced Yes `
           -Order 1
```

### Tips & Warnings
> ⚠️ **Enforced GPOs override Block Inheritance.** Use sparingly — it can override intentional OU-level exceptions.

> 💡 To remove a link entirely (without deleting the GPO), use `Remove-GPLink`:
> ```powershell
> Remove-GPLink -Name "Old-Policy" -Target "OU=Workstations,DC=corp,DC=local"
> ```

---

## 4. `Invoke-GPUpdate`

### What it does
Forces an immediate Group Policy refresh on a local or remote computer. Normally, Group Policy updates in the background every 90 minutes (± 30 min random offset). `Invoke-GPUpdate` is the PowerShell equivalent of `gpupdate /force`.

### Full Syntax
```powershell
Invoke-GPUpdate
    [[-Computer] <String[]>]
    [-RandomDelayInMinutes <Int32>]
    [-Force]
    [-LogOff]
    [-Boot]
    [-Target <GpoUpdateTarget>]
    [-AsJob]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Computer` | Target computer(s) — omit for local machine |
| `-Force` | Reapplies all settings even if unchanged |
| `-Target` | `Computer`, `User`, or both |
| `-RandomDelayInMinutes` | Staggers the update across multiple machines (reduce DC load) |
| `-LogOff` | Log off users after update (needed for user policy changes) |
| `-Boot` | Restart the computer (needed for some computer policy changes) |

### Real-World Example
**Scenario:** You just enabled a new firewall rule GPO. You need it applied immediately on all computers in the Finance OU without waiting 90 minutes.

```powershell
# Get all computers in the Finance OU
$computers = Get-ADComputer -Filter * -SearchBase "OU=Finance,DC=corp,DC=local" |
    Select-Object -ExpandProperty Name

# Force GP update on all of them
Invoke-GPUpdate -Computer $computers -Force -RandomDelayInMinutes 5
```

### Sample Output
```
(Runs silently — check Event Viewer on each computer for Group Policy operational logs)
```

### Tips & Warnings
> 💡 For large environments, use `-RandomDelayInMinutes` to spread load across your DCs.

> ⚠️ Requires Windows Remote Management (WinRM) to be enabled on target computers. Test with `Test-WSMan <computername>` first.

---

## 5. `Get-GPOReport`

### What it does
Generates a detailed report of a GPO's settings in HTML or XML format. HTML reports are human-readable and useful for documentation and audits. XML reports are machine-readable for parsing with scripts.

### Full Syntax
```powershell
Get-GPOReport
    [-Name] <String>
    [-ReportType] <ReportType>
    [-Path <String>]
    [-Domain <String>]
    [-Server <String>]

# ReportType: Html | Xml
```

### Real-World Example
**Scenario:** You need to document the settings in `Default Domain Policy` for your security audit package.

```powershell
# Generate HTML report
Get-GPOReport -Name "Default Domain Policy" -ReportType Html `
              -Path "C:\audit\DefaultDomainPolicy_Report.html"

# Generate reports for ALL GPOs
Get-GPO -All | ForEach-Object {
    $safeName = $_.DisplayName -replace '[\\/:*?"<>|]', '_'
    Get-GPOReport -Name $_.DisplayName -ReportType Html `
                  -Path "C:\audit\GPO_Reports\$safeName.html"
}

Write-Host "Reports saved to C:\audit\"
```

### Tips & Warnings
> 💡 Open the HTML report in a browser for a clear, formatted view of all configured settings — it mirrors what you'd see in GPMC.

> 💡 Parse XML reports with PowerShell for automated compliance checking:
> ```powershell
> [xml]$report = Get-GPOReport -Name "Default Domain Policy" -ReportType Xml
> $report.GPO.Computer.ExtensionData
> ```

---

## 6. `Backup-GPO`

### What it does
Creates a backup of one or all Group Policy Objects to a specified folder. Critical for change management — always back up before modifying a GPO, especially in production.

### Full Syntax
```powershell
Backup-GPO
    [-Name] <String>
    [-Path] <String>
    [-Comment <String>]
    [-Domain <String>]

# Back up all GPOs:
Backup-GPO -All -Path <String> [-Comment <String>]
```

### Real-World Example
**Scenario:** Before applying a new security baseline, you back up all GPOs as a safety net.

```powershell
$backupPath = "C:\GPO-Backups\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $backupPath -Force

Backup-GPO -All -Path $backupPath -Comment "Pre-baseline backup $(Get-Date -Format 'yyyy-MM-dd')"

Write-Host "All GPOs backed up to: $backupPath"
```

### Sample Output
```
DisplayName                  GpoId                                 Id
-----------                  -----                                 --
Default Domain Policy        {31B2F340-016D-11D2-945F-00C04FB984F9} {A1C4...}
Workstation Security         {5F3D...}                             {B2D5...}
SEC-Workstation-Baseline-2026 {4A2B...}                            {C3E6...}
```

### Tips & Warnings
> 💡 **Automate weekly backups** with a scheduled task to protect against accidental modification.

> ⚠️ Backups include all GPO settings but **not** the GPO links. Document your links separately using `Get-GPO -All | Get-GPOReport`.

---

## 7. `Restore-GPO`

### What it does
Restores a previously backed-up Group Policy Object from a backup folder. If something breaks after a GPO change, this is your rollback mechanism.

### Full Syntax
```powershell
Restore-GPO
    [-Name] <String>
    [-Path] <String>
    [-Domain <String>]
    [-Server <String>]

# Restore by backup ID:
Restore-GPO -BackupId <Guid> -Path <String>
```

### Real-World Example
**Scenario:** After pushing a change to `Workstation Security` GPO, users report they can't access mapped drives. You restore the previous backup.

```powershell
Restore-GPO -Name "Workstation Security" `
            -Path "C:\GPO-Backups\2026-03-28"

# Force update to apply restored settings
Invoke-GPUpdate -Force
```

### Tips & Warnings
> ⚠️ Restoring overwrites the current GPO settings. Confirm the backup path contains the correct version before running.

> 💡 To list all backups in a folder and their timestamps:
> ```powershell
> Get-ChildItem "C:\GPO-Backups" -Recurse -Filter "bkupInfo.xml" | ForEach-Object {
>     [xml]$info = Get-Content $_.FullName
>     [PSCustomObject]@{
>         GPOName    = $info.BackupInst.GPODisplayName.'#cdata-section'
>         BackupTime = $info.BackupInst.BackupTime.'#cdata-section'
>         BackupPath = $_.DirectoryName
>     }
> } | Sort-Object BackupTime -Descending | Format-Table
> ```

---

## 8. `Get-GPResultantSetOfPolicy`

### What it does
Calculates and displays the **effective** (resultant) Group Policy settings that actually apply to a specific user and/or computer, after all inheritance, precedence, and filtering rules are resolved. This is the PowerShell equivalent of `gpresult /R` or `rsop.msc`.

### Full Syntax
```powershell
Get-GPResultantSetOfPolicy
    [-ReportType] <ReportType>
    [-Path] <String>
    [-Computer <String>]
    [-User <String>]
    [-Domain <String>]
    [-Server <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-ReportType` | `Html` or `Xml` |
| `-Path` | File path to save the report |
| `-Computer` | Computer to analyze (default: local) |
| `-User` | User account to analyze |

### Real-World Example
**Scenario:** A user says the USB restriction policy is not blocking them. You generate an RSoP report to see exactly which policies are applying.

```powershell
Get-GPResultantSetOfPolicy -ReportType Html `
    -Computer "PC-FINANCE-01" `
    -User "jsmith" `
    -Path "C:\audit\RSoP_jsmith_PC-FINANCE-01.html"

Write-Host "RSoP report generated — open in browser"
```

### Tips & Warnings
> ⚠️ Requires WinRM access to the remote computer and sufficient rights to query RSoP data.

> 💡 Cross-reference the RSoP report with `Get-GPO -All` to identify which specific GPO is setting (or not setting) a value.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [01 — Identity and Access Management](01-Identity-and-Access-Management.md) | [README](../README.md) | [03 — Network Security](03-Network-Security.md) |
