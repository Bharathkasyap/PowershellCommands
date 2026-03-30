# 25 — AppLocker and WDAC

> **Modules required:** `AppLocker` (built-in on Enterprise/Education SKUs), `ConfigCI` (for WDAC)  
> **Run as:** Local Administrator; GPO deployment requires Domain Admin or delegated GPO rights.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-AppLockerPolicy` | Retrieve AppLocker policies from local, domain, or effective stores |
| `Set-AppLockerPolicy` | Apply an AppLocker policy |
| `New-AppLockerPolicy` | Generate a policy from file information |
| `Get-AppLockerFileInformation` | Get publisher/hash/path info for files |
| `Test-AppLockerPolicy` | Test whether a file would be allowed or denied |
| AppLocker Event Analysis | Audit events 8003/8004/8006/8007 |
| `Get-CIPolicy` | Retrieve WDAC (Code Integrity) policy |
| `New-CIPolicy` | Create a new WDAC policy from system scan |
| `ConvertFrom-CIPolicy` | Convert XML policy to binary format |
| `Set-HVCIOptions` | Configure hypervisor-protected code integrity |
| Merging CI Policies | Combine multiple WDAC policies |
| Deploying WDAC via PowerShell | Apply policies to endpoints |

---

## 1. `Get-AppLockerPolicy`

### What it does
Retrieves the current AppLocker policy from different sources — local machine, effective (combined), or domain GPO. Essential for auditing what's currently enforced.

### Full Syntax
```powershell
Get-AppLockerPolicy
    -Local              # Local policy
    -Effective          # Effective merged policy
    -Ldap <String>      # Domain policy via LDAP path
    [-Xml]              # Return raw XML
```

### Real-World Example
**Scenario:** Audit the effective AppLocker policy to understand what's allowed and blocked.

```powershell
# Get effective policy
$policy = Get-AppLockerPolicy -Effective

# View rule summaries
$policy.RuleCollections | ForEach-Object {
    Write-Host "`n=== $($_.RuleCollectionType) ===" -ForegroundColor Yellow
    $_ | ForEach-Object {
        $_.PublisherConditions + $_.PathConditions + $_.HashConditions |
            Select-Object @{n='RuleType';e={$_.GetType().Name}},
            @{n='Action';e={$_.Action}},
            @{n='Description';e={$_.Description}}
    }
}

# Export to XML for backup
Get-AppLockerPolicy -Effective -Xml | Out-File "C:\audit\applocker_policy.xml"
```

### Sample Output
```
=== Exe ===
Allow — Everyone — All files in %PROGRAMFILES%\*
Allow — Everyone — All files in %WINDIR%\*
Allow — BUILTIN\Administrators — All files
Deny  — Everyone — %TEMP%\*.exe

=== Script ===
Allow — Everyone — All scripts in %PROGRAMFILES%\*
Allow — BUILTIN\Administrators — All scripts
```

### Tips & Warnings
> 💡 Always export and version-control your AppLocker policies before making changes.

> ⚠️ An empty rule collection means that type is NOT being controlled by AppLocker.

---

## 2. `Set-AppLockerPolicy` and `New-AppLockerPolicy`

### What it does
Creates and applies AppLocker rules. `New-AppLockerPolicy` generates rules from file scanning; `Set-AppLockerPolicy` applies them.

### Real-World Example
**Scenario:** Create a policy allowing only signed executables from trusted publishers.

```powershell
# Generate rules from installed applications
$fileInfo = Get-ChildItem "C:\Program Files" -Recurse -Include "*.exe" -ErrorAction SilentlyContinue |
    Get-AppLockerFileInformation -ErrorAction SilentlyContinue

$policy = $fileInfo | New-AppLockerPolicy -RuleType Publisher, Hash -User Everyone -Optimize

# Apply in audit mode first
Set-AppLockerPolicy -PolicyObject $policy -Ldap "LDAP://DC01.corp.local/CN={GUID},CN=Policies,CN=System,DC=corp,DC=local" -Merge

# Or apply locally
Set-AppLockerPolicy -PolicyObject $policy -Merge
```

### Tips & Warnings
> ⚠️ **Always start in Audit Only mode** (`-RuleAction AuditOnly`) — enforcing immediately can lock users out.

> 💡 Use `-Optimize` to merge similar rules and reduce policy size.

---

## 3. `Test-AppLockerPolicy`

### What it does
Tests whether specific files would be allowed or denied by an AppLocker policy without actually enforcing it — essential for pre-deployment validation.

### Full Syntax
```powershell
Test-AppLockerPolicy
    -PolicyObject <AppLockerPolicy>
    -Path <String[]>
    [-User <String>]
```

### Real-World Example
**Scenario:** Before enforcing a new policy, test whether critical business applications would be blocked.

```powershell
$policy = Get-AppLockerPolicy -Effective

# Test critical applications
$testPaths = @(
    "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "C:\Program Files\Company\BusinessApp.exe",
    "C:\Users\jsmith\Downloads\suspicious.exe",
    "C:\Windows\Temp\payload.exe"
)

foreach ($path in $testPaths) {
    if (Test-Path $path) {
        $result = Get-AppLockerFileInformation -Path $path |
            Test-AppLockerPolicy -PolicyObject $policy -User "CORP\jsmith"
        Write-Host "$path — $($result.PolicyDecision)" -ForegroundColor $(
            if ($result.PolicyDecision -eq 'Allowed') { 'Green' } else { 'Red' }
        )
    }
}
```

### Sample Output
```
C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE — Allowed
C:\Program Files\Company\BusinessApp.exe — Allowed
C:\Users\jsmith\Downloads\suspicious.exe — Denied
C:\Windows\Temp\payload.exe — Denied
```

### Tips & Warnings
> 💡 Test with different user contexts — admin users may have different rules than standard users.

---

## 4. AppLocker Event Analysis

### What it does
Analyzes AppLocker event logs to find blocked executions, audit violations, and potential bypass attempts.

### Analysis Script
```powershell
# Key AppLocker Event IDs:
# 8003 = File allowed (audit mode)
# 8004 = File would have been blocked (audit mode)
# 8006 = File allowed
# 8007 = File blocked (enforce mode)

# Find all blocked or would-be-blocked events
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(8004, 8007) } |
    ForEach-Object {
        [PSCustomObject]@{
            Time     = $_.TimeCreated
            EventId  = $_.Id
            Mode     = if ($_.Id -eq 8004) { "AUDIT (would block)" } else { "ENFORCED (blocked)" }
            User     = $_.Properties[1].Value
            FilePath = $_.Properties[0].Value
        }
    } | Format-Table -AutoSize -Wrap

# Summary of top blocked files
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 2000 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(8004, 8007) } |
    Group-Object { $_.Properties[0].Value } |
    Sort-Object Count -Descending |
    Select-Object Count, @{n='FilePath';e={$_.Name}} -First 20 |
    Format-Table -AutoSize
```

### Sample Output
```
Time                     EventId  Mode                    User           FilePath
----                     -------  ----                    ----           --------
3/29/2026 2:15:00 PM     8007     ENFORCED (blocked)      CORP\jsmith    C:\Users\jsmith\Downloads\tool.exe
3/29/2026 3:00:00 PM     8004     AUDIT (would block)     CORP\admin     C:\Temp\script.ps1
```

### Tips & Warnings
> ⚠️ Review 8004 events carefully before switching from Audit to Enforce mode — they show what WOULD be blocked.

---

## 5. `New-CIPolicy` — Creating WDAC Policies

### What it does
Windows Defender Application Control (WDAC) policies are more powerful than AppLocker — they apply to kernel mode drivers and are harder to bypass.

### Full Syntax
```powershell
New-CIPolicy
    -FilePath <String>          # Output XML path
    -Level <String>             # FilePublisher, Publisher, Hash, FileName, etc.
    [-Fallback <String[]>]      # Fallback rule level
    [-ScanPath <String>]        # Path to scan for creating rules
    [-UserPEs]                  # Include user-mode executables
    [-Audit]                    # Create in audit mode
```

### Real-World Example
**Scenario:** Create a WDAC baseline policy from a clean reference machine.

```powershell
# Scan the system and create a policy based on publisher and hash
New-CIPolicy -FilePath "C:\Policies\BasePolicy.xml" `
    -Level FilePublisher `
    -Fallback Hash `
    -ScanPath "C:\" `
    -UserPEs `
    -Audit

Write-Host "Policy created. Review C:\Policies\BasePolicy.xml before deploying."
```

### Tips & Warnings
> ⚠️ Always create WDAC policies in **Audit mode** first — enforcing on first deploy will likely break things.

> 💡 Use `-Level FilePublisher` for the best balance of security and manageability.

---

## 6. `ConvertFrom-CIPolicy` — Binary Conversion

### What it does
Converts a WDAC XML policy to the binary `.p7b` format required for deployment.

### Real-World Example
```powershell
# Convert XML to binary
ConvertFrom-CIPolicy -XmlFilePath "C:\Policies\BasePolicy.xml" `
    -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"

Write-Host "Binary policy created. Reboot to apply."
```

### Tips & Warnings
> ⚠️ The binary must be placed in `C:\Windows\System32\CodeIntegrity\` and requires a reboot to take effect.

---

## 7. `Set-HVCIOptions` — Hypervisor Code Integrity

### What it does
Configures Hypervisor-Protected Code Integrity (HVCI), which uses virtualization to protect the kernel from unsigned driver loading.

### Configuration Script
```powershell
# Enable HVCI in the WDAC policy
Set-HVCIOptions -Enabled -FilePath "C:\Policies\BasePolicy.xml"

# Verify HVCI status
$devGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
[PSCustomObject]@{
    HVCIRunning = 2 -in $devGuard.SecurityServicesRunning
    VBSStatus   = switch ($devGuard.VirtualizationBasedSecurityStatus) {
        0 { "Not Enabled" }; 1 { "Enabled but not running" }; 2 { "Running" }
    }
}
```

### Tips & Warnings
> ⚠️ HVCI can break unsigned or poorly signed drivers — test thoroughly before enabling.

---

## 8. Merging WDAC Policies

### What it does
Combines multiple WDAC policies into one — useful for adding supplemental rules to a base policy.

### Merge Script
```powershell
# Merge base policy with supplemental rules
Merge-CIPolicy -PolicyPaths "C:\Policies\BasePolicy.xml","C:\Policies\Supplemental_LOB.xml" `
    -OutputFilePath "C:\Policies\MergedPolicy.xml"

# Or use multiple supplemental policies (Windows 10 1903+)
# Base + supplemental model
Set-CIPolicyIdInfo -FilePath "C:\Policies\BasePolicy.xml" -BasePolicyID "{base-guid}"
Set-CIPolicyIdInfo -FilePath "C:\Policies\Supplemental_LOB.xml" -SupplementsBasePolicyID "{base-guid}"
```

### Tips & Warnings
> 💡 Use the supplemental policy model (1903+) instead of merging — it's cleaner and easier to manage.

---

## 9. Deploying WDAC via PowerShell

### What it does
Deploys WDAC policies to endpoints remotely using PowerShell remoting.

### Deployment Script
```powershell
$computers = Get-ADComputer -Filter "OperatingSystem -like '*Windows 1*'" |
    Select-Object -ExpandProperty Name

$policyPath = "\\share\policies\SIPolicy.p7b"

foreach ($computer in $computers) {
    try {
        Invoke-Command -ComputerName $computer -ScriptBlock {
            param($sourcePath)
            Copy-Item $sourcePath "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" -Force
            Write-Output "$env:COMPUTERNAME — Policy deployed"
        } -ArgumentList $policyPath
    } catch {
        Write-Host "$computer — FAILED: $_" -ForegroundColor Red
    }
}

Write-Host "Deploy complete. Reboot endpoints to enforce."
```

### Tips & Warnings
> ⚠️ Deploy in audit mode first, review events, then switch to enforce after validation.

---

## 10. Detecting AppLocker Bypasses

### What it does
Monitors for common AppLocker bypass techniques — attackers use LOLBins (Living off the Land Binaries) to execute code that AppLocker allows.

### Detection Script
```powershell
# Common AppLocker bypass binaries
$lolbins = @(
    'mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe',
    'msbuild.exe', 'installutil.exe', 'cmstp.exe', 'rundll32.exe',
    'xwizard.exe', 'ieexec.exe', 'msconfig.exe'
)

# Check process creation events (4688) for LOLBin usage
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 5000 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $newProcess = ($xml.Event.EventData.Data | Where-Object Name -eq 'NewProcessName').'#text'
        $cmdLine = ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
        $processName = Split-Path $newProcess -Leaf

        if ($processName -in $lolbins -and $cmdLine -match 'http|\\\\|base64|encode|bypass|invoke') {
            [PSCustomObject]@{
                Time     = $_.TimeCreated
                Process  = $processName
                CmdLine  = $cmdLine.Substring(0, [Math]::Min(120, $cmdLine.Length))
                User     = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
            }
        }
    } | Format-Table -AutoSize -Wrap
```

### Tips & Warnings
> ⚠️ `mshta.exe` loading remote HTA files and `regsvr32.exe /s /u /i:http://...` are classic bypass techniques.

> 💡 Block LOLBins via WDAC for stronger enforcement than AppLocker alone.

---

## 11. Building a Baseline AppLocker Policy

### What it does
Creates an AppLocker policy baseline from a clean, patched reference machine — the recommended starting point.

### Baseline Script
```powershell
# Step 1: Generate rules from the clean machine
$exeInfo = Get-ChildItem "C:\Windows","C:\Program Files","C:\Program Files (x86)" -Recurse -Include "*.exe" -ErrorAction SilentlyContinue |
    Get-AppLockerFileInformation

$scriptInfo = Get-ChildItem "C:\Windows","C:\Program Files","C:\Program Files (x86)" -Recurse -Include "*.ps1","*.bat","*.cmd","*.vbs","*.js" -ErrorAction SilentlyContinue |
    Get-AppLockerFileInformation

# Step 2: Create publisher-based rules with hash fallback
$exePolicy = $exeInfo | New-AppLockerPolicy -RuleType Publisher -RuleNamePrefix "Baseline" -User Everyone -Optimize
$scriptPolicy = $scriptInfo | New-AppLockerPolicy -RuleType Publisher -RuleNamePrefix "Baseline" -User Everyone -Optimize

# Step 3: Add default deny for temp/user directories
$denyRule = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="$(New-Guid)" Name="Deny Temp" Description="Block executables from temp folders" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%TEMP%\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

# Step 4: Export
$exePolicy | Set-AppLockerPolicy -Merge
Write-Host "Baseline AppLocker policy created in Audit mode"
```

### Tips & Warnings
> 💡 Build the baseline on a fully patched machine with all standard LOB applications installed.

> ⚠️ Audit for at least 2 weeks before switching to enforce mode.

---

## 12. Auditing Unsigned Executables

### What it does
Finds unsigned or invalidly signed executables on the system — potential indicators of tampering or malware.

### Audit Script
```powershell
$scanPaths = @("C:\Program Files", "C:\Program Files (x86)", "C:\Windows\System32")

$unsigned = foreach ($path in $scanPaths) {
    Get-ChildItem $path -Recurse -Include "*.exe","*.dll" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName
            if ($sig.Status -ne 'Valid') {
                [PSCustomObject]@{
                    Path      = $_.FullName
                    Status    = $sig.Status
                    Signer    = $sig.SignerCertificate.Subject
                    SizeKB    = [math]::Round($_.Length / 1KB, 1)
                }
            }
        }
}

Write-Host "Found $($unsigned.Count) unsigned/invalid executables"
$unsigned | Sort-Object Status | Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Focus on `NotSigned` files in system directories — these are unusual and warrant investigation.

> ⚠️ Some legitimate software is unsigned — maintain an exception list.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [24 — SOC Automation and Playbooks](24-SOC-Automation-and-Playbooks.md) | [README](../README.md) | [26 — Cloud Security Multicloud](26-Cloud-Security-Multicloud.md) |
