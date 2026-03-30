# 26 — Cloud Security Multicloud

> **Modules required:** `AWSPowerShell.NetCore` or `AWS.Tools.*`, `Az.*`, `GoogleCloud` (gcloud CLI)  
> **Run as:** IAM users/roles with Security Audit permissions in each cloud provider.

---

## ⚡ Quick Reference

| Command / Technique | Cloud | Purpose |
|---------------------|-------|---------|
| `Get-IAMUser` | AWS | Audit IAM users and access keys |
| `Get-S3BucketAcl` | AWS | Detect public S3 buckets |
| `Get-EC2SecurityGroup` | AWS | Find open security group rules |
| `Get-CTTrail` | AWS | Audit CloudTrail configuration |
| `Get-GD2Finding` | AWS | Retrieve GuardDuty findings |
| `Get-SHUBFinding` | AWS | Get Security Hub findings |
| `Get-AzSecurityAlert` | Azure | Get Defender for Cloud alerts |
| `Get-AzSecurityTask` | Azure | Get security recommendations |
| `gcloud` from PowerShell | GCP | GCP resource auditing |
| Cross-Cloud IAM Audit | Multi | Compare permissions across clouds |
| Public Storage Detection | Multi | Find publicly accessible storage |
| Privilege Escalation Detection | Multi | Detect dangerous IAM configurations |

---

## 1. AWS IAM User Audit — `Get-IAMUser`

### What it does
Lists all IAM users in your AWS account with their access key age, MFA status, and last activity — essential for identifying stale or over-privileged accounts.

### Full Syntax
```powershell
Get-IAMUser [-UserName <String>] [-PathPrefix <String>]
Get-IAMAccessKey -UserName <String>
Get-IAMMFADevice -UserName <String>
```

### Real-World Example
**Scenario:** Audit all IAM users for missing MFA and old access keys.

```powershell
# Import AWS module
Import-Module AWSPowerShell.NetCore
Set-AWSCredential -ProfileName "security-audit"

$users = Get-IAMUser
$audit = foreach ($user in $users) {
    $keys = Get-IAMAccessKey -UserName $user.UserName
    $mfa = Get-IAMMFADevice -UserName $user.UserName -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        UserName    = $user.UserName
        Created     = $user.CreateDate
        LastActive  = $user.PasswordLastUsed
        MFAEnabled  = ($mfa.Count -gt 0)
        AccessKeys  = $keys.Count
        OldestKey   = ($keys | Sort-Object CreateDate | Select-Object -First 1).CreateDate
        KeyAgeDays  = if ($keys) { ((Get-Date) - ($keys | Sort-Object CreateDate | Select-Object -First 1).CreateDate).Days } else { "N/A" }
    }
}

# Flag issues
$audit | Where-Object { $_.MFAEnabled -eq $false -or $_.KeyAgeDays -gt 90 } |
    Format-Table -AutoSize
```

### Sample Output
```
UserName      Created              LastActive            MFAEnabled  AccessKeys  KeyAgeDays
--------      -------              ----------            ----------  ----------  ----------
admin         2024-01-15           2026-03-29            False       2           800
deploy-svc    2025-06-01                                 False       1           302
dev-user      2025-11-01           2026-03-28            True        1           149
```

### Tips & Warnings
> ⚠️ **`admin` has no MFA and 800-day-old keys** — this is a critical finding.

> 💡 AWS best practice: rotate access keys every 90 days and require MFA for all human users.

---

## 2. Public S3 Bucket Detection — `Get-S3BucketAcl`

### What it does
Scans all S3 buckets for public access — one of the most common cloud security misconfigurations.

### Detection Script
```powershell
$buckets = Get-S3Bucket
$publicBuckets = foreach ($bucket in $buckets) {
    $acl = Get-S3BucketACL -BucketName $bucket.BucketName

    # Check for public grants
    $publicGrants = $acl.Grants | Where-Object {
        $_.Grantee.URI -match 'AllUsers|AuthenticatedUsers'
    }

    # Check Block Public Access settings
    $blockPublic = Get-S3PublicAccessBlock -BucketName $bucket.BucketName -ErrorAction SilentlyContinue

    if ($publicGrants -or ($blockPublic -and -not $blockPublic.BlockPublicAcls)) {
        [PSCustomObject]@{
            Bucket       = $bucket.BucketName
            PublicACL    = ($publicGrants.Count -gt 0)
            BlockPublic  = if ($blockPublic) { $blockPublic.BlockPublicAcls } else { "NOT SET" }
            GrantDetails = ($publicGrants | ForEach-Object { "$($_.Grantee.URI):$($_.Permission)" }) -join '; '
        }
    }
}

if ($publicBuckets) {
    Write-Host "[ALERT] Public S3 buckets found:" -ForegroundColor Red
    $publicBuckets | Format-Table -AutoSize
} else {
    Write-Host "[OK] No public S3 buckets" -ForegroundColor Green
}
```

### Sample Output
```
[ALERT] Public S3 buckets found:

Bucket               PublicACL  BlockPublic  GrantDetails
------               ---------  -----------  ------------
company-backups      True       NOT SET      AllUsers:READ
marketing-assets     True       False        AllUsers:READ; AllUsers:READ_ACP
```

### Tips & Warnings
> ⚠️ **Public S3 buckets with sensitive data = data breach.** Enable S3 Block Public Access at the account level.

---

## 3. Open Security Groups — `Get-EC2SecurityGroup`

### What it does
Finds AWS security groups with overly permissive rules — particularly `0.0.0.0/0` (open to the internet).

### Detection Script
```powershell
$secGroups = Get-EC2SecurityGroup
$openRules = foreach ($sg in $secGroups) {
    foreach ($rule in $sg.IpPermissions) {
        $openCidrs = $rule.IpRanges | Where-Object { $_.CidrIp -eq '0.0.0.0/0' }
        $openIpv6 = $rule.Ipv6Ranges | Where-Object { $_.CidrIpv6 -eq '::/0' }

        if ($openCidrs -or $openIpv6) {
            [PSCustomObject]@{
                GroupName  = $sg.GroupName
                GroupId    = $sg.GroupId
                VpcId      = $sg.VpcId
                Port       = if ($rule.FromPort -eq $rule.ToPort) { $rule.FromPort } else { "$($rule.FromPort)-$($rule.ToPort)" }
                Protocol   = $rule.IpProtocol
                OpenTo     = "0.0.0.0/0 (INTERNET)"
                Risk       = if ($rule.FromPort -in @(22,3389,445,1433,3306,5432)) { "CRITICAL" } else { "HIGH" }
            }
        }
    }
}

$openRules | Sort-Object Risk -Descending | Format-Table -AutoSize
```

### Sample Output
```
GroupName       GroupId       VpcId          Port   Protocol  OpenTo               Risk
---------       -------       -----          ----   --------  ------               ----
default         sg-abc123     vpc-xyz789     22     tcp       0.0.0.0/0 (INTERNET) CRITICAL
web-servers     sg-def456     vpc-xyz789     443    tcp       0.0.0.0/0 (INTERNET) HIGH
db-servers      sg-ghi789     vpc-xyz789     3306   tcp       0.0.0.0/0 (INTERNET) CRITICAL
```

### Tips & Warnings
> ⚠️ SSH (22), RDP (3389), and database ports open to `0.0.0.0/0` are critical security misconfigurations.

---

## 4. CloudTrail Audit — `Get-CTTrail`

### What it does
Verifies that AWS CloudTrail is properly configured — logging enabled, multi-region, log file validation, and encryption.

### Audit Script
```powershell
$trails = Get-CTTrail
foreach ($trail in $trails) {
    $status = Get-CTTrailStatus -Name $trail.Name
    [PSCustomObject]@{
        Name                = $trail.Name
        IsMultiRegion       = $trail.IsMultiRegionTrail
        IsLogging           = $status.IsLogging
        LogFileValidation   = $trail.LogFileValidationEnabled
        KMSEncrypted        = ($trail.KmsKeyId -ne $null)
        S3Bucket            = $trail.S3BucketName
        LatestDelivery      = $status.LatestDeliveryTime
    }
} | Format-Table -AutoSize
```

### Sample Output
```
Name         IsMultiRegion  IsLogging  LogFileValidation  KMSEncrypted  S3Bucket          LatestDelivery
----         -------------  ---------  -----------------  ------------  --------          --------------
main-trail   True           True       True               True          company-ct-logs   3/29/2026 8:00 AM
```

### Tips & Warnings
> ⚠️ `IsLogging: False` = **CloudTrail is disabled** — you have no audit trail. Re-enable immediately.

> 💡 Enable log file validation and KMS encryption for tamper-proof audit logs.

---

## 5. AWS GuardDuty Findings — `Get-GD2Finding`

### What it does
Retrieves AWS GuardDuty threat detection findings for investigation and response.

### Query Script
```powershell
$detectorId = (Get-GD2Detector).DetectorIds[0]
$findingIds = Get-GD2Finding -DetectorId $detectorId

$findings = Get-GD2FindingDetail -DetectorId $detectorId -FindingId $findingIds
$findings | Select-Object Title, Severity, Type, CreatedAt,
    @{n='Resource';e={$_.Resource.ResourceType}},
    @{n='Action';e={$_.Service.Action.ActionType}} |
    Where-Object { $_.Severity -ge 7 } |  # High severity
    Sort-Object Severity -Descending |
    Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Integrate GuardDuty findings into your SIEM for centralized alerting.

---

## 6. AWS Security Hub — `Get-SHUBFinding`

### What it does
Retrieves consolidated security findings from AWS Security Hub, which aggregates results from GuardDuty, Inspector, Macie, and third-party tools.

### Query Script
```powershell
$findings = Get-SHUBFinding -Filter @{
    SeverityLabel = @{ Value = "CRITICAL"; Comparison = "EQUALS" }
    WorkflowStatus = @{ Value = "NEW"; Comparison = "EQUALS" }
}

$findings.Findings | Select-Object Title, Severity, ProductName,
    @{n='Resource';e={$_.Resources[0].Type}},
    @{n='Account';e={$_.AwsAccountId}},
    CreatedAt |
    Format-Table -AutoSize -Wrap
```

### Tips & Warnings
> 💡 Enable Security Hub's automated standards (CIS, PCI DSS) for continuous compliance checks.

---

## 7. Azure Defender for Cloud — `Get-AzSecurityAlert`

### What it does
Retrieves security alerts from Microsoft Defender for Cloud across all your Azure subscriptions.

### Query Script
```powershell
Connect-AzAccount

# Get all active security alerts
$alerts = Get-AzSecurityAlert | Where-Object { $_.Status -eq "Active" }
$alerts | Select-Object AlertDisplayName, Severity, Status, TimeGeneratedUtc,
    @{n='Resource';e={$_.CompromisedEntity}},
    @{n='AttackTactic';e={$_.Intent}} |
    Sort-Object Severity |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
AlertDisplayName                      Severity  Status  TimeGeneratedUtc       Resource         AttackTactic
----------------                      --------  ------  ----------------       --------         ------------
Suspicious process execution          High      Active  3/29/2026 2:00 AM      vm-web-01        Execution
Public IP brute force                 Medium    Active  3/29/2026 3:00 AM      vm-sql-01        PreAttack
```

### Tips & Warnings
> 💡 Use `Get-AzSecurityTask` to get actionable recommendations:
> ```powershell
> Get-AzSecurityTask | Select-Object Name, RecommendationType, State | Format-Table -AutoSize
> ```

---

## 8. GCP Security Auditing from PowerShell

### What it does
Uses the `gcloud` CLI from PowerShell to audit GCP resource configurations and security settings.

### Audit Script
```powershell
# Ensure gcloud is available
if (Get-Command gcloud -ErrorAction SilentlyContinue) {
    # List IAM policies for the project
    Write-Host "=== GCP IAM Policies ===" -ForegroundColor Yellow
    $iamPolicy = & gcloud projects get-iam-policy $env:GCP_PROJECT --format=json | ConvertFrom-Json
    $iamPolicy.bindings | ForEach-Object {
        [PSCustomObject]@{
            Role    = $_.role
            Members = $_.members -join '; '
        }
    } | Where-Object { $_.Role -match 'admin|owner|editor' } | Format-Table -AutoSize -Wrap

    # Check for public GCS buckets
    Write-Host "=== GCS Bucket ACLs ===" -ForegroundColor Yellow
    $buckets = & gcloud storage buckets list --format=json | ConvertFrom-Json
    foreach ($bucket in $buckets) {
        $acl = & gcloud storage buckets describe $bucket.name --format=json | ConvertFrom-Json
        if ($acl.iamConfiguration.publicAccessPrevention -ne 'enforced') {
            Write-Host "[WARN] $($bucket.name) — Public access prevention NOT enforced" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "gcloud CLI not found. Install: https://cloud.google.com/sdk/docs/install" -ForegroundColor Red
}
```

### Tips & Warnings
> 💡 Install gcloud and authenticate: `& gcloud auth login` and `& gcloud config set project PROJECT_ID`

---

## 9. Cross-Cloud IAM Audit

### What it does
Compares IAM configurations across AWS, Azure, and GCP to ensure consistent security policies.

### Audit Script
```powershell
$crossCloudAudit = @()

# AWS IAM check
$awsUsers = Get-IAMUser
$crossCloudAudit += [PSCustomObject]@{
    Cloud    = "AWS"
    Metric   = "Total IAM Users"
    Value    = $awsUsers.Count
    Finding  = if ($awsUsers.Count -gt 50) { "REVIEW — many users" } else { "OK" }
}

# Azure AD check
$azureUsers = Get-MgUser -All -Property AccountEnabled | Where-Object { $_.AccountEnabled }
$crossCloudAudit += [PSCustomObject]@{
    Cloud    = "Azure"
    Metric   = "Active Users"
    Value    = $azureUsers.Count
    Finding  = "Informational"
}

# Check MFA across clouds
$awsNoMFA = ($awsUsers | Where-Object { (Get-IAMMFADevice -UserName $_.UserName).Count -eq 0 }).Count
$crossCloudAudit += [PSCustomObject]@{
    Cloud    = "AWS"
    Metric   = "Users without MFA"
    Value    = $awsNoMFA
    Finding  = if ($awsNoMFA -gt 0) { "CRITICAL" } else { "OK" }
}

$crossCloudAudit | Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Normalize findings across clouds into a single report for executive visibility.

---

## 10. Cloud Storage Public Access Detection

### What it does
Scans for publicly accessible storage across all three major cloud providers.

### Detection Script
```powershell
$publicStorage = @()

# AWS S3
Get-S3Bucket | ForEach-Object {
    $block = Get-S3PublicAccessBlock -BucketName $_.BucketName -ErrorAction SilentlyContinue
    if (-not $block -or -not $block.BlockPublicAcls) {
        $publicStorage += [PSCustomObject]@{ Cloud="AWS"; Resource=$_.BucketName; Type="S3 Bucket"; Risk="HIGH" }
    }
}

# Azure Storage
Get-AzStorageAccount | ForEach-Object {
    if ($_.AllowBlobPublicAccess) {
        $publicStorage += [PSCustomObject]@{ Cloud="Azure"; Resource=$_.StorageAccountName; Type="Storage Account"; Risk="HIGH" }
    }
}

if ($publicStorage) {
    Write-Host "[ALERT] Public cloud storage detected:" -ForegroundColor Red
    $publicStorage | Format-Table -AutoSize
} else {
    Write-Host "[OK] No public cloud storage" -ForegroundColor Green
}
```

### Tips & Warnings
> ⚠️ Public cloud storage is the #1 cause of cloud data breaches. Block public access at the organization level.

---

## 11. Cloud Privilege Escalation Detection

### What it does
Identifies dangerous IAM configurations that could allow privilege escalation in cloud environments.

### Detection Script
```powershell
# AWS: Find users with IAM policy modification permissions
$users = Get-IAMUser
foreach ($user in $users) {
    $policies = Get-IAMUserPolicyList -UserName $user.UserName
    $attachedPolicies = Get-IAMAttachedUserPolicyList -UserName $user.UserName

    foreach ($ap in $attachedPolicies) {
        $policyVersion = Get-IAMPolicyVersion -PolicyArn $ap.PolicyArn -VersionId (Get-IAMPolicy -PolicyArn $ap.PolicyArn).DefaultVersionId
        $doc = [System.Web.HttpUtility]::UrlDecode($policyVersion.Document)

        if ($doc -match '"iam:\*"|"iam:Create"|"iam:Attach"|"iam:Put"|"\*:\*"') {
            [PSCustomObject]@{
                User       = $user.UserName
                Policy     = $ap.PolicyName
                Risk       = "PRIVILEGE ESCALATION POSSIBLE"
                Detail     = "Can modify IAM policies"
            }
        }
    }
} | Format-Table -AutoSize -Wrap
```

### Tips & Warnings
> ⚠️ Users with `iam:*` or `*:*` permissions can escalate to full admin access — restrict immediately.

> 💡 Use AWS IAM Access Analyzer for automated privilege escalation detection.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [25 — AppLocker and WDAC](25-AppLocker-and-WDAC.md) | [README](../README.md) | [27 — Ransomware Detection and Response](27-Ransomware-Detection-and-Response.md) |
