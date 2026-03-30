# 11 — PKI and Certificate Management

> **Module required:** `PKI` (built-in on Windows), `ADCSAdministration` (RSAT for ADCS)  
> **Run as:** Local Administrator for store operations; Enterprise Admin for ADCS management.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `New-SelfSignedCertificate` | Generate a self-signed certificate for testing or internal use |
| `Get-ChildItem Cert:\` | Browse and search the local certificate stores |
| `Import-Certificate` | Import a certificate (.cer/.crt) into a certificate store |
| `Export-PfxCertificate` | Export a certificate with its private key to a .pfx file |
| `certutil` | Swiss-army knife for certificate verification, CRL checks, and store management |
| `Get-Certificate` | Request a certificate from a CA or enroll against a template |
| `Get-ChildItem` (expiry audit) | Find certificates expiring within a defined time window |
| `certutil -verify -urlfetch` | Verify a certificate's CRL and OCSP revocation status |
| `Get-ADCSCertificationAuthority` | Query Active Directory Certificate Services configuration |
| `Revoke-Certificate` | Revoke a compromised or decommissioned certificate via ADCS |

---

## 1. `New-SelfSignedCertificate`

### What it does
Creates a self-signed X.509 certificate and stores it in the local certificate store. Self-signed certificates are useful for development, testing, internal code signing, and encrypting PowerShell DSC credentials. They are not trusted by external parties unless explicitly imported.

### Full Syntax
```powershell
New-SelfSignedCertificate
    [-Subject <String>]
    [-DnsName <String[]>]
    [-CertStoreLocation <String>]
    [-KeyAlgorithm <String>]
    [-KeyLength <Int32>]
    [-KeyExportPolicy <KeyExportPolicy>]
    [-KeyUsage <KeyUsage[]>]
    [-TextExtension <String[]>]
    [-NotAfter <DateTime>]
    [-FriendlyName <String>]
    [-HashAlgorithm <String>]
    [-Provider <String>]
    [-Type <CertificateType>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Subject` | String | The certificate subject (CN). Example: `"CN=myserver.corp.local"` |
| `-DnsName` | String[] | One or more DNS names for the Subject Alternative Name (SAN) |
| `-CertStoreLocation` | String | Store path, e.g., `Cert:\LocalMachine\My` or `Cert:\CurrentUser\My` |
| `-KeyAlgorithm` | String | `RSA` (default) or `ECDSA_nistP256` / `ECDSA_nistP384` |
| `-KeyLength` | Int32 | Key size in bits — `2048` (default), `4096` for RSA |
| `-KeyExportPolicy` | Enum | `Exportable`, `ExportableEncrypted`, or `NonExportable` |
| `-NotAfter` | DateTime | Certificate expiration date; defaults to one year from creation |
| `-HashAlgorithm` | String | `SHA256` (default), `SHA384`, or `SHA512` |
| `-FriendlyName` | String | Human-readable label shown in the certificate store |

### Real-World Example
**Scenario:** You need a TLS certificate for a development web server with multiple SAN entries and a two-year validity period.

```powershell
$cert = New-SelfSignedCertificate `
    -Subject "CN=devapp.corp.local" `
    -DnsName "devapp.corp.local","devapp","localhost" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2) `
    -FriendlyName "DevApp TLS Certificate" `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

Write-Host "Created certificate: $($cert.Thumbprint)"
```

### Sample Output
```
Created certificate: A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2
```

### Tips & Warnings
> ⚠️ **Self-signed certificates are not trusted by default.** Clients will show TLS warnings unless the certificate is added to their Trusted Root store. Never use self-signed certs in production for public-facing services.

> 💡 **Tip:** Use `-KeyExportPolicy NonExportable` in production to prevent private key extraction. Only mark as `Exportable` during initial creation if you need to back up the PFX.

> ⚠️ **Minimum key length:** Always use at least 2048-bit RSA or 256-bit ECDSA. Certificates with 1024-bit keys are rejected by modern browsers and fail compliance checks.

---

## 2. `Get-ChildItem Cert:\` — Browsing Certificate Stores

### What it does
PowerShell mounts the certificate store as a PSDrive called `Cert:\`. You can browse it like a file system using `Get-ChildItem`. This is the fastest way to inspect installed certificates, find expiring certs, or locate a specific certificate by thumbprint or subject.

### Full Syntax
```powershell
Get-ChildItem
    [-Path] <String>       # e.g., Cert:\LocalMachine\My
    [-Recurse]
    [-ExpiringInDays <Int32>]
    [-SSLServerAuthentication]
    [-DnsName <String>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Path` | String | Certificate store path — `Cert:\LocalMachine\My`, `Cert:\CurrentUser\Root`, etc. |
| `-Recurse` | Switch | Search all child containers within the store |
| `-DnsName` | String | Filter certificates by DNS name in the subject or SAN |
| `-ExpiringInDays` | Int32 | Return only certificates expiring within N days |

### Real-World Example
**Scenario:** You need to list all certificates in the local machine's Personal store and check their expiration dates.

```powershell
Get-ChildItem -Path Cert:\LocalMachine\My |
    Select-Object Thumbprint, Subject, NotAfter, Issuer |
    Sort-Object NotAfter |
    Format-Table -AutoSize
```

### Sample Output
```
Thumbprint                               Subject                          NotAfter             Issuer
----------                               -------                          --------             ------
A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2 CN=devapp.corp.local             6/15/2028 12:00:00 AM CN=devapp.corp.local
B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3 CN=sqlserver.corp.local          9/01/2026 12:00:00 AM CN=Corp-Issuing-CA
C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4 CN=exchange.corp.local           3/22/2026 12:00:00 AM CN=Corp-Issuing-CA
```

### Tips & Warnings
> 💡 **Key store locations:**
> - `Cert:\LocalMachine\My` — Machine personal certificates (used by IIS, SQL Server, etc.)
> - `Cert:\LocalMachine\Root` — Trusted Root CAs
> - `Cert:\LocalMachine\CA` — Intermediate CAs
> - `Cert:\CurrentUser\My` — Current user's personal certificates

> 💡 **Find a certificate by thumbprint:**
> ```powershell
> Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq "A1B2C3D4..." }
> ```

> ⚠️ Certificates in `Root` and `CA` stores affect the entire trust chain. Only add trusted certificates to these stores.

---

## 3. `Import-Certificate`

### What it does
Imports a public certificate file (.cer, .crt, .der) into a specified certificate store. This is how you distribute root CA certificates to machines, add intermediate CA certs, or install certificates received from vendors.

### Full Syntax
```powershell
Import-Certificate
    [-FilePath] <String>
    [-CertStoreLocation] <String>
    [-Confirm]
    [-WhatIf]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-FilePath` | String | Path to the certificate file (.cer, .crt, or .der format) |
| `-CertStoreLocation` | String | Destination store, e.g., `Cert:\LocalMachine\Root` |
| `-WhatIf` | Switch | Preview the import without actually executing it |
| `-Confirm` | Switch | Prompt for confirmation before importing |

### Real-World Example
**Scenario:** Your organization has deployed a new internal root CA. You need to push its certificate into the Trusted Root store on all workstations.

```powershell
# Import the internal root CA certificate
Import-Certificate `
    -FilePath "\\fileserver\certs\CorpRootCA.cer" `
    -CertStoreLocation "Cert:\LocalMachine\Root"

# Verify the import
Get-ChildItem -Path Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like "*CorpRootCA*" } |
    Select-Object Subject, Thumbprint, NotAfter
```

### Sample Output
```
Subject                       Thumbprint                               NotAfter
-------                       ----------                               --------
CN=CorpRootCA, DC=corp, DC=…  D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5 12/31/2035 11:59:59 PM
```

### Tips & Warnings
> ⚠️ **Importing into Root is a trust decision.** Any certificate signed by this CA will be trusted by the machine. Verify the thumbprint against a known-good value before importing.

> 💡 **Deploy at scale with GPO:** Rather than scripting imports on every machine, publish the root CA certificate through Group Policy (`Computer Configuration → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities`).

> ⚠️ `Import-Certificate` only imports public certificates. To import a certificate **with its private key**, use `Import-PfxCertificate` instead.

---

## 4. `Export-PfxCertificate`

### What it does
Exports a certificate along with its private key to a PFX (PKCS#12) file, protected by a password. This is essential for backing up TLS certificates, migrating them between servers, or storing them securely offline.

### Full Syntax
```powershell
Export-PfxCertificate
    [-Cert] <Certificate>
    [-FilePath] <String>
    [-Password] <SecureString>
    [-ChainOption <ExportChainOption>]
    [-NoProperties]
    [-Force]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Cert` | Certificate | The certificate object to export (piped from `Get-ChildItem Cert:\`) |
| `-FilePath` | String | Destination path for the .pfx file |
| `-Password` | SecureString | Password to protect the exported PFX file |
| `-ChainOption` | Enum | `BuildChain` (include full chain), `EndEntityCertOnly` (default) |
| `-NoProperties` | Switch | Exclude extended properties from the export |
| `-Force` | Switch | Overwrite the file if it already exists |

### Real-World Example
**Scenario:** You are migrating a web application to a new server and need to export the TLS certificate with its private key.

```powershell
$password = ConvertTo-SecureString "Export@2026Secure!" -AsPlainText -Force
$cert = Get-ChildItem -Path Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq "CN=webapp.corp.local" }

Export-PfxCertificate `
    -Cert $cert `
    -FilePath "C:\CertBackup\webapp-corp-local.pfx" `
    -Password $password `
    -ChainOption BuildChain

Write-Host "Exported $($cert.Subject) to PFX"
```

### Sample Output
```
    Directory: C:\CertBackup

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/29/2026  10:30 AM           4218 webapp-corp-local.pfx
Exported CN=webapp.corp.local to PFX
```

### Tips & Warnings
> ⚠️ **PFX files contain private keys.** Store them in a secure location with restricted ACLs. Never leave PFX files on shared drives or in source control.

> ⚠️ **Use strong passwords** for PFX exports. A weak password is the only thing standing between an attacker and your private key.

> 💡 **Tip:** Use `-ChainOption BuildChain` when exporting for migration — the destination server may not have the intermediate CA certificates installed.

---

## 5. `certutil` via PowerShell

### What it does
`certutil.exe` is a built-in Windows command-line utility for certificate management. While not a native PowerShell cmdlet, it is frequently invoked from PowerShell for tasks like verifying certificate chains, decoding certificate files, dumping store contents, and managing CRLs. It remains indispensable for operations not covered by the PKI module.

### Full Syntax
```powershell
# Dump a certificate file
certutil -dump <CertificateFile>

# Verify a certificate chain
certutil -verify <CertificateFile>

# List certificates in a store
certutil -store My

# Download and cache a CRL
certutil -urlcache -split -f <CRL_URL> <OutputFile>

# Decode a Base64 certificate to DER
certutil -decode <Base64File> <DERFile>
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-dump` | Display full details of a certificate file including extensions and key usage |
| `-verify` | Validate the certificate chain and revocation status |
| `-store <StoreName>` | List all certificates in the named store (My, Root, CA, etc.) |
| `-urlcache -split -f` | Force download a resource (CRL, AIA) and display the cached result |
| `-decode` / `-encode` | Convert between Base64 (PEM) and DER binary formats |

### Real-World Example
**Scenario:** A user reports TLS errors connecting to an internal service. You need to verify the server certificate chain is valid and all intermediate CAs are reachable.

```powershell
# Export the certificate from the store using PowerShell, then verify it
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*webapp.corp.local*" }
Export-Certificate -Cert $cert -FilePath C:\diag\webapp.cer

certutil -verify -urlfetch C:\diag\webapp.cer

# Check the certificate's full details
certutil -dump C:\diag\webapp.cer
```

### Sample Output
```
================ Certificate 0 ================
Serial Number: 6100000002a3b8c9d1e5f00000000002
Issuer: CN=Corp-Issuing-CA, DC=corp, DC=local
 NotBefore: 1/15/2026 9:00 AM
 NotAfter: 1/15/2028 9:00 AM
Subject: CN=webapp.corp.local
Cert Hash(sha1): a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
  Key Container = {12345678-abcd-ef01-2345-6789abcdef01}
  Provider = Microsoft RSA SChannel Cryptographic Provider
...
--------------------------------
    CRL Distribution Points:
        [1] http://pki.corp.local/CertEnroll/Corp-Issuing-CA.crl
    Verified Issuance Policies: None
    Verified Application Policies: Server Authentication
CertUtil: -verify command completed successfully.
```

### Tips & Warnings
> 💡 **`certutil -verify -urlfetch`** is the gold standard for diagnosing certificate chain problems. It checks every link in the chain and reports exactly where it breaks.

> ⚠️ `certutil` output is verbose. Pipe to `Select-String` when looking for specific fields:
> ```powershell
> certutil -dump cert.cer | Select-String "NotAfter|Subject|Issuer"
> ```

> 💡 **Tip:** Use `certutil -hashfile <file> SHA256` to quickly compute file hashes for integrity verification.

---

## 6. Managing Certificate Stores

### What it does
PowerShell can directly manage the certificate store using the `Cert:\` PSDrive. You can remove untrusted certificates, move certificates between stores, and clean up expired certs — all through familiar file-system-style commands like `Remove-Item` and `Move-Item`.

### Full Syntax
```powershell
# Remove a certificate by thumbprint
Remove-Item -Path Cert:\LocalMachine\My\<Thumbprint> -DeleteKey

# Copy a certificate to another store
$cert = Get-ChildItem -Path Cert:\LocalMachine\My\<Thumbprint>
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Path` | Full path including thumbprint, e.g., `Cert:\LocalMachine\My\A1B2C3...` |
| `-DeleteKey` | Also delete the associated private key when removing a certificate |
| `X509Store.Open()` | Open the store with `ReadWrite`, `ReadOnly`, or `MaxAllowed` permissions |

### Real-World Example
**Scenario:** An internal CA was decommissioned. You need to remove its certificate from the Trusted Root store across all servers.

```powershell
# Identify the old CA certificate
$oldCA = Get-ChildItem -Path Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like "*OldCorpCA*" }

if ($oldCA) {
    Remove-Item -Path "Cert:\LocalMachine\Root\$($oldCA.Thumbprint)"
    Write-Host "Removed: $($oldCA.Subject) [$($oldCA.Thumbprint)]"
} else {
    Write-Host "Certificate not found — already removed."
}
```

### Sample Output
```
Removed: CN=OldCorpCA, DC=corp, DC=local [F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1]
```

### Tips & Warnings
> ⚠️ **Removing root CA certificates breaks trust** for every certificate in that chain. Verify that no active services depend on the CA before removal.

> ⚠️ **Use `-DeleteKey` with caution.** Once the private key is deleted, there is no way to recover it. Only use this when permanently decommissioning a certificate.

> 💡 **Audit before cleanup:** Export a list of all certificates before bulk removal so you have a rollback reference:
> ```powershell
> Get-ChildItem Cert:\LocalMachine\Root |
>     Select-Object Subject, Thumbprint, NotAfter |
>     Export-Csv -Path C:\audit\root-certs-backup.csv -NoTypeInformation
> ```

---

## 7. Certificate Expiry Auditing

### What it does
Expired certificates cause outages — TLS handshakes fail, services refuse to start, and authentication breaks silently. Proactive expiry auditing scans your certificate stores and reports certificates nearing their expiration date so you can renew them before they cause downtime.

### Full Syntax
```powershell
# Using built-in parameter
Get-ChildItem -Path Cert:\LocalMachine\My -ExpiringInDays <Int32>

# Manual filtering for custom thresholds
Get-ChildItem -Path Cert:\LocalMachine\My |
    Where-Object { $_.NotAfter -lt (Get-Date).AddDays(<Days>) }
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-ExpiringInDays` | Int32 | Return certificates expiring within this many days |
| `-Path` | String | The certificate store to audit |
| `$_.NotAfter` | DateTime | The certificate's expiration date (property on the cert object) |

### Real-World Example
**Scenario:** You need a weekly report of all machine certificates expiring within the next 60 days, emailed to the infrastructure team.

```powershell
$threshold = 60
$expiring = Get-ChildItem -Path Cert:\LocalMachine\My -ExpiringInDays $threshold |
    Select-Object @{n='Subject';e={$_.Subject}},
                  @{n='Thumbprint';e={$_.Thumbprint}},
                  @{n='ExpiresOn';e={$_.NotAfter.ToString("yyyy-MM-dd")}},
                  @{n='DaysLeft';e={($_.NotAfter - (Get-Date)).Days}},
                  @{n='Issuer';e={$_.Issuer}}

if ($expiring) {
    $expiring | Format-Table -AutoSize
    Write-Warning "$($expiring.Count) certificate(s) expiring within $threshold days!"
} else {
    Write-Host "No certificates expiring within $threshold days."
}
```

### Sample Output
```
Subject                     Thumbprint                               ExpiresOn   DaysLeft Issuer
-------                     ----------                               ---------   -------- ------
CN=webapp.corp.local        B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3 2026-05-10        42 CN=Corp-Issuing-CA
CN=api.corp.local           C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4 2026-04-22        24 CN=Corp-Issuing-CA

WARNING: 2 certificate(s) expiring within 60 days!
```

### Tips & Warnings
> ⚠️ **Don't forget remote servers.** Use `Invoke-Command` to scan certificate stores across your environment:
> ```powershell
> $servers = Get-Content C:\servers.txt
> Invoke-Command -ComputerName $servers -ScriptBlock {
>     Get-ChildItem Cert:\LocalMachine\My -ExpiringInDays 30 |
>         Select-Object PSComputerName, Subject, NotAfter
> }
> ```

> 💡 **Automate with a scheduled task.** Run the audit weekly and email results using `Send-MailMessage` or push alerts to your ticketing system.

> ⚠️ Certificates in `CurrentUser` stores are often overlooked — include both `LocalMachine` and `CurrentUser` in your audits.

---

## 8. CRL Checking — Certificate Revocation Validation

### What it does
Certificate Revocation Lists (CRLs) and the Online Certificate Status Protocol (OCSP) allow clients to verify that a certificate has not been revoked. Checking CRL status is critical when diagnosing trust failures or validating that your PKI infrastructure is publishing revocation data correctly.

### Full Syntax
```powershell
# Verify CRL and OCSP using certutil
certutil -verify -urlfetch <CertificateFile>

# Check CRL distribution points in a certificate
certutil -dump <CertificateFile> | Select-String "CRL Distribution"

# Download and inspect a CRL file
certutil -urlcache -split -f "http://pki.corp.local/CertEnroll/Corp-CA.crl" CorpCA.crl
certutil -dump CorpCA.crl
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-verify -urlfetch` | Verify the certificate chain and attempt to download CRLs and OCSP responses |
| `-dump` on a .crl file | Display all entries in the CRL including serial numbers and revocation dates |
| `-urlcache -split -f` | Force-download a URL to the local cache and output the result |

### Real-World Example
**Scenario:** Users report that a web application shows "certificate revoked" errors. You need to check the CRL status and verify the certificate is still valid.

```powershell
# Step 1: Export the problem certificate
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*webapp.corp.local*" }
Export-Certificate -Cert $cert -FilePath C:\diag\webapp.cer

# Step 2: Verify the chain and revocation status
certutil -verify -urlfetch C:\diag\webapp.cer

# Step 3: Check when the CRL was last updated
certutil -urlcache -split -f "http://pki.corp.local/CertEnroll/Corp-Issuing-CA.crl" C:\diag\latest.crl
certutil -dump C:\diag\latest.crl | Select-String "ThisUpdate|NextUpdate|Serial Number"
```

### Sample Output
```
Verified Issuance Policies: All
Verified Application Policies: Server Authentication
Leaf certificate revocation check passed
CertUtil: -verify command completed successfully.

--------- CRL Info ---------
ThisUpdate: 3/28/2026 6:00 AM
NextUpdate: 4/04/2026 6:00 AM
CRL Entries: 3
  Serial Number: 6100000005...  Revocation Date: 2/10/2026 3:00 PM
  Serial Number: 6100000008...  Revocation Date: 3/01/2026 9:00 AM
  Serial Number: 610000000b...  Revocation Date: 3/15/2026 11:00 AM
```

### Tips & Warnings
> ⚠️ **Stale CRLs cause outages.** If `NextUpdate` is in the past, clients will reject all certificates from that CA. Monitor CRL freshness as part of your PKI health checks.

> 💡 **OCSP is faster than CRL** for individual certificate checks. If your CA supports OCSP, ensure the responder URL is reachable from all client networks.

> 💡 **Test CRL connectivity from client machines:**
> ```powershell
> $cdpUrl = "http://pki.corp.local/CertEnroll/Corp-Issuing-CA.crl"
> try { Invoke-WebRequest -Uri $cdpUrl -UseBasicParsing | Select-Object StatusCode }
> catch { Write-Error "CRL download failed: $_" }
> ```

---

## 9. ADCS Management — Active Directory Certificate Services

### What it does
Active Directory Certificate Services (ADCS) is Microsoft's enterprise PKI solution. PowerShell can query CA configuration, list issued certificates, manage certificate templates, and monitor CA health. The `ADCSAdministration` module provides cmdlets for direct CA management.

### Full Syntax
```powershell
# Query the CA configuration
Get-CertificationAuthority

# List certificate templates
certutil -CATemplates

# View certificates issued by the CA
certutil -view -restrict "Disposition=20" -out "RequesterName,CommonName,NotAfter,SerialNumber"

# Backup the CA database
Backup-CARoleService -Path "C:\CABackup" -KeyOnly
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `Get-CertificationAuthority` | Returns CA name, server, type, and certificate information |
| `-CATemplates` | List all certificate templates available on the CA |
| `-view -restrict "Disposition=20"` | Query issued certificates (Disposition 20 = issued) |
| `Backup-CARoleService` | Back up the CA private key and/or database |
| `-KeyOnly` | Back up only the CA private key and certificate |

### Real-World Example
**Scenario:** During a quarterly PKI review, you need to inventory all certificates issued by your enterprise CA and identify any issued to decommissioned servers.

```powershell
# List all issued certificates with expiry dates
certutil -view -restrict "Disposition=20" `
    -out "RequesterName,CommonName,Certificate Expiration Date,SerialNumber" |
    Out-File C:\audit\issued-certificates.txt

# Check CA health and configuration
certutil -CAInfo

# List available certificate templates
certutil -CATemplates | Select-String "Template\[" |
    ForEach-Object { $_.Line.Trim() }
```

### Sample Output
```
CA Configuration:
  Server:        PKI01.corp.local
  CA Name:       Corp-Issuing-CA
  CA Type:       Enterprise Subordinate CA
  CA Cert[0]:    Valid (NotAfter: 12/31/2030)

Available Templates:
  Template[0]: WebServer -- Web Server
  Template[1]: CodeSigning -- Code Signing
  Template[2]: DomainController -- Domain Controller Authentication
  Template[3]: WorkstationAuth -- Workstation Authentication
```

### Tips & Warnings
> ⚠️ **ADCS misconfigurations are a top Active Directory attack vector.** Audit certificate templates for overly permissive enrollment rights — tools like Certify and Certipy exploit these weaknesses (ESC1–ESC8 attacks).

> 💡 **Critical template settings to audit:**
> ```powershell
> # Check for templates that allow the enrollee to supply their own subject name
> certutil -v -dstemplate | Select-String "msPKI-Certificate-Name-Flag|CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"
> ```

> ⚠️ **Back up your CA regularly.** A lost CA private key means you must rebuild your entire PKI. Schedule `Backup-CARoleService` as a daily automated task.

---

## 10. Revoking Certificates

### What it does
Certificate revocation invalidates a certificate before its natural expiration. This is essential when a private key is compromised, an employee leaves the organization, or a server is decommissioned. Revoked certificates are published in the CRL so that relying parties stop trusting them.

### Full Syntax
```powershell
# Revoke via certutil (most common method)
certutil -revoke <SerialNumber> <Reason>

# Reason codes:
#   0 = Unspecified
#   1 = Key Compromise
#   2 = CA Compromise
#   3 = Affiliation Changed
#   4 = Superseded
#   5 = Cessation of Operation

# Publish an updated CRL immediately
certutil -CRL
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `<SerialNumber>` | The serial number of the certificate to revoke (hex string from `certutil -view`) |
| `<Reason>` | Integer reason code (0–5) indicating why the certificate is being revoked |
| `-CRL` | Force the CA to publish an updated CRL immediately |

### Real-World Example
**Scenario:** A web server's private key was exposed in a Git repository. You need to revoke the certificate immediately and publish an updated CRL.

```powershell
# Step 1: Find the certificate's serial number
$serial = certutil -view -restrict "CommonName=webapp.corp.local,Disposition=20" `
    -out "SerialNumber" |
    Select-String "Serial Number:" |
    ForEach-Object { ($_ -split ": ")[1].Trim() }

Write-Host "Revoking certificate with serial: $serial"

# Step 2: Revoke with reason "Key Compromise"
certutil -revoke $serial 1

# Step 3: Publish updated CRL immediately
certutil -CRL

Write-Host "Certificate revoked and CRL published."
```

### Sample Output
```
Revoking certificate with serial: 6100000002a3b8c9d1e5f00000000002
ICertAdmin::RevokeCertificate -- revoked successfully.
CertUtil: -CRL command completed successfully.
Certificate revoked and CRL published.
```

### Tips & Warnings
> ⚠️ **Revocation is irreversible** (for reason code 1 — Key Compromise). Double-check the serial number before confirming. Unrevoke is only possible for certain reason codes.

> ⚠️ **Publish the CRL after revocation.** Revocation takes effect only after the CRL is updated and distributed. Until then, clients will still trust the revoked certificate.

> 💡 **Monitor revocation propagation:** After publishing, verify the CRL was updated:
> ```powershell
> certutil -urlcache -split -f "http://pki.corp.local/CertEnroll/Corp-Issuing-CA.crl" C:\diag\check.crl
> certutil -dump C:\diag\check.crl | Select-String "ThisUpdate|NextUpdate"
> ```

> 💡 **Tip:** For time-critical revocations (key compromise), also consider disabling the certificate's associated service account and rotating any credentials that may have been exposed alongside the private key.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [10 — Compliance and Auditing](10-Compliance-and-Auditing.md) | [README](../README.md) | [12 — Active Directory Attack Detection](12-Active-Directory-Attack-Detection.md) |
