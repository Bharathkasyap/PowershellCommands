# 🛡️ PowerShell Commands for Cybersecurity Engineers

> A comprehensive, well-structured reference repository covering essential PowerShell commands for cybersecurity work — from identity management and incident response to cloud security and compliance auditing.

Whether you are just getting started with PowerShell in a security role or you want a reliable day-to-day reference, this repository explains every command in plain English with real-world examples, sample output, and practical tips.

---

## 📚 Table of Contents

### 🔐 Identity & Access Management

| # | Topic | Description |
|---|-------|-------------|
| 01 | [Identity and Access Management](docs/01-Identity-and-Access-Management.md) | AD users, groups, password policies, service account auditing |
| 02 | [GPO Management](docs/02-GPO-Management.md) | Create, link, back up, and report on Group Policy Objects |
| 11 | [PKI and Certificate Management](docs/11-PKI-and-Certificate-Management.md) | Cert stores, ADCS, self-signed certs, expiry auditing, CRL checking |
| 12 | [Active Directory Attack Detection](docs/12-Active-Directory-Attack-Detection.md) | Kerberoasting, DCSync, Golden Ticket, ACL abuse, BloodHound patterns |
| 13 | [Privileged Access Management](docs/13-Privileged-Access-Management.md) | JEA, LAPS, tiered admin, Protected Users, privilege escalation events |
| 21 | [Kerberos and Authentication](docs/21-Kerberos-and-Authentication.md) | klist, SPNs, delegation, NTLM audit, smart cards, authentication silos |
| 23 | [Credential Security and LAPS](docs/23-Credential-Security-and-LAPS.md) | LAPS management, Credential Guard, LSASS protection, DCSync detection |

### 🖥️ Endpoint & OS Security

| # | Topic | Description |
|---|-------|-------------|
| 07 | [Endpoint Security](docs/07-Endpoint-Security.md) | Defender, AppLocker, BitLocker, firewall profiles, drivers |
| 14 | [Windows Registry Security](docs/14-Windows-Registry-Security.md) | Run keys, COM/CLSID hijacking, IFEO, autorun locations, hardening |
| 15 | [PowerShell Security and Hardening](docs/15-PowerShell-Security-and-Hardening.md) | Execution policy, AMSI, CLM, script block logging, downgrade detection |
| 25 | [AppLocker and WDAC](docs/25-AppLocker-and-WDAC.md) | AppLocker policies, WDAC/CI policies, bypass detection, HVCI |
| 27 | [Ransomware Detection and Response](docs/27-Ransomware-Detection-and-Response.md) | File monitoring, VSS deletion detection, isolation, TTP detection |

### 🌐 Network Security

| # | Topic | Description |
|---|-------|-------------|
| 03 | [Network Security](docs/03-Network-Security.md) | Firewall rules, TCP connections, DNS, adapters |
| 16 | [WinRM and Remote Management Security](docs/16-WinRM-and-Remote-Management-Security.md) | PSRemoting, WinRM HTTPS, CredSSP, lateral movement detection |
| 22 | [Network Forensics and Monitoring](docs/22-Network-Forensics-and-Monitoring.md) | Packet capture, beaconing, DNS tunneling, SMB lateral movement |

### 🔍 Threat Detection & Hunting

| # | Topic | Description |
|---|-------|-------------|
| 05 | [Threat Hunting](docs/05-Threat-Hunting.md) | Suspicious tasks, registry keys, encoded PS, lateral movement |
| 17 | [Microsoft Defender and Sentinel](docs/17-Microsoft-Defender-and-Sentinel.md) | MpPreference, MDE status, Sentinel incidents, KQL from PowerShell |
| 20 | [Forensics and Memory Analysis](docs/20-Forensics-and-Memory-Analysis.md) | Volatile data, process hollowing, prefetch, USN journal, WMI persistence |
| 24 | [SOC Automation and Playbooks](docs/24-SOC-Automation-and-Playbooks.md) | Alert triage, host isolation, IOC hunting, VirusTotal API, dashboards |

### 🔬 Incident Response & Forensics

| # | Topic | Description |
|---|-------|-------------|
| 04 | [Incident Response](docs/04-Incident-Response.md) | Processes, scheduled tasks, event logs, user sessions |
| 20 | [Forensics and Memory Analysis](docs/20-Forensics-and-Memory-Analysis.md) | Volatile data, process hollowing, prefetch, USN journal, WMI persistence |
| 27 | [Ransomware Detection and Response](docs/27-Ransomware-Detection-and-Response.md) | File monitoring, VSS deletion detection, isolation, TTP detection |

### ☁️ Cloud & Modern Security

| # | Topic | Description |
|---|-------|-------------|
| 08 | [Cloud Security — Azure](docs/08-Cloud-Security-Azure.md) | Azure AD users, RBAC, policies, MFA, Conditional Access |
| 17 | [Microsoft Defender and Sentinel](docs/17-Microsoft-Defender-and-Sentinel.md) | MpPreference, MDE status, Sentinel incidents, KQL from PowerShell |
| 19 | [Zero Trust and MS Graph](docs/19-Zero-Trust-and-MS-Graph.md) | Conditional Access, MFA gaps, risky users, PIM, sign-in/audit logs |
| 26 | [Cloud Security Multicloud](docs/26-Cloud-Security-Multicloud.md) | AWS IAM/S3/GuardDuty, Azure Defender, GCP audit, cross-cloud security |

### 📋 Compliance & Governance

| # | Topic | Description |
|---|-------|-------------|
| 06 | [Vulnerability Management](docs/06-Vulnerability-Management.md) | Installed software, hotfixes, shares, weak service configs |
| 10 | [Compliance and Auditing](docs/10-Compliance-and-Auditing.md) | ACLs, audit policy, CIS benchmarks, HTML reports |
| 15 | [PowerShell Security and Hardening](docs/15-PowerShell-Security-and-Hardening.md) | Execution policy, AMSI, CLM, script block logging, downgrade detection |
| 25 | [AppLocker and WDAC](docs/25-AppLocker-and-WDAC.md) | AppLocker policies, WDAC/CI policies, bypass detection, HVCI |

### 🔧 Specialized Operations

| # | Topic | Description |
|---|-------|-------------|
| 09 | [Log Management & SIEM](docs/09-Log-Management-SIEM.md) | WinEvent filtering, key Event IDs, CSV export, brute force detection |
| 18 | [Exchange and Email Security](docs/18-Exchange-and-Email-Security.md) | Message trace, quarantine, DKIM, BEC forwarding detection, compliance purge |
| 21 | [Kerberos and Authentication](docs/21-Kerberos-and-Authentication.md) | klist, SPNs, delegation, NTLM audit, smart cards, authentication silos |
| 24 | [SOC Automation and Playbooks](docs/24-SOC-Automation-and-Playbooks.md) | Alert triage, host isolation, IOC hunting, VirusTotal API, dashboards |

---

## 🚀 How to Use This Repository

1. Browse the table of contents above and click the topic you need.
2. Each file contains a **Quick Reference table** at the top — scan it first.
3. Scroll to any command for a full explanation, syntax breakdown, real-world example, sample output, and tips.
4. Copy-paste the examples directly into your PowerShell session (adjust parameters to your environment).

> **Prerequisites:** Most AD and GPO commands require the **RSAT** (Remote Server Administration Tools) or the **ActiveDirectory** PowerShell module. Azure commands require the **Az** and **Microsoft.Graph** modules. AWS commands require the **AWSPowerShell** module. Run PowerShell **as Administrator** where noted.

---

## 👤 Author

**Bharath Kasyap**  
Cybersecurity Engineer | PowerShell Practitioner  
GitHub: [@Bharathkasyap](https://github.com/Bharathkasyap)

---

> 📌 *This repository is maintained as both a personal reference and a public learning resource. Contributions and corrections are welcome via Pull Request.*
