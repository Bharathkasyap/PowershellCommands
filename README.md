# 🛡️ PowerShell Commands for Cybersecurity Engineers

> A comprehensive, well-structured reference repository covering essential PowerShell commands for cybersecurity work — from identity management and incident response to cloud security and compliance auditing.

Whether you are just getting started with PowerShell in a security role or you want a reliable day-to-day reference, this repository explains every command in plain English with real-world examples, sample output, and practical tips.

---

## 📚 Table of Contents

| # | Topic | Description |
|---|-------|-------------|
| 01 | [Identity and Access Management](docs/01-Identity-and-Access-Management.md) | AD users, groups, password policies, service account auditing |
| 02 | [GPO Management](docs/02-GPO-Management.md) | Create, link, back up, and report on Group Policy Objects |
| 03 | [Network Security](docs/03-Network-Security.md) | Firewall rules, TCP connections, DNS, adapters |
| 04 | [Incident Response](docs/04-Incident-Response.md) | Processes, scheduled tasks, event logs, user sessions |
| 05 | [Threat Hunting](docs/05-Threat-Hunting.md) | Suspicious tasks, registry keys, encoded PS, lateral movement |
| 06 | [Vulnerability Management](docs/06-Vulnerability-Management.md) | Installed software, hotfixes, shares, weak service configs |
| 07 | [Endpoint Security](docs/07-Endpoint-Security.md) | Defender, AppLocker, BitLocker, firewall profiles, drivers |
| 08 | [Cloud Security — Azure](docs/08-Cloud-Security-Azure.md) | Azure AD users, RBAC, policies, MFA, Conditional Access |
| 09 | [Log Management & SIEM](docs/09-Log-Management-SIEM.md) | WinEvent filtering, key Event IDs, CSV export, brute force detection |
| 10 | [Compliance and Auditing](docs/10-Compliance-and-Auditing.md) | ACLs, audit policy, CIS benchmarks, HTML reports |

---

## 🚀 How to Use This Repository

1. Browse the table of contents above and click the topic you need.
2. Each file contains a **Quick Reference table** at the top — scan it first.
3. Scroll to any command for a full explanation, syntax breakdown, real-world example, sample output, and tips.
4. Copy-paste the examples directly into your PowerShell session (adjust parameters to your environment).

> **Prerequisites:** Most AD and GPO commands require the **RSAT** (Remote Server Administration Tools) or the **ActiveDirectory** PowerShell module. Azure commands require the **Az** and **Microsoft.Graph** modules. Run PowerShell **as Administrator** where noted.

---

## 👤 Author

**Bharath Kasyap**  
Cybersecurity Engineer | PowerShell Practitioner  
GitHub: [@Bharathkasyap](https://github.com/Bharathkasyap)

---

> 📌 *This repository is maintained as both a personal reference and a public learning resource. Contributions and corrections are welcome via Pull Request.*
