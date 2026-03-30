# 16 — WinRM and Remote Management Security

> **Module required:** Built-in (`Microsoft.WSMan.Management`, `Microsoft.PowerShell.Core`)
> **Run as:** Administrator for configuration changes; some detection commands require Security-log read access.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Enable-PSRemoting` | Configure WinRM and allow incoming PS remote sessions |
| `Disable-PSRemoting` | Revoke session configurations to block new remote sessions |
| `winrm quickconfig -transport:https` | Set up WinRM over HTTPS with a certificate |
| `Set-Item WSMan:\localhost\Client\TrustedHosts` | Define which hosts can be connected to without Kerberos |
| `New-PSSession` | Create a persistent, authenticated remote session |
| `New-NetFirewallRule` / `Set-NetFirewallRule` | Restrict WinRM traffic to specific subnets or IPs |
| `Get-WinEvent` | Query Security and WSMan Operational logs for remote-access events |
| `New-PSSession -SSHTransport` | Connect to a remote host over SSH instead of WinRM |
| `Enable-WSManCredSSP` / `Disable-WSManCredSSP` | Manage CredSSP delegation (use with extreme caution) |
| `Get-PSSession` | List active remote sessions for auditing |

---

## 1. `Enable-PSRemoting` / `Disable-PSRemoting`

### What it does
`Enable-PSRemoting` configures the WinRM service, registers default session configurations, and creates firewall exceptions so the machine can accept incoming PowerShell remote connections. `Disable-PSRemoting` revokes access to session configurations but does **not** stop the WinRM service itself.

### Full Syntax
```powershell
Enable-PSRemoting
    [-Force]
    [-SkipNetworkProfileCheck]
    [-WhatIf] [-Confirm]

Disable-PSRemoting
    [-Force]
    [-WhatIf] [-Confirm]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Force` | Switch | Suppresses all confirmation prompts |
| `-SkipNetworkProfileCheck` | Switch | Allows remoting on public-profile networks (Windows only) |

### Real-World Example
**Scenario:** You are hardening a jump server and need to ensure PSRemoting is active only for administrative use, then later disable it on a decommissioned host.

```powershell
# Enable on the jump server
Enable-PSRemoting -Force

# Disable session configs on a host being retired
Disable-PSRemoting -Force
# Also stop and disable the WinRM service entirely
Stop-Service WinRM -Force
Set-Service WinRM -StartupType Disabled
```

### Sample Output
```
WinRM has been updated to receive requests.
WinRM service type changed successfully.
WinRM service started.
WinRM has been updated for remote management.
WinRM firewall exception configured.
```

### Tips & Warnings
> ⚠️ **`Disable-PSRemoting` is not a full lockdown.** It only sets session-configuration ACLs to deny remote access. The WinRM service remains running. Stop and disable the service explicitly for full removal.

> 💡 **Tip:** Use `-SkipNetworkProfileCheck` only when the server is on a DMZ or isolated VLAN and the network profile cannot be changed to Private/Domain.

---

## 2. WinRM HTTPS with Certificates

### What it does
Configures WinRM to listen on port 5986 using TLS, encrypting all traffic with an X.509 certificate. This prevents credential sniffing on untrusted networks.

### Full Syntax
```powershell
# Create a self-signed cert (production: use CA-issued cert)
$cert = New-SelfSignedCertificate `
    -DnsName "server01.corp.local" `
    -CertStoreLocation Cert:\LocalMachine\My

# Create the HTTPS listener
winrm create winrm/config/Listener?Address=*+Transport=HTTPS `
    "@{Hostname=`"server01.corp.local`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"

# Or via PowerShell cmdlets
New-Item -Path WSMan:\localhost\Listener `
    -Transport HTTPS `
    -Address * `
    -CertificateThumbprint $cert.Thumbprint `
    -Force
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-DnsName` | String | Subject name on the certificate — must match the server FQDN |
| `-CertStoreLocation` | String | Store path; use `Cert:\LocalMachine\My` for machine certs |
| `CertificateThumbprint` | String | SHA-1 thumbprint of the TLS certificate to bind |
| `-Transport` | String | `HTTP` (5985) or `HTTPS` (5986) |

### Real-World Example
**Scenario:** You manage a workgroup server that is not domain-joined. Kerberos is unavailable, so you configure HTTPS to protect credentials in transit.

```powershell
$cert = New-SelfSignedCertificate -DnsName "mgmt01.lab.local" `
    -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)

New-Item -Path WSMan:\localhost\Listener -Transport HTTPS `
    -Address * -CertificateThumbprint $cert.Thumbprint -Force

New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound `
    -LocalPort 5986 -Protocol TCP -Action Allow
```

### Sample Output
```
   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Listener

Type            Keys                                Name
----            ----                                ----
Container       {Transport=HTTPS, Address=*}        Listener_1677421852
```

### Tips & Warnings
> ⚠️ **Never use self-signed certificates in production.** They cannot be validated by clients without manually trusting the cert, making them vulnerable to man-in-the-middle attacks. Use your enterprise CA.

> 💡 **Tip:** After enabling HTTPS, disable the HTTP listener to force encrypted connections:
> ```powershell
> Remove-Item -Path WSMan:\localhost\Listener\Listener_*HTTP -Recurse
> ```

---

## 3. Managing Trusted Hosts

### What it does
The TrustedHosts list tells the WinRM client which remote machines it is allowed to authenticate to via NTLM (without Kerberos mutual authentication). Misconfiguring this opens the door to credential-relay attacks.

### Full Syntax
```powershell
# View current trusted hosts
Get-Item WSMan:\localhost\Client\TrustedHosts

# Set trusted hosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value <String> [-Force]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Value` | String | Comma-separated list of hostnames, IPs, or `*` (wildcard — dangerous) |
| `-Concatenate` | Switch | Append to the existing list instead of overwriting |
| `-Force` | Switch | Skip confirmation prompts |

### Real-World Example
**Scenario:** You need to manage two non-domain workgroup servers from an admin workstation without using `*`.

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.10.50,192.168.10.51" -Force

# Verify
Get-Item WSMan:\localhost\Client\TrustedHosts | Select-Object Value
```

### Sample Output
```
Value
-----
192.168.10.50,192.168.10.51
```

### Tips & Warnings
> ⚠️ **Never set TrustedHosts to `*`.** This allows NTLM authentication to any host, enabling credential theft through relay and spoofing attacks.

> 💡 **Tip:** Prefer HTTPS + certificate validation over TrustedHosts. TrustedHosts is a fallback for workgroup environments, not a security mechanism.

---

## 4. `New-PSSession` Security Options

### What it does
Creates a persistent remote session to a target machine. Security-relevant options control authentication method, encryption, and credential handling.

### Full Syntax
```powershell
New-PSSession
    [-ComputerName] <String[]>
    [-Credential <PSCredential>]
    [-Authentication <AuthenticationMechanism>]
    [-UseSSL]
    [-SessionOption <PSSessionOption>]
    [-ConfigurationName <String>]
    [-Port <Int32>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-ComputerName` | String[] | Target host(s) |
| `-Credential` | PSCredential | Explicit credential object for authentication |
| `-Authentication` | Enum | `Default`, `Kerberos`, `Negotiate`, `NegotiateWithImplicitCredential`, `CredSSP`, `Basic` |
| `-UseSSL` | Switch | Forces connection over HTTPS (port 5986) |
| `-SessionOption` | PSSessionOption | Timeout, proxy, and cancellation settings |
| `-ConfigurationName` | String | Restricts session to a JEA or custom endpoint |

### Real-World Example
**Scenario:** Connect securely to a sensitive server with Kerberos authentication and SSL, using a dedicated admin credential.

```powershell
$cred = Get-Credential -UserName "CORP\tier0-admin" -Message "Enter Tier-0 admin password"

$session = New-PSSession -ComputerName dc01.corp.local `
    -Credential $cred `
    -Authentication Kerberos `
    -UseSSL `
    -ConfigurationName "JEA_DCMaintenance"

Invoke-Command -Session $session -ScriptBlock { Get-ADDomainController -Filter * }
```

### Sample Output
```
 Id Name            ComputerName    ComputerType    State    ConfigurationName
 -- ----            ------------    ------------    -----    -----------------
  1 WinRM1          dc01.corp.local RemoteMachine   Opened   JEA_DCMaintenance
```

### Tips & Warnings
> ⚠️ **Avoid `-Authentication Basic`.** Basic sends credentials in Base64 (not encrypted) unless combined with `-UseSSL`. It is disabled by default for good reason.

> 💡 **Tip:** Use `-ConfigurationName` to connect to JEA (Just Enough Administration) endpoints, which limit what the remote user can execute.

---

## 5. Restricting WinRM via Firewall

### What it does
Limits which source IPs or subnets can reach WinRM ports (5985/5986), reducing the attack surface for lateral movement.

### Full Syntax
```powershell
# Modify the built-in WinRM firewall rule
Set-NetFirewallRule
    -DisplayName "Windows Remote Management (HTTP-In)"
    -RemoteAddress <String[]>
    -Enabled <Boolean>

# Or create a dedicated restrictive rule
New-NetFirewallRule
    -DisplayName <String>
    -Direction Inbound
    -LocalPort <UInt16[]>
    -Protocol TCP
    -RemoteAddress <String[]>
    -Action Allow
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-DisplayName` | String | Human-readable name of the rule |
| `-RemoteAddress` | String[] | Allowed source IPs/subnets (e.g., `10.0.1.0/24`) |
| `-LocalPort` | UInt16[] | Port(s) to filter — `5985` (HTTP) or `5986` (HTTPS) |
| `-Action` | Enum | `Allow` or `Block` |
| `-Profile` | Enum | `Domain`, `Private`, `Public`, or `Any` |

### Real-World Example
**Scenario:** Lock down WinRM so only your admin VLAN (`10.0.1.0/24`) can connect.

```powershell
# Restrict the default HTTP rule
Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" `
    -RemoteAddress "10.0.1.0/24" -Enabled True

# Block WinRM from all other sources explicitly
New-NetFirewallRule -DisplayName "Block WinRM - All Others" `
    -Direction Inbound -LocalPort 5985,5986 -Protocol TCP `
    -Action Block -RemoteAddress Any -Profile Any
```

### Sample Output
```
Name                  : {e1f7b3c2-4d5a-6e7f-8901-abcdef012345}
DisplayName           : Block WinRM - All Others
Direction             : Inbound
Action                : Block
```

### Tips & Warnings
> ⚠️ **Rule order matters.** Windows Firewall processes allow rules before block rules. Create specific allow rules first, then a catch-all block rule.

> 💡 **Tip:** Deploy these rules via Group Policy (`Computer Configuration → Windows Settings → Security Settings → Windows Firewall`) for consistency across your fleet.

---

## 6. Detecting Unauthorized PSRemoting

### What it does
Uses Windows Event Log queries to identify remote PowerShell connections. Key sources are Security event 4624 (logon type 3 — network) and the `Microsoft-Windows-WinRM/Operational` log.

### Full Syntax
```powershell
Get-WinEvent
    -FilterHashtable @{
        LogName     = <String>
        Id          = <Int32[]>
        StartTime   = <DateTime>
    }
    [-MaxEvents <Int64>]
    [-ComputerName <String>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `LogName` | String | Event log name — `Security`, `Microsoft-Windows-WinRM/Operational` |
| `Id` | Int32[] | Event IDs to filter (4624, 91, 168, 6) |
| `StartTime` | DateTime | How far back to search |
| `-MaxEvents` | Int64 | Limit number of results returned |

### Real-World Example
**Scenario:** Your SOC received an alert about unusual network logons at 2 AM. Investigate whether someone used PSRemoting.

```powershell
# Network logon events (Type 3) in the last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = (Get-Date).AddHours(-24)
} | Where-Object { $_.Properties[8].Value -eq 3 } |
    Select-Object TimeCreated,
        @{N='User';E={$_.Properties[5].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}} |
    Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# WinRM session-creation events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-WinRM/Operational'
    Id        = 91
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 50
```

### Sample Output
```
TimeCreated           User             SourceIP
-----------           ----             --------
6/15/2026 2:14:33 AM  CORP\svc-backup  10.99.5.22
6/15/2026 2:12:07 AM  CORP\unknown-adm 10.99.5.22
6/14/2026 11:30:00 PM CORP\jsmith      10.0.1.15
```

### Tips & Warnings
> ⚠️ **Event ID 4624 alone is not conclusive.** Network logons include SMB, WinRM, WMI, and more. Correlate with WinRM Operational event 91 (session created) for confirmation.

> 💡 **Tip:** Forward these events to your SIEM (Splunk, Sentinel) with a Windows Event Forwarding (WEF) subscription for centralized monitoring.

---

## 7. SSH-Based PowerShell Remoting

### What it does
PowerShell 7+ supports SSH as a transport instead of WinRM. This uses the OpenSSH subsystem, enabling cross-platform remoting (Windows, Linux, macOS) and leveraging SSH key authentication.

### Full Syntax
```powershell
New-PSSession
    -HostName <String[]>
    -UserName <String>
    [-KeyFilePath <String>]
    [-SSHTransport]
    [-Port <Int32>]
    [-Subsystem <String>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-HostName` | String[] | Target host(s) for SSH connection |
| `-UserName` | String | SSH username to authenticate as |
| `-KeyFilePath` | String | Path to private SSH key for key-based auth |
| `-SSHTransport` | Switch | Explicitly select SSH transport |
| `-Port` | Int32 | SSH port (default: 22) |
| `-Subsystem` | String | SSH subsystem name (default: `powershell`) |

### Real-World Example
**Scenario:** You manage a mixed Windows/Linux environment and want to avoid WinRM entirely, using SSH key-based authentication.

```powershell
# Connect to a Linux host from PowerShell 7
$session = New-PSSession -HostName linuxweb01.corp.local `
    -UserName adminuser `
    -KeyFilePath ~/.ssh/id_ed25519

Invoke-Command -Session $session -ScriptBlock { uname -a; systemctl status sshd }

# Connect to a Windows host via SSH
Enter-PSSession -HostName win-srv01.corp.local -UserName CORP\admin -SSHTransport
```

### Sample Output
```
 Id Name            Transport ComputerName           ComputerType  State
 -- ----            --------- ------------           ------------  -----
  3 Runspace3       SSH       linuxweb01.corp.local  RemoteMachine Opened
```

### Tips & Warnings
> ⚠️ **Requires OpenSSH Server and a `Subsystem powershell` entry in `sshd_config`.** Without the subsystem configured, SSH connections succeed but PowerShell remoting fails.

> 💡 **Tip:** SSH remoting with key-based auth eliminates password exposure entirely. Combine with `authorized_keys` restrictions (`command=`, `from=`) for zero-trust remote management.

---

## 8. CredSSP Risks and Alternatives

### What it does
CredSSP (Credential Security Support Provider) delegates the user's full credentials to the remote server, allowing multi-hop ("double-hop") authentication. This is extremely dangerous — a compromised remote host can reuse your credentials.

### Full Syntax
```powershell
Enable-WSManCredSSP -Role <String> [-DelegateComputer <String[]>] [-Force]
Disable-WSManCredSSP -Role <String>

# Check CredSSP status
Get-WSManCredSSP
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-Role` | String | `Client` (workstation) or `Server` (target machine) |
| `-DelegateComputer` | String[] | Servers the client is permitted to delegate to |
| `-Force` | Switch | Suppress prompts |

### Real-World Example
**Scenario:** You need a double-hop (admin workstation → jump server → file server). Instead of CredSSP, use Kerberos constrained delegation or resource-based constrained delegation.

```powershell
# ❌ AVOID: CredSSP delegates full credentials
Enable-WSManCredSSP -Role Client -DelegateComputer "jump01.corp.local" -Force

# ✅ PREFERRED: Resource-based Kerberos constrained delegation
$jumpServer = Get-ADComputer -Identity "JUMP01"
Set-ADComputer -Identity "FILESVR01" `
    -PrincipalsAllowedToDelegateToAccount $jumpServer

# Then connect with standard Kerberos — delegation handled by AD
$session = New-PSSession -ComputerName jump01.corp.local -Authentication Kerberos
Invoke-Command -Session $session -ScriptBlock {
    Get-ChildItem \\filesvr01\share$
}
```

### Tips & Warnings
> ⚠️ **CredSSP is a credential-theft goldmine.** If the remote server is compromised, the attacker can capture your plaintext credentials or TGT from memory. Disable it unless there is absolutely no alternative.

> 💡 **Tip:** Audit for CredSSP usage: `Get-WSManCredSSP` on all servers. Any machine returning "This computer is configured to allow delegating fresh credentials" should be investigated.

---

## 9. Kerberos vs NTLM for Remoting

### What it does
Compares the two primary authentication protocols used by WinRM. Kerberos provides mutual authentication, delegation support, and is significantly more secure than NTLM.

### Comparison Table
| Feature | Kerberos | NTLM |
|---------|----------|------|
| Mutual authentication | ✅ Yes | ❌ No |
| Works across domains/trusts | ✅ Yes | ⚠️ Limited |
| Vulnerable to relay attacks | ❌ No | ✅ Yes |
| Requires domain membership | ✅ Yes | ❌ No |
| Delegation support | ✅ Constrained/RBCD | ❌ None |
| Default for domain-joined | ✅ Yes | Fallback only |

### Real-World Example
**Scenario:** Ensure all WinRM connections use Kerberos and block NTLM fallback.

```powershell
# Force Kerberos on a specific session
$s = New-PSSession -ComputerName srv01.corp.local -Authentication Kerberos

# Detect NTLM-based WinRM logons in Security log
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4624
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {
    $_.Properties[8].Value -eq 3 -and   # Network logon
    $_.Properties[14].Value -eq 'NTLM'  # Auth package
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='Source';E={$_.Properties[18].Value}} |
    Format-Table -AutoSize
```

### Sample Output
```
TimeCreated           User             Source
-----------           ----             ------
6/14/2026 3:22:10 PM  CORP\legacysvc   10.5.5.100
6/13/2026 9:15:44 AM  CORP\backupadm   10.5.5.101
```

### Tips & Warnings
> ⚠️ **NTLM is susceptible to relay and pass-the-hash attacks.** If you see NTLM network logons in your domain, investigate and migrate those systems to Kerberos.

> 💡 **Tip:** Use Group Policy to restrict NTLM: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network Security: Restrict NTLM`.

---

## 10. `Get-PSSession` Auditing

### What it does
Lists all active PowerShell remote sessions on the local machine (client-side) or queries a remote computer for disconnected/orphaned sessions. Essential for detecting stale or unauthorized sessions.

### Full Syntax
```powershell
Get-PSSession
    [-ComputerName <String[]>]
    [-State <SessionFilterState>]
    [-ConfigurationName <String>]
    [-Name <String[]>]
```

### Parameters Explained
| Parameter | Type | Description |
|-----------|------|-------------|
| `-ComputerName` | String[] | Query remote machines for sessions connected to them |
| `-State` | Enum | `Opened`, `Disconnected`, `Closed`, `Broken` |
| `-ConfigurationName` | String | Filter by endpoint configuration name |
| `-Name` | String[] | Filter by session name |

### Real-World Example
**Scenario:** During an incident response, enumerate all active and disconnected remote sessions across critical servers.

```powershell
$servers = @("dc01","app01","sql01","file01")

$sessions = $servers | ForEach-Object {
    Get-PSSession -ComputerName $_ -ErrorAction SilentlyContinue
}

$sessions | Select-Object ComputerName, Name, State, ConfigurationName,
    @{N='IdleTimeout(min)';E={$_.IdleTimeout / 60000}} |
    Format-Table -AutoSize

# Disconnect suspicious sessions
$sessions | Where-Object { $_.State -eq 'Opened' -and $_.Name -notlike 'Admin-*' } |
    Disconnect-PSSession
```

### Sample Output
```
ComputerName Name       State        ConfigurationName  IdleTimeout(min)
------------ ----       -----        -----------------  ----------------
dc01         WinRM4     Opened       microsoft.powershell            120
app01        WinRM7     Disconnected microsoft.powershell            120
sql01        Session3   Opened       JEA_SQLMaint                     60
```

### Tips & Warnings
> ⚠️ **Disconnected sessions persist on the server and can be reconnected by the original user.** Attackers may disconnect and later return. Clean up orphaned sessions with `Remove-PSSession`.

> 💡 **Tip:** Set maximum idle timeouts via session configuration: `Set-PSSessionConfiguration -Name microsoft.powershell -MaxIdleTimeoutMs 1800000` (30 minutes).

---

## 11. Detecting Lateral Movement via PS Remoting

### What it does
Identifies patterns consistent with lateral movement — rapid connections to multiple hosts, unusual service accounts using remoting, or connections from non-admin workstations.

### Full Syntax
```powershell
# Query WinRM Operational logs across multiple hosts
Invoke-Command -ComputerName <String[]> -ScriptBlock {
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-WinRM/Operational'
        Id      = <Int32[]>
    }
}
```

### Real-World Example
**Scenario:** Your EDR flagged unusual PS remoting activity. Sweep all servers to build a timeline of remote session creation (Event 91) and identify the source.

```powershell
$allServers = (Get-ADComputer -Filter 'OperatingSystem -like "*Server*"').DnsHostName

$remoteSessions = Invoke-Command -ComputerName $allServers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-WinRM/Operational'
        Id        = 91
        StartTime = (Get-Date).AddHours(-4)
    } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, MachineName, Message
} -ErrorAction SilentlyContinue

# Flag hosts with > 3 sessions in the window (possible spray)
$remoteSessions |
    Group-Object { $_.Message -replace '.*from\s+([\d.]+).*','$1' } |
    Where-Object Count -gt 3 |
    Select-Object Name, Count |
    Sort-Object Count -Descending
```

### Sample Output
```
Name           Count
----           -----
10.99.5.22        14
10.99.5.23         7
10.0.1.50          2
```

### Tips & Warnings
> ⚠️ **Lateral movement via PS remoting is hard to distinguish from normal admin activity.** Baseline your environment first — know which admin hosts and accounts are expected to create sessions.

> 💡 **Tip:** Combine WinRM logs with PowerShell ScriptBlock Logging (Event 4104) to see exactly **what** was executed during each remote session, not just that a connection was made.

---

## 12. WinRM Hardening Best Practices

### What it does
A consolidated checklist of settings and configurations to minimize the attack surface of WinRM across your environment.

### Hardening Checklist

```powershell
# 1. Force HTTPS only — remove HTTP listener
Get-ChildItem WSMan:\localhost\Listener | Where-Object {
    $_.Keys -contains "Transport=HTTP"
} | Remove-Item -Recurse -Force

# 2. Restrict allowed IPs
Set-Item WSMan:\localhost\Service\IPv4Filter -Value "10.0.1.0/24"

# 3. Disable Basic and CredSSP authentication
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false
Disable-WSManCredSSP -Role Server

# 4. Require encrypted traffic (default, but verify)
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false

# 5. Set idle and max-session timeouts
Set-Item WSMan:\localhost\Shell\IdleTimeout -Value 900000    # 15 minutes
Set-Item WSMan:\localhost\Service\MaxConcurrentUsers -Value 5

# 6. Enable audit logging
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true

# 7. Restrict to specific session configuration (JEA)
Disable-PSSessionConfiguration -Name microsoft.powershell -Force
Enable-PSSessionConfiguration -Name JEA_AdminEndpoint -Force
```

### Summary Table
| Setting | Recommended Value | Why |
|---------|------------------|-----|
| Transport | HTTPS only | Encrypts credentials and data in transit |
| Basic Auth | Disabled | Prevents plaintext credential transmission |
| CredSSP | Disabled | Prevents credential delegation and theft |
| AllowUnencrypted | `$false` | Blocks cleartext message exchange |
| TrustedHosts | Specific IPs only | Prevents NTLM relay to arbitrary hosts |
| IdleTimeout | 900000 ms (15 min) | Kills orphaned sessions automatically |
| IPv4Filter | Admin subnet only | Limits network exposure |
| Session Config | JEA endpoint | Applies least-privilege to remote commands |

### Tips & Warnings
> ⚠️ **Apply these settings via Group Policy for consistency.** Manual per-server changes drift over time and are easily missed during provisioning.

> 💡 **Tip:** Test all hardening changes in a staging environment first. Overly restrictive WinRM settings can break SCCM, Ansible, DSC, and other management tools that depend on remoting.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [15 — PowerShell Security and Hardening](15-PowerShell-Security-and-Hardening.md) | [README](../README.md) | [17 — Microsoft Defender and Sentinel](17-Microsoft-Defender-and-Sentinel.md) |
