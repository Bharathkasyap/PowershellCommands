# 03 — Network Security

> **Modules required:** `NetSecurity`, `NetTCPIP`, `DnsClient` (built into Windows 8.1+ / Server 2012 R2+)  
> **Run as:** Local Administrator for firewall management; standard user for read-only queries.

---

## ⚡ Quick Reference

| Command | Purpose |
|---------|---------|
| `Get-NetFirewallRule` | List existing firewall rules and their settings |
| `New-NetFirewallRule` | Create a new firewall rule |
| `Set-NetFirewallRule` | Modify an existing firewall rule |
| `Get-NetTCPConnection` | Show active and listening TCP connections |
| `Test-NetConnection` | Test connectivity to a host/port (like ping + Telnet in one) |
| `Resolve-DnsName` | Perform DNS lookups — A, MX, TXT, PTR records |
| `Get-NetIPConfiguration` | Show IP addresses, gateways, and DNS servers per adapter |
| `Get-NetAdapter` | List network interface cards and their status |

---

## 1. `Get-NetFirewallRule`

### What it does
Lists Windows Firewall rules. You can see every inbound and outbound rule — its name, action (Allow/Block), direction, ports, protocol, and whether it is enabled. Useful for auditing what traffic is permitted on an endpoint.

### Full Syntax
```powershell
Get-NetFirewallRule
    [[-Name] <String[]>]
    [-DisplayName <String[]>]
    [-Action <Action[]>]
    [-Direction <Direction[]>]
    [-Enabled <Enabled[]>]
    [-Profile <Profile[]>]
    [-PolicyStore <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Name` | Internal rule name |
| `-DisplayName` | User-friendly name — supports wildcards (e.g., `"*RDP*"`) |
| `-Action` | `Allow` or `Block` |
| `-Direction` | `Inbound` or `Outbound` |
| `-Enabled` | `True` or `False` |
| `-Profile` | `Domain`, `Private`, `Public`, or `Any` |

### Real-World Example
**Scenario:** You need to audit which inbound Allow rules are enabled on a workstation to identify unexpected open services.

```powershell
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Select-Object DisplayName, Profile, @{
        n='LocalPort'; e={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}
    } |
    Sort-Object DisplayName |
    Format-Table -AutoSize
```

### Sample Output
```
DisplayName                          Profile   LocalPort
-----------                          -------   ---------
File and Printer Sharing (Echo...)   Domain    Any
Remote Desktop - User Mode (TCP-In)  Domain    3389
Windows Remote Management (HTTP-In)  Domain    5985
```

### Tips & Warnings
> ⚠️ Seeing port **3389 (RDP)** or **5985/5986 (WinRM)** open on Public profile is a serious misconfiguration — those should only be on Domain profile.

> 💡 To get full details including port, protocol, and remote address:
> ```powershell
> Get-NetFirewallRule -DisplayName "*Remote Desktop*" | 
>     Get-NetFirewallPortFilter | Select-Object Protocol, LocalPort, RemotePort
> ```

---

## 2. `New-NetFirewallRule`

### What it does
Creates a new Windows Firewall rule. Essential for hardening endpoints — blocking inbound access to unused ports, or allowing only specific management traffic.

### Full Syntax
```powershell
New-NetFirewallRule
    [-Name <String>]
    -DisplayName <String>
    [-Direction <Direction>]
    [-Protocol <String>]
    [-LocalPort <String[]>]
    [-RemoteAddress <String[]>]
    [-Action <Action>]
    [-Profile <String[]>]
    [-Enabled <Enabled>]
    [-Description <String>]
    [-Program <String>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-DisplayName` | Friendly name shown in the firewall UI |
| `-Direction` | `Inbound` (traffic coming in) or `Outbound` (traffic going out) |
| `-Protocol` | `TCP`, `UDP`, `ICMPv4`, `Any` |
| `-LocalPort` | Port(s) on the local machine to apply the rule to |
| `-RemoteAddress` | Restrict rule to specific source/destination IPs |
| `-Action` | `Allow` or `Block` |
| `-Profile` | `Domain`, `Private`, `Public`, or `Any` |

### Real-World Example
**Scenario:** Block inbound Telnet (port 23) on all profiles — it's an unencrypted legacy protocol with no business use.

```powershell
New-NetFirewallRule `
    -DisplayName "BLOCK Inbound Telnet (SEC)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 23 `
    -Action Block `
    -Profile Any `
    -Enabled True `
    -Description "Block unencrypted Telnet. CIS Benchmark control."
```

### Sample Output
```
Name         : {GUID}
DisplayName  : BLOCK Inbound Telnet (SEC)
Description  : Block unencrypted Telnet. CIS Benchmark control.
DisplayGroup :
Enabled      : True
Profile      : Any
Direction    : Inbound
Action       : Block
```

### Tips & Warnings
> 💡 To allow RDP only from the IT admin subnet:
> ```powershell
> New-NetFirewallRule -DisplayName "Allow RDP from IT Subnet" `
>     -Direction Inbound -Protocol TCP -LocalPort 3389 `
>     -RemoteAddress "10.0.1.0/24" -Action Allow -Profile Domain
> ```

> ⚠️ Always test new block rules in a non-production environment first. A poorly scoped block rule can lock out administrators.

---

## 3. `Set-NetFirewallRule`

### What it does
Modifies an existing firewall rule without deleting and recreating it. Use it to enable/disable a rule, change its action, or update port/address filters.

### Full Syntax
```powershell
Set-NetFirewallRule
    -DisplayName <String>
    [-Enabled <Enabled>]
    [-Action <Action>]
    [-LocalPort <String[]>]
    [-RemoteAddress <String[]>]
    [-Profile <String[]>]
```

### Real-World Example
**Scenario:** During an incident, you need to immediately disable all outbound traffic from a compromised host except DNS (to keep it manageable).

```powershell
# Block all outbound on the compromised machine (run remotely)
Invoke-Command -ComputerName "PC-COMPROMISED-01" -ScriptBlock {
    # Disable all existing outbound Allow rules
    Get-NetFirewallRule -Direction Outbound -Action Allow |
        Set-NetFirewallRule -Enabled False

    # Create a targeted outbound block
    New-NetFirewallRule -DisplayName "INCIDENT - Block All Outbound" `
        -Direction Outbound -Action Block -Protocol Any -Enabled True
}
```

### Tips & Warnings
> ⚠️ Blocking all outbound on a remote machine will break your Invoke-Command session. Ensure you have out-of-band management (IPMI, console) before doing this.

---

## 4. `Get-NetTCPConnection`

### What it does
Displays all current TCP connections and listening ports on the machine — similar to `netstat -ano` but with PowerShell objects you can filter, sort, and export. Essential for spotting C2 (command-and-control) beaconing, unexpected listening services, or unauthorized connections.

### Full Syntax
```powershell
Get-NetTCPConnection
    [-State <TCPState[]>]
    [-LocalPort <UInt16[]>]
    [-RemoteAddress <String[]>]
    [-RemotePort <UInt16[]>]
    [-OwningProcess <UInt32[]>]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-State` | Filter by connection state: `Listen`, `Established`, `TimeWait`, `CloseWait` |
| `-LocalPort` | Filter by local port number |
| `-RemoteAddress` | Filter by remote IP address |
| `-OwningProcess` | Filter by process ID (PID) |

### Real-World Example
**Scenario:** You suspect a machine has an active connection to an external IP. List all established connections and resolve the owning process name.

```powershell
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        @{n='PID'; e={$_.OwningProcess}},
        @{n='ProcessName'; e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
    Where-Object { $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|::1)' } |
    Sort-Object RemoteAddress |
    Format-Table -AutoSize
```

### Sample Output
```
LocalAddress  LocalPort  RemoteAddress    RemotePort  PID   ProcessName
------------  ---------  -------------    ----------  ---   -----------
10.0.0.50     52341      185.220.101.45   443         4832  chrome
10.0.0.50     52398      203.0.113.77     4444        1337  powershell
```

### Tips & Warnings
> ⚠️ **powershell.exe connected to an external IP on a non-standard port** (like 4444 in the sample) is a major red flag — potential reverse shell. Isolate the machine immediately.

> 💡 Check all listening ports (potential backdoors):
> ```powershell
> Get-NetTCPConnection -State Listen |
>     Select-Object LocalAddress, LocalPort,
>         @{n='ProcessName'; e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
>     Sort-Object LocalPort
> ```

---

## 5. `Test-NetConnection`

### What it does
Tests network connectivity to a remote host. It combines ping (ICMP), TCP port test, and route information in a single command. Use it to check if a firewall rule is working, if a service is reachable, or to troubleshoot connectivity.

### Full Syntax
```powershell
Test-NetConnection
    [[-ComputerName] <String>]
    [-Port <Int32>]
    [-CommonTCPPort <String>]
    [-InformationLevel <String>]
    [-TraceRoute]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-ComputerName` | Hostname or IP to test |
| `-Port` | TCP port to test connectivity to |
| `-CommonTCPPort` | Shorthand: `HTTP`, `HTTPS`, `RDP`, `SMB`, `WINRM` |
| `-TraceRoute` | Perform a traceroute |
| `-InformationLevel` | `Quiet` returns only `True`/`False` |

### Real-World Example
**Scenario:** You added a firewall rule to allow port 443 from a web server. Confirm it's working.

```powershell
# Test HTTPS connectivity
Test-NetConnection -ComputerName "webserver.corp.local" -Port 443

# Quick pass/fail check (useful in scripts)
$result = Test-NetConnection -ComputerName "10.0.0.20" -Port 22 -InformationLevel Quiet
if ($result) { Write-Host "SSH is OPEN" -ForegroundColor Red } `
else { Write-Host "SSH is BLOCKED" -ForegroundColor Green }
```

### Sample Output
```
ComputerName     : webserver.corp.local
RemoteAddress    : 10.0.1.80
RemotePort       : 443
InterfaceAlias   : Ethernet
SourceAddress    : 10.0.0.50
TcpTestSucceeded : True
```

### Tips & Warnings
> 💡 Use `-TraceRoute` during incident response to see the network path to a suspicious IP and identify where traffic is being routed.

> 💡 Test multiple ports in a loop:
> ```powershell
> 80, 443, 3389, 445, 22 | ForEach-Object {
>     $open = Test-NetConnection -ComputerName "target.corp.local" -Port $_ -InformationLevel Quiet
>     [PSCustomObject]@{ Port = $_; Open = $open }
> } | Format-Table
> ```

---

## 6. `Resolve-DnsName`

### What it does
Performs DNS lookups from PowerShell. You can query A records (IP addresses), MX records (mail servers), TXT records (SPF/DMARC), reverse lookups (PTR), and more. More flexible than `nslookup`.

### Full Syntax
```powershell
Resolve-DnsName
    [-Name] <String>
    [-Type <RecordType>]
    [-Server <String>]
    [-DnsOnly]
    [-NoHostsFile]
```

### Parameters Explained
| Parameter | Description |
|-----------|-------------|
| `-Name` | Hostname or IP to look up |
| `-Type` | Record type: `A`, `AAAA`, `MX`, `TXT`, `PTR`, `CNAME`, `SOA`, `ANY` |
| `-Server` | Use a specific DNS server for the query |
| `-DnsOnly` | Skip local hosts file, query DNS directly |

### Real-World Example
**Scenario:** You received an alert about traffic to `suspicious-domain.xyz`. You want to check its DNS records and see if it resolves.

```powershell
# Resolve the domain
Resolve-DnsName -Name "suspicious-domain.xyz" -Type A

# Reverse lookup an IP from a firewall alert
Resolve-DnsName -Name "185.220.101.45" -Type PTR

# Check TXT records (often used for C2 tunneling or payload delivery)
Resolve-DnsName -Name "suspicious-domain.xyz" -Type TXT
```

### Sample Output
```
Name                  Type  TTL  Section  IPAddress
----                  ----  ---  -------  ---------
suspicious-domain.xyz A     300  Answer   185.220.101.45
```

### Tips & Warnings
> ⚠️ **Very short TTL values** (under 300 seconds) are often used in domain generation algorithms (DGA) or fast-flux C2 infrastructure. Flag them.

> 💡 TXT records with base64-encoded content or very long strings may indicate DNS-based C2. Inspect them carefully.

---

## 7. `Get-NetIPConfiguration`

### What it does
Shows the full IP configuration for each network adapter — IP address, subnet mask, default gateway, and DNS servers. More concise than `ipconfig /all` and returns proper objects.

### Full Syntax
```powershell
Get-NetIPConfiguration
    [-InterfaceAlias <String>]
    [-InterfaceIndex <UInt32>]
    [-All]
    [-Detailed]
```

### Real-World Example
**Scenario:** During incident response, you need to document the network configuration of a potentially compromised machine.

```powershell
Get-NetIPConfiguration -Detailed | Select-Object InterfaceAlias,
    @{n='IPv4Address'; e={$_.IPv4Address.IPAddress}},
    @{n='Gateway'; e={$_.IPv4DefaultGateway.NextHop}},
    @{n='DNS'; e={$_.DNSServer.ServerAddresses -join ', '}}
```

### Sample Output
```
InterfaceAlias  IPv4Address   Gateway      DNS
--------------  -----------   -------      ---
Ethernet        10.0.0.50     10.0.0.1     10.0.0.10, 10.0.0.11
Wi-Fi           192.168.1.5   192.168.1.1  192.168.1.1
```

### Tips & Warnings
> ⚠️ Multiple active network adapters on a server (especially Wi-Fi on a domain-joined server) is unusual — investigate.

> ⚠️ DNS servers pointing to external/unexpected IPs may indicate DNS hijacking.

---

## 8. `Get-NetAdapter`

### What it does
Lists all network interface cards (NICs) — physical and virtual — along with their link speed, MAC address, and operational status. Useful for inventory, diagnosing connectivity issues, or detecting rogue virtual adapters.

### Full Syntax
```powershell
Get-NetAdapter
    [[-Name] <String[]>]
    [-InterfaceDescription <String[]>]
    [-Physical]
    [-Virtual]
```

### Real-World Example
**Scenario:** You are auditing a server for unusual virtual adapters (which could indicate a VM-based attack tool or VPN software).

```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, 
    MacAddress, LinkSpeed, Virtual |
    Sort-Object Status |
    Format-Table -AutoSize
```

### Sample Output
```
Name      InterfaceDescription          Status  MacAddress         LinkSpeed  Virtual
----      --------------------          ------  ----------         ---------  -------
Ethernet  Intel(R) Ethernet I219-V      Up      00-1A-2B-3C-4D-5E  1 Gbps     False
vEthernet Hyper-V Virtual Ethernet      Up      00-15-5D-AA-BB-CC  10 Gbps    True
Wi-Fi     Intel(R) Wireless-AC 9560     Down    DC-21-5C-DD-EE-FF  0 bps      False
```

### Tips & Warnings
> 💡 Unexpected **virtual adapters** (Hyper-V, TAP, loopback) may indicate VPN clients, attack frameworks (like Metasploit's pivoting modules), or hypervisors installed without authorization.

> 💡 Cross-reference MAC addresses against your DHCP lease table to confirm the machine's identity.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [02 — GPO Management](02-GPO-Management.md) | [README](../README.md) | [04 — Incident Response](04-Incident-Response.md) |
