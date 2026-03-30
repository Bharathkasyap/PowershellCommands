# 22 — Network Forensics and Monitoring

> **Run as:** Local Administrator for most network commands.  
> **Philosophy:** Network artifacts are volatile — capture them early in any investigation before connections are closed or caches expire.

---

## ⚡ Quick Reference

| Technique | Purpose |
|-----------|---------|
| `Get-NetTCPConnection` + process mapping | Map active connections to their owning processes |
| `netsh trace` via PowerShell | Capture network packets without third-party tools |
| Beaconing Detection | Identify periodic C2 callbacks |
| DNS Monitoring (Events 5156/5157) | Track DNS query patterns |
| DNS Tunneling Indicators | Detect data exfiltration via DNS |
| ARP Monitoring | Detect ARP spoofing |
| Disable NetBIOS / LLMNR | Harden against name resolution poisoning |
| Rogue DHCP Detection | Find unauthorized DHCP servers |
| Unusual Listening Ports | Detect backdoor listeners |
| SMB Lateral Movement (Events 5140/5145) | Track file share access |
| Named Pipe Enumeration | Detect C2 and lateral movement via pipes |
| C2 over Allowed Ports | Find C2 channels using standard ports |

---

## 1. Network Connections with Process Mapping

### What it does
Maps every active TCP connection to its owning process, command line, and user — essential for identifying C2 channels and lateral movement.

### Collection Script
```powershell
Get-NetTCPConnection -State Established, Listen |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $($_.OwningProcess)" -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddr   = "$($_.LocalAddress):$($_.LocalPort)"
            RemoteAddr  = "$($_.RemoteAddress):$($_.RemotePort)"
            State       = $_.State
            PID         = $_.OwningProcess
            Process     = $proc.ProcessName
            CommandLine = $cim.CommandLine
            User        = (Invoke-CimMethod -InputObject $cim -MethodName GetOwner -ErrorAction SilentlyContinue).User
        }
    } | Sort-Object Process |
    Format-Table -AutoSize -Wrap
```

### Sample Output
```
LocalAddr          RemoteAddr            State        PID   Process      CommandLine                     User
---------          ----------            -----        ---   -------      -----------                     ----
10.0.0.50:49721    185.220.101.5:443     Established  3456  powershell   powershell.exe -enc JABj...     jsmith
10.0.0.50:445      10.0.0.100:52341      Established  4     System                                      SYSTEM
10.0.0.50:8080     0.0.0.0:0             Listen       6789  nc           nc.exe -lvp 8080                admin
```

### Tips & Warnings
> ⚠️ `nc.exe` (netcat) listening on any port is a backdoor indicator. Also watch for `powershell.exe` with established connections to external IPs.

---

## 2. Packet Capture with `netsh trace`

### What it does
Captures network traffic without installing Wireshark or other tools — built into Windows.

### Collection Script
```powershell
# Start capture
& netsh trace start capture=yes tracefile=E:\forensics\nettrace.etl maxsize=512 overwrite=yes

# Let it run for the desired period...
Start-Sleep -Seconds 300  # 5 minutes

# Stop capture
& netsh trace stop

# Convert to pcapng for Wireshark analysis (requires etl2pcapng tool)
# & etl2pcapng.exe E:\forensics\nettrace.etl E:\forensics\capture.pcapng
```

### Tips & Warnings
> 💡 Filter to reduce capture size: `& netsh trace start capture=yes IPv4.Address=185.220.101.5`

> ⚠️ ETL files can only be read natively by Microsoft Network Monitor. Convert to pcapng for Wireshark.

---

## 3. Beaconing Detection

### What it does
Identifies periodic network connections (beaconing) that indicate C2 communication. Beacons typically connect at regular intervals (e.g., every 60 seconds).

### Detection Script
```powershell
# Collect connection data over time
$connections = @()
for ($i = 0; $i -lt 30; $i++) {
    Get-NetTCPConnection -State Established |
        Where-Object { $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2|3[01])\.|192\.168\.|127\.)' } |
        ForEach-Object {
            $connections += [PSCustomObject]@{
                Time       = Get-Date
                RemoteIP   = $_.RemoteAddress
                RemotePort = $_.RemotePort
                PID        = $_.OwningProcess
                Process    = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            }
        }
    Start-Sleep -Seconds 10
}

# Analyze for beaconing patterns
$connections | Group-Object RemoteIP |
    Where-Object { $_.Count -gt 15 } |  # Connected in >50% of checks
    Select-Object @{n='RemoteIP';e={$_.Name}}, Count,
        @{n='Process';e={($_.Group.Process | Select-Object -Unique) -join ', '}} |
    Sort-Object Count -Descending |
    Format-Table -AutoSize
```

### Sample Output
```
RemoteIP          Count  Process
--------          -----  -------
185.220.101.5     28     svchost
45.33.32.156      22     chrome
```

### Tips & Warnings
> ⚠️ High count + `svchost.exe` to a single external IP = strong C2 indicator. Investigate immediately.

> 💡 Real C2 beacons often add jitter (±10-20%) to avoid perfect periodicity — look for approximately regular patterns.

---

## 4. DNS Monitoring via Event Logs

### What it does
Uses Windows Filtering Platform events (5156/5157) to monitor DNS query activity and detect anomalous DNS patterns.

### Detection Script
```powershell
# DNS queries via WFP events (Event 5156 = allowed connection)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 5156
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 500 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $destPort = ($xml.Event.EventData.Data | Where-Object Name -eq 'DestPort').'#text'
        if ($destPort -eq '53') {
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                Process = ($xml.Event.EventData.Data | Where-Object Name -eq 'Application').'#text'
                DestIP  = ($xml.Event.EventData.Data | Where-Object Name -eq 'DestAddress').'#text'
                PID     = ($xml.Event.EventData.Data | Where-Object Name -eq 'ProcessID').'#text'
            }
        }
    } | Format-Table -AutoSize
```

### Tips & Warnings
> 💡 Enable DNS Client event log for richer data: `wevtutil set-log Microsoft-Windows-DNS-Client/Operational /enabled:true`

---

## 5. DNS Tunneling Detection

### What it does
Detects DNS tunneling — a technique where attackers exfiltrate data by encoding it in DNS query subdomains (e.g., `base64data.evil.com`).

### Detection Script
```powershell
# Analyze DNS cache for tunneling indicators
$dnsCache = Get-DnsClientCache
$suspicious = $dnsCache | Where-Object {
    # Long subdomain labels (>30 chars) indicate encoding
    $_.Entry -match '[a-z0-9]{30,}\.' -or
    # High entropy domain names
    $_.Entry.Split('.')[0].Length -gt 40 -or
    # Unusual TXT record queries
    $_.RecordType -eq 'TXT'
}

if ($suspicious) {
    Write-Host "[ALERT] Potential DNS tunneling detected:" -ForegroundColor Red
    $suspicious | Select-Object Entry, RecordType, Data | Format-Table -AutoSize
} else {
    Write-Host "[OK] No DNS tunneling indicators found" -ForegroundColor Green
}
```

### Sample Output
```
[ALERT] Potential DNS tunneling detected:

Entry                                                    RecordType  Data
-----                                                    ----------  ----
aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com           A           185.220.101.5
dGVzdGluZyBkYXRhIGV4ZmlsdHJhdGlvbg.evil.com             TXT         encoded-response
```

### Tips & Warnings
> ⚠️ High volumes of queries to a single domain with long, random-looking subdomains = DNS tunneling.

---

## 6. ARP Monitoring and Spoofing Detection

### What it does
Monitors the ARP table for signs of ARP spoofing (multiple IPs resolving to the same MAC address).

### Detection Script
```powershell
$arpTable = Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' }

# Detect duplicate MACs (potential ARP spoofing)
$duplicates = $arpTable | Group-Object LinkLayerAddress |
    Where-Object { $_.Count -gt 1 -and $_.Name -ne '00-00-00-00-00-00' -and $_.Name -ne 'FF-FF-FF-FF-FF-FF' }

if ($duplicates) {
    Write-Host "[ALERT] Potential ARP spoofing — duplicate MACs detected:" -ForegroundColor Red
    foreach ($dup in $duplicates) {
        Write-Host "  MAC: $($dup.Name)" -ForegroundColor Yellow
        $dup.Group | Select-Object IPAddress, LinkLayerAddress, State | Format-Table
    }
} else {
    Write-Host "[OK] No ARP spoofing indicators" -ForegroundColor Green
}
```

### Tips & Warnings
> ⚠️ The gateway IP sharing a MAC with another IP is a critical finding — likely an active MITM attack.

---

## 7. Disabling NetBIOS and LLMNR

### What it does
Disables insecure name resolution protocols that attackers exploit for credential capture (Responder/LLMNR poisoning).

### Hardening Script
```powershell
# Disable LLMNR via registry
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

# Disable NetBIOS over TCP/IP on all adapters
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } |
    ForEach-Object {
        $_.SetTcpipNetbios(2)  # 2 = Disable
        Write-Host "Disabled NetBIOS on: $($_.Description)"
    }

# Verify
$llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
Write-Host "LLMNR Disabled: $($llmnr.EnableMulticast -eq 0)"
```

### Tips & Warnings
> ⚠️ Test in a lab first — some legacy applications rely on NetBIOS for name resolution.

> 💡 Also disable WPAD: `New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1`

---

## 8. Rogue DHCP Detection

### What it does
Detects unauthorized DHCP servers on the network that could be used for MITM attacks.

### Detection Script
```powershell
# Check for multiple DHCP servers by examining DHCP events
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Microsoft-Windows-Dhcp-Client'
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'DHCP server' } |
    Select-Object TimeCreated, Message |
    Format-Table -AutoSize -Wrap

# Quick check: compare configured DHCP server vs actual
$adapters = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' }
foreach ($adapter in $adapters) {
    $dhcpServer = (Get-WmiObject Win32_NetworkAdapterConfiguration |
        Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }).DhcpServer
    Write-Host "Adapter: $($adapter.InterfaceAlias)  DHCP Server: $dhcpServer"
}
```

### Tips & Warnings
> 💡 Authorized DHCP servers should be registered in AD. Compare detected servers against: `Get-DhcpServerInDC`

---

## 9. Detecting Unusual Listening Ports

### What it does
Finds processes listening on network ports that may indicate backdoors, reverse shells, or unauthorized services.

### Detection Script
```powershell
# Common legitimate listening ports
$knownPorts = @(80, 443, 445, 135, 139, 3389, 5985, 5986, 53, 88, 389, 636, 3268, 3269)

Get-NetTCPConnection -State Listen |
    Where-Object { $_.LocalPort -notin $knownPorts } |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Port     = $_.LocalPort
            Address  = $_.LocalAddress
            PID      = $_.OwningProcess
            Process  = $proc.ProcessName
            Path     = $proc.Path
        }
    } | Sort-Object Port |
    Format-Table -AutoSize
```

### Sample Output
```
Port  Address    PID   Process     Path
----  -------    ---   -------     ----
4444  0.0.0.0    9876  nc          C:\Temp\nc.exe
8080  0.0.0.0    5432  python      C:\Python39\python.exe
9999  10.0.0.50  1234  backdoor    C:\Users\Public\backdoor.exe
```

### Tips & Warnings
> ⚠️ Port 4444 (Metasploit default), processes in `C:\Temp` or `C:\Users\Public`, and `nc.exe` are critical findings.

---

## 10. SMB Lateral Movement — Events 5140/5145

### What it does
Tracks file share access to detect lateral movement via SMB — attackers use admin shares (C$, ADMIN$) to move between machines.

### Detection Script
```powershell
# Event 5140 = Network share accessed
# Event 5145 = Detailed file share access
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 5140, 5145
    StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 500 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            EventId   = $_.Id
            User      = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
            Source    = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
            Share     = ($xml.Event.EventData.Data | Where-Object Name -eq 'ShareName').'#text'
            File      = ($xml.Event.EventData.Data | Where-Object Name -eq 'RelativeTargetName').'#text'
        }
    } |
    # Flag admin share access
    Where-Object { $_.Share -match '\$' } |
    Format-Table -AutoSize
```

### Sample Output
```
Time                     EventId  User    Source       Share       File
----                     -------  ----    ------       -----       ----
3/29/2026 2:00:00 AM     5145     admin   10.0.0.100   \\*\C$     Windows\Temp\payload.exe
3/29/2026 2:01:00 AM     5145     admin   10.0.0.100   \\*\ADMIN$ psexesvc.exe
```

### Tips & Warnings
> ⚠️ `ADMIN$` access + `psexesvc.exe` = PsExec lateral movement. `C$` writes to `Windows\Temp` = malware staging.

---

## 11. Named Pipe Enumeration

### What it does
Lists named pipes on the system. Some C2 frameworks (Cobalt Strike, Covenant) and lateral movement tools use named pipes for communication.

### Detection Script
```powershell
# List all named pipes
$pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
$suspiciousPatterns = @('msagent_', 'MSSE-', 'postex_', 'status_', 'mojo', 'crashpad', 'beacon')

$pipes | ForEach-Object {
    $pipeName = $_.Replace("\\.\pipe\", "")
    $suspicious = $false
    foreach ($pattern in $suspiciousPatterns) {
        if ($pipeName -match $pattern) { $suspicious = $true; break }
    }
    if ($suspicious) {
        [PSCustomObject]@{
            PipeName   = $pipeName
            Status     = "SUSPICIOUS"
        }
    }
} | Format-Table -AutoSize

Write-Host "Total pipes: $($pipes.Count)"
```

### Tips & Warnings
> ⚠️ Cobalt Strike default pipes include `msagent_*`, `MSSE-*-server`, `postex_*`, and `status_*`.

> 💡 Compare against a baseline of known-good pipes to find anomalies.

---

## 12. C2 over Allowed Ports Detection

### What it does
Identifies C2 channels hiding within commonly allowed ports (80, 443, 53) by analyzing connection patterns and process behavior.

### Detection Script
```powershell
# Find non-browser processes connecting on HTTP/HTTPS ports
$webPorts = @(80, 443)
$browsers = @('chrome','firefox','msedge','iexplore','Teams','OneDrive')

Get-NetTCPConnection -State Established |
    Where-Object { $_.RemotePort -in $webPorts } |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($proc.ProcessName -notin $browsers) {
            [PSCustomObject]@{
                RemoteAddr = "$($_.RemoteAddress):$($_.RemotePort)"
                PID        = $_.OwningProcess
                Process    = $proc.ProcessName
                Path       = $proc.Path
            }
        }
    } | Format-Table -AutoSize
```

### Sample Output
```
RemoteAddr            PID   Process      Path
----------            ---   -------      ----
185.220.101.5:443     3456  rundll32     C:\Windows\System32\rundll32.exe
45.33.32.156:80       7890  svchost      C:\Windows\System32\svchost.exe
```

### Tips & Warnings
> ⚠️ `rundll32.exe` or `svchost.exe` making outbound HTTPS connections to unknown IPs = high-confidence C2.

> 💡 Cross-reference remote IPs with threat intelligence feeds for known C2 infrastructure.

---

## Navigation

| ← Previous | Home | Next → |
|-----------|------|--------|
| [21 — Kerberos and Authentication](21-Kerberos-and-Authentication.md) | [README](../README.md) | [23 — Credential Security and LAPS](23-Credential-Security-and-LAPS.md) |
