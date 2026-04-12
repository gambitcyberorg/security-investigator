# Defender for Endpoint - Failed Connections & Logon Attempts

**Created:** 2026-01-13  
**Platform:** Microsoft Sentinel  
**Tables:** DeviceLogonEvents, DeviceNetworkEvents, SecurityEvent, W3CIISLog  
**Keywords:** failed logon, brute force, password spray, failed connection, port scan, blocked attack, endpoint, device, RDP, IIS, authentication, honeypot, multi-layer  
**MITRE:** T1110, T1046, T1190, TA0006, TA0007, TA0001  
**Domains:** endpoint, identity  
**Timeframe:** Last 14 days (configurable)

---

## Overview

This collection contains production-ready KQL queries to identify Defender for Endpoint devices experiencing:
- **Multiple failed login attempts** (potential brute force attacks)
- **Multiple failed network connections** (port scanning, blocked attacks)
- **Combined authentication and network issues** (compromised or targeted devices)

All queries have been tested against live Sentinel data and use proper column names for Microsoft Sentinel (`TimeGenerated` instead of `Timestamp`).

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Devices with Multiple Failed Logon Attempts](#query-1-devices-with-multiple-failed-logon-attempts) | Investigation | `DeviceLogonEvents` |
| 1 | [B: Failed RDP/Auth via SecurityEvent (Layer 2 — Authentication)](#query-1b-failed-rdpauth-via-securityevent-layer-2--authentication) | Investigation | `DeviceLogonEvents` + `SecurityEvent` |
| 1 | [C: IIS Authentication Failures via W3CIISLog (Layer 3 — Application)](#query-1c-iis-authentication-failures-via-w3ciislog-layer-3--application) | Investigation | `DeviceLogonEvents` + `SecurityEvent` |
| 2 | [External Inbound Attack Attempts (Port Scanning/Network Attacks)](#query-2-external-inbound-attack-attempts-port-scanningnetwork-attacks) | Investigation | `DeviceNetworkEvents` |
| 2 | [B: Honeypot Detection - Successful External Inbound Connections](#query-2b-honeypot-detection---successful-external-inbound-connections) | Detection | `DeviceNetworkEvents` |
| 2 | [C: Investigation - Successful Logins Following Network Connections](#query-2c-investigation---successful-logins-following-network-connections) | Investigation | `DeviceLogonEvents` + `DeviceNetworkEvents` |
| 3 | [Combined View - Devices with BOTH Issues](#query-3-combined-view---devices-with-both-issues) | Investigation | `DeviceLogonEvents` + `DeviceNetworkEvents` |
| 4 | [Aggregated Failed Login Report (Honeypot View)](#query-4-aggregated-failed-login-report-honeypot-view) | Investigation | `DeviceLogonEvents` |
| 5 | [Failed Network Connections by Protocol](#query-5-failed-network-connections-by-protocol) | Investigation | `DeviceNetworkEvents` |
| 6 | [Timeline View - Failed Attempts Over Time](#query-6-timeline-view---failed-attempts-over-time) | Investigation | `DeviceLogonEvents` + `DeviceNetworkEvents` |
| 7 | [Geographic Source Analysis (Requires Threat Intelligence)](#query-7-geographic-source-analysis-requires-threat-intelligence) | Investigation | `DeviceLogonEvents` |
| 8 | [Anomaly Detection - Unusual Failed Login Patterns](#query-8-anomaly-detection---unusual-failed-login-patterns) | Detection | `DeviceLogonEvents` |
| — | [Adjust Thresholds](#adjust-thresholds) | Investigation | — |
| — | [Change Time Range](#change-time-range) | Investigation | — |
| — | [Filter by Specific Devices](#filter-by-specific-devices) | Investigation | — |
| — | [Add Exclusions for Known Good IPs](#add-exclusions-for-known-good-ips) | Investigation | — |
| — | [Export to CSV for Analysis](#export-to-csv-for-analysis) | Investigation | — |
| 1. | [Add Early Filters](#1-add-early-filters) | Investigation | — |
| 2. | [Use Summarize Early](#2-use-summarize-early) | Investigation | — |
| 3. | [Limit Result Sets](#3-limit-result-sets) | Investigation | — |
| 4. | [Use Materialize for Reused Data](#4-use-materialize-for-reused-data) | Investigation | `DeviceLogonEvents` |


## Multi-Layer Attack Detection Model

Internet-facing servers (especially honeypots) are attacked across three distinct layers. Each layer requires a **different table** and provides unique visibility:

| Layer | Table | What It Captures | Key Filter / EventID | Visibility |
|-------|-------|-------------------|---------------------|------------|
| **1. Network** | `DeviceNetworkEvents` | TCP/UDP handshakes, connection attempts | `LocalPort in (3389, 80, 443, 445, 22)` | Attacker reached NIC — measures scanning volume |
| **2. Auth** | `SecurityEvent` | Windows logon attempts (success/failure) | EventID `4625` / `4624` / `4771` | Attacker supplied credentials — measures brute force |
| **3. Application** | `W3CIISLog` | IIS HTTP requests (200/401/403/500) | `scStatus == 401` | Attacker reached IIS — measures web exploitation |

**Why this matters:**

- **`DeviceLogonEvents`** (MDE table) captures endpoint-managed logon telemetry but **dramatically under-samples external RDP/NLA brute force** on Windows Server. Live testing shows MDE reports ~0.2% of the actual volume (e.g., 47 events vs 20,000 in SecurityEvent for the same attacker IP). `SecurityEvent` (Windows Security auditing) is the **only authoritative source** for EventID 4625.
- **`DeviceNetworkEvents`** captures TCP-level events, but brute force attacks that reach the auth layer appear as **successful TCP connections** (`InboundConnectionAccepted`), NOT as `ConnectionFailed` or `InboundConnectionBlocked`. The TCP handshake succeeds — authentication fails at a higher layer. This means Query 2 (failed/blocked connections) will miss RDP brute force entirely. Use Query 2B (successful inbound) + Query 1B (SecurityEvent 4625) for the complete picture.
- A single attacker IP may appear in **all three layers**: TCP handshake (DeviceNetworkEvents) → RDP authentication failure (SecurityEvent 4625) → IIS exploitation attempt (W3CIISLog 401).
- Zero results at one layer doesn't mean no attack — it means the attack was stopped at a lower layer or the table has insufficient coverage.

**Signal ratio across layers (observed on honeypot server):**

| Layer | Table | Same Attacker IP | Coverage |
|-------|-------|-------------------|----------|
| Network | `DeviceNetworkEvents` (InboundConnectionAccepted) | 1–4 events | ~0.005% |
| Auth (MDE) | `DeviceLogonEvents` (LogonFailed) | 47 events | ~0.2% |
| Auth (Windows) | `SecurityEvent` (EventID 4625) | 20,000 events | **100% (authoritative)** |

> **⚠️ Key takeaway:** MDE heavily samples/aggregates network and logon events. For accurate brute-force volume assessment, **always use SecurityEvent** (Query 1B). DeviceLogonEvents (Query 1) is useful for detecting the presence of attacks but will dramatically undercount their volume.

**Investigation workflow:** Query all three layers, then cross-correlate IPs to build the full attack chain. Start with SecurityEvent (Query 1B) for accurate volume, then use DeviceNetworkEvents (Query 2B) for successful connection enumeration.

---

## Query 1: Devices with Multiple Failed Logon Attempts

**Purpose:** Detect potential brute force attacks or credential guessing attempts targeting your devices.

> **⚠️ Coverage Note:** `DeviceLogonEvents` is MDE-managed telemetry that **dramatically under-samples external RDP brute force** — live testing shows it captures approximately **0.2% of actual volume** compared to SecurityEvent (e.g., 47 vs 20,000 events for the same attacker IP). For authoritative failed RDP logon data, **always use Query 1B** (`SecurityEvent` EventID 4625). This query is useful for detecting the *presence* of attacks but will severely undercount volume. Best suited for internal logon failures and credential misuse detected by Defender for Endpoint.

**Thresholds:**
- Minimum 5 failed logon attempts per device/IP combination
- Aggregates by device and remote IP address
- Shows unique accounts targeted and logon types used

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "CredentialAccess"
title: "Brute Force: {{FailedAttempts}} failed logons on {{DeviceName}} from {{RemoteIP}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Remove `| take 20` and `| order by` for production CD deployment. Threshold (>=5 attempts) is tunable per environment."
-->
```kql
// Query 1: Devices with Multiple Failed Logon Attempts (14 days)
// Detects potential brute force attacks or credential guessing attempts
DeviceLogonEvents
| where TimeGenerated > ago(14d)
| where ActionType == "LogonFailed"
| summarize 
    FailedAttempts = count(),
    UniqueAccounts = dcount(AccountName),
    Accounts = make_set(AccountName, 10),
    FirstFailed = min(TimeGenerated),
    LastFailed = max(TimeGenerated),
    LogonTypes = make_set(LogonType)
    by DeviceName, RemoteIP
| where FailedAttempts >= 5
| extend Duration = LastFailed - FirstFailed
| project DeviceName, RemoteIP, FailedAttempts, UniqueAccounts, Accounts, FirstFailed, LastFailed, Duration, LogonTypes
| order by FailedAttempts desc
| take 20
```

**Expected Results:**
- **DeviceName**: Target device name
- **RemoteIP**: Attacking IP address
- **FailedAttempts**: Total number of failed login attempts
- **UniqueAccounts**: Number of different accounts targeted
- **Accounts**: List of up to 10 account names attempted
- **FirstFailed / LastFailed**: Time window of attack
- **Duration**: Length of attack campaign
- **LogonTypes**: Types of logon attempts (Network, RemoteInteractive, etc.)

**Indicators of Attack:**
- High `FailedAttempts` (50+) = aggressive brute force
- High `UniqueAccounts` (20+) = password spraying attack
- Short `Duration` with many attempts = automated attack tool
- `LogonType` = "Network" from external IP = remote attack

---

## Query 1B: Failed RDP/Auth via SecurityEvent (Layer 2 — Authentication)

**Purpose:** Detect failed RDP logon attempts using Windows Security Event log — the authoritative source for authentication-layer brute force on Windows servers. This query captures EventID 4625 (logon failure) which `DeviceLogonEvents` may miss for external RDP attacks.

**Layer:** Authentication (see [Multi-Layer Attack Detection Model](#multi-layer-attack-detection-model))

**Key Differences from Query 1:**

| Factor | Query 1 (`DeviceLogonEvents`) | Query 1B (`SecurityEvent`) |
|--------|-------------------------------|---------------------------|
| Source | MDE agent telemetry | Windows Security audit log |
| RDP coverage | May miss external NLA failures | Authoritative for all logon types |
| Computer field | `DeviceName` (lowercase) | `Computer` (often UPPERCASE — use `=~` for case-insensitive) |
| IP extraction | `RemoteIP` column | `IpAddress` column (may be `-` or empty; extract from `EventData` as fallback) |

**Thresholds:**
- Minimum 5 failed logon attempts per Computer/IP combination
- Excludes IpAddress of `-` or empty (local/system failures)
- LogonType 10 = RemoteInteractive (RDP); LogonType 3 = Network

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "CredentialAccess"
title: "RDP Brute Force: {{FailedAttempts}} failed logons on {{Computer}} from {{SourceIP}}"
impactedAssets:
  - type: "host"
    identifier: "hostName"
adaptation_notes: "Remove `| take 30` and `| order by` for production CD deployment. Threshold (>=5 attempts) is tunable. IpAddress extraction fallback (EventData parsing) can be removed if IpAddress column is reliably populated in your workspace. Use `SecurityEvent` table — requires Sentinel Data Lake or AH with connected workspace."
-->
```kql
// Query 1B: Failed RDP/Auth via SecurityEvent (14 days)
// Authoritative source for Windows logon failures — captures what DeviceLogonEvents misses
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID == 4625
// Extract IP — prefer IpAddress column, fall back to EventData parsing
| extend SourceIP = iff(IpAddress != "-" and isnotempty(IpAddress), IpAddress,
    extract(@"Source Network Address:\s+([^\s]+)", 1, tostring(EventData)))
| where isnotempty(SourceIP) and SourceIP != "-" and SourceIP != "127.0.0.1"
| summarize
    FailedAttempts = count(),
    UniqueAccounts = dcount(TargetAccount),
    Accounts = make_set(TargetAccount, 10),
    LogonTypes = make_set(LogonType),
    FirstFailed = min(TimeGenerated),
    LastFailed = max(TimeGenerated)
    by Computer, SourceIP
| where FailedAttempts >= 5
| extend Duration = LastFailed - FirstFailed
| project Computer, SourceIP, FailedAttempts, UniqueAccounts, Accounts,
    LogonTypes, FirstFailed, LastFailed, Duration
| order by FailedAttempts desc
| take 30
```

**Expected Results:**
- **Computer**: Target device (often UPPERCASE in SecurityEvent)
- **SourceIP**: Attacking IP address
- **FailedAttempts**: Total failed logon attempts
- **UniqueAccounts**: Number of different accounts targeted (high count = password spray)
- **Accounts**: Up to 10 account names attempted
- **LogonTypes**: `3` = Network, `10` = RemoteInteractive (RDP), `8` = NetworkCleartext

**When to prefer Query 1B over Query 1:**
- Investigating **RDP brute force** against internet-facing servers
- Query 1 returns 0 results but DeviceNetworkEvents shows inbound connections to port 3389
- You need the **authoritative** Windows Security audit log rather than MDE agent telemetry

**Troubleshooting Low Results:**

If Query 1B returns fewer results than expected, verify:

1. **Windows audit policy** on the target server logs Logon Failure events:
   ```powershell
   auditpol /get /subcategory:"Logon"
   # Expected: Logon: Success and Failure
   ```
2. **SecurityEvent data connector** in Sentinel collects EventID 4625 (configure under "Common" or "All Events" tier, not "Minimal")
3. **Server uptime** — intermittent availability reduces auth event volume even when scanning is constant

---

## Query 1C: IIS Authentication Failures via W3CIISLog (Layer 3 — Application)

**Purpose:** Detect IIS-level brute force and web exploitation attempts. When attackers reach an IIS web server, their activity appears as HTTP 401 (Unauthorized) responses and exploitation payloads in W3CIISLog — a data source invisible to both `DeviceLogonEvents` and `SecurityEvent`.

**Layer:** Application (see [Multi-Layer Attack Detection Model](#multi-layer-attack-detection-model))

**Thresholds:**
- Minimum 3 failed requests per IP (low threshold — IIS exploitation attempts are often low-volume, high-impact)
- Filters to HTTP `401`/`403` status codes for attack detection

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregates by client IP across all target URIs — would need restructuring for per-path alerting in CD. `scStatus` grouping produces enriched context but complicates single-entity mapping. Consider splitting into separate 401-focused (brute force) and 404-focused (recon) detection rules for CD deployment."
-->
```kql
// Query 1C: IIS Brute Force & Web Exploitation via W3CIISLog (14 days)
// Detects HTTP-level attacks invisible to DeviceLogonEvents and SecurityEvent
W3CIISLog
| where TimeGenerated > ago(14d)
| where scStatus in (401, 403)
// Exclude internal/monitoring traffic
| where cIP !startswith "10."
| where cIP !startswith "192.168."
| where cIP !startswith "172.16." and cIP !startswith "172.17." and cIP !startswith "172.18." and cIP !startswith "172.19."
| where cIP !startswith "172.20." and cIP !startswith "172.21." and cIP !startswith "172.22." and cIP !startswith "172.23."
| where cIP !startswith "172.24." and cIP !startswith "172.25." and cIP !startswith "172.26." and cIP !startswith "172.27."
| where cIP !startswith "172.28." and cIP !startswith "172.29." and cIP !startswith "172.30." and cIP !startswith "172.31."
| where cIP !startswith "127."
| summarize
    FailedRequests = count(),
    Status401 = countif(scStatus == 401),
    Status403 = countif(scStatus == 403),
    TargetPaths = make_set(csUriStem, 10),
    Methods = make_set(csMethod, 5),
    UserAgents = make_set(csUserAgent, 3),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by cIP, Computer
| where FailedRequests >= 3
| extend Duration = LastSeen - FirstSeen
| extend AttackType = case(
    Status401 > 10, "HTTP Brute Force",
    TargetPaths has_any ("eval-stdin", "phpunit", ".env", "wp-login", "wp-admin"), "Web Exploitation",
    TargetPaths has_any ("actuator", "console", "manager", "admin"), "Admin Panel Recon",
    Status403 > Status401, "Access Probing",
    "General Scanning")
| project cIP, Computer, FailedRequests, Status401, Status403, AttackType,
    TargetPaths, UserAgents, FirstSeen, LastSeen, Duration
| order by FailedRequests desc
| take 30
```

**Expected Results:**
- **cIP**: Attacking IP address
- **Computer**: Target IIS server
- **FailedRequests**: Total 401/403 responses (HTTP authentication failures + forbidden)
- **AttackType**: Categorized attack vector:
  - `HTTP Brute Force`: >10 consecutive 401s — credential stuffing against IIS auth
  - `Web Exploitation`: Known exploit paths (phpunit eval-stdin, .env file exposure, WordPress)
  - `Admin Panel Recon`: Probing for management consoles (Tomcat, Spring Actuator)
  - `Access Probing`: Mostly 403 Forbidden — testing directory permissions
  - `General Scanning`: Low-volume recon
- **TargetPaths**: URI stems targeted — reveals attack intent
- **UserAgents**: Scanner identification

**Common Web Exploitation Payloads:**

| Path | Attack | MITRE |
|------|--------|-------|
| `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` | CVE-2017-9841 — Remote code execution via PHPUnit | T1190 |
| `/.env` | Environment file exposure (credentials, API keys) | T1552.001 |
| `/wp-login.php`, `/wp-admin/` | WordPress admin brute force | T1110 |
| `/actuator/health`, `/actuator/env` | Spring Boot Actuator information leak | T1190 |
| `/hello.world` | Scanner fingerprinting probe | T1595.002 |

**Cross-Layer Correlation:**

After identifying IIS attacker IPs, check if the same IPs also appear at the auth layer:

```kql
// Cross-reference IIS attackers in SecurityEvent
let IISAttackers = W3CIISLog
    | where TimeGenerated > ago(14d)
    | where scStatus in (401, 403)
    | where cIP !startswith "10." and cIP !startswith "192.168." and cIP !startswith "127."
    | summarize FailedHTTP = count() by cIP
    | where FailedHTTP >= 3
    | project cIP;
// Did they also try Windows auth?
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID == 4625
| where IpAddress in (IISAttackers) or IpAddress != "-"
| summarize AuthFailures = count() by IpAddress, Computer
| join kind=inner (IISAttackers) on $left.IpAddress == $right.cIP
| project IpAddress, Computer, AuthFailures
```

---

## Query 2: External Inbound Attack Attempts (Port Scanning/Network Attacks)

**Purpose:** Detect external attackers attempting inbound connections to your devices - port scanning, brute force connection attempts, or blocked attacks from the internet.

**Key Features:**
- Filters to **external IPs only** (excludes RFC1918 private ranges, localhost, Azure infrastructure)
- Focuses on **inbound** connection attempts (RemoteIP → LocalPort)
- Detects port scanning patterns and targeted attacks
- Minimum 10 attempts to reduce noise

**Thresholds:**
- Minimum 10 inbound attempts from single external IP
- Excludes internal network traffic (10.x, 192.168.x, 172.16-31.x)
- Excludes Azure metadata services (168.63.129.16, 169.254.169.254)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregates across multiple devices per RemoteIP — each row represents an attacker IP, not a specific device. Would need restructuring to produce per-device rows for CD entity mapping. Also, verbose RFC1918 filter consumes significant character budget."
-->
```kql
// Query 2: External Inbound Attack Attempts (14 days)
// Detects external attackers attempting to connect to your devices (port scanning, brute force, blocked attacks)
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where ActionType in ("InboundConnectionBlocked", "ConnectionFailed", "ConnectionAttempt")
// Filter to only EXTERNAL IPs (exclude private RFC1918 ranges, localhost, Azure metadata)
| where RemoteIP !startswith "10."
| where RemoteIP !startswith "192.168."
| where RemoteIP !startswith "172.16." and RemoteIP !startswith "172.17." and RemoteIP !startswith "172.18." and RemoteIP !startswith "172.19." 
| where RemoteIP !startswith "172.20." and RemoteIP !startswith "172.21." and RemoteIP !startswith "172.22." and RemoteIP !startswith "172.23."
| where RemoteIP !startswith "172.24." and RemoteIP !startswith "172.25." and RemoteIP !startswith "172.26." and RemoteIP !startswith "172.27."
| where RemoteIP !startswith "172.28." and RemoteIP !startswith "172.29." and RemoteIP !startswith "172.30." and RemoteIP !startswith "172.31."
| where RemoteIP !startswith "127."
| where RemoteIP != "168.63.129.16"  // Azure metadata service
| where RemoteIP != "169.254.169.254"  // Azure IMDS
| where RemoteIP !has ":"  // Exclude IPv6 for now (mostly internal/link-local)
// Focus on inbound attempts where remote is initiating TO our LocalPort
| where isnotempty(LocalPort)
| summarize 
    InboundAttempts = count(),
    TargetedPorts = make_set(LocalPort, 15),
    TargetedDevices = dcount(DeviceName),
    Devices = make_set(DeviceName, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP
| where InboundAttempts >= 10
| extend Duration = LastSeen - FirstSeen
| project RemoteIP, InboundAttempts, TargetedPorts, TargetedDevices, Devices, FirstSeen, LastSeen, Duration
| order by InboundAttempts desc
| take 20
```

**Expected Results:**
- **RemoteIP**: External attacking IP address
- **InboundAttempts**: Number of inbound connection attempts from this IP
- **TargetedPorts**: Which ports on your devices the attacker tried to reach
- **TargetedDevices**: Number of your devices this IP attempted to connect to
- **Devices**: Sample of device names targeted
- **FirstSeen / LastSeen**: Time window of attack activity
- **Duration**: How long the attack campaign lasted

**Indicators of Attack:**
- High `InboundAttempts` (50+) = aggressive port scanning
- High `TargetedDevices` (5+) = network-wide scanning
- Multiple high ports = port sweep looking for open services
- Common attack ports in `TargetedPorts`:
  - **22**: SSH brute force
  - **23**: Telnet exploitation
  - **80/443**: Web service attacks
  - **445/139**: SMB/NetBIOS exploitation
  - **3389**: RDP brute force
  - **1433/3306**: Database attacks (MSSQL/MySQL)
  - **8080/8443**: Alternative web ports

> **⚠️ Critical limitation:** This query filters to `ConnectionFailed`, `InboundConnectionBlocked`, and `ConnectionAttempt` — but **RDP brute force attacks will NOT appear here**. When an attacker connects to port 3389, the TCP handshake succeeds (appearing as `InboundConnectionAccepted` in Query 2B), and authentication fails at the auth layer (SecurityEvent 4625). The `ConnectionFailed` events in DeviceNetworkEvents are typically outbound failures or internal monitoring noise (e.g., `monitoringhost.exe`), not inbound attack traffic. `InboundConnectionBlocked` may not exist in all environments (0 events observed in testing). This query is most useful for detecting **port scanning** where the TCP connection itself is rejected/blocked, not for brute force detection.

**Note:** `DeviceNetworkEvents` only logs what reaches the device network stack. If perimeter controls (NSG, firewall, JIT) block traffic upstream, it won't appear here. Cross-reference with Query 1B (SecurityEvent 4625) for authentication-layer attacks and Query 2B for successful inbound connections.

> **⚠️ FourToSixMapping note:** This query uses RFC1918 exclusion filters (not `RemoteIPType == "Public"`), which correctly catches all non-private IPs regardless of MDE's dual-stack classification. However, if adapting this query to use `RemoteIPType` filtering instead, be aware that IIS and other dual-stack listeners cause MDE to classify inbound IPv4 connections as `FourToSixMapping` rather than `Public`. Always include both: `RemoteIPType in ("Public", "FourToSixMapping")`. See `queries/network/internet_exposure_analysis.md` for full details.

---

## Query 2B: Honeypot Detection - Successful External Inbound Connections

**Purpose:** For honeypot servers, detect SUCCESSFUL inbound connections from external IPs - indicating attackers successfully bypassed network defenses and reached your services.

**Use Case:**
- Honeypot security analysis (intentionally exposed systems)
- Detect attackers who successfully connected to services (RDP, SSH, HTTP)
- Correlate with Query 1 to see which IPs succeeded at network layer then tried authentication
- Track attack progression: Network connection → Authentication attempt → (potential compromise)

**Thresholds:**
- No minimum threshold (all successful external connections are relevant for honeypots)
- Focuses on common attack ports (RDP, SSH, HTTP, SMB, etc.)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Honeypot-specific query requiring manual device parameter substitution (`<HONEYPOT_DEVICE>`). Aggregates by RemoteIP across ports. Intended for ad-hoc honeypot investigation, not automated alerting."
-->
```kql
// Query 2B: Honeypot Detection - Successful External Inbound Connections (14 days)
// Detects successful inbound connections from external IPs to honeypot services
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
// Replace with your honeypot device name:
| where DeviceName startswith "<HONEYPOT_DEVICE>"  // Use startswith — DeviceName is often FQDN (e.g., hostname.domain.com)
// Focus on SUCCESSFUL inbound connections (not blocked/failed)
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted", "ConnectionFound")
// Common attack ports (RDP, HTTP, HTTPS, SMB, SSH, FTP, Telnet, alt-HTTP)
| where LocalPort in (3389, 80, 443, 445, 22, 21, 23, 8080, 8443, 139, 135)
// Filter to only EXTERNAL IPs (exclude RFC1918 private ranges, localhost)
| where RemoteIP !startswith "10."
| where RemoteIP !startswith "192.168."
| where RemoteIP !startswith "172.16." and RemoteIP !startswith "172.17." and RemoteIP !startswith "172.18." and RemoteIP !startswith "172.19."
| where RemoteIP !startswith "172.20." and RemoteIP !startswith "172.21." and RemoteIP !startswith "172.22." and RemoteIP !startswith "172.23."
| where RemoteIP !startswith "172.24." and RemoteIP !startswith "172.25." and RemoteIP !startswith "172.26." and RemoteIP !startswith "172.27."
| where RemoteIP !startswith "172.28." and RemoteIP !startswith "172.29." and RemoteIP !startswith "172.30." and RemoteIP !startswith "172.31."
| where RemoteIP !startswith "127."
| where RemoteIP != "::1"  // IPv6 localhost
| summarize
    TotalAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetPorts = make_set(LocalPort),
    ActionTypes = make_set(ActionType)
    by RemoteIP
| extend Duration = LastSeen - FirstSeen
| project RemoteIP, TotalAttempts, TargetPorts, ActionTypes, FirstSeen, LastSeen, Duration
| order by TotalAttempts desc
| take 50
```

**Expected Results:**
- **RemoteIP**: External IP that successfully connected
- **TotalAttempts**: Number of successful connections (1 = single probe, 2+ = persistent)
- **TargetPorts**: Which services the attacker accessed (e.g., [3389] = RDP only, [80,3389] = HTTP + RDP)
- **ActionTypes**: Connection types (InboundConnectionAccepted = standard connection)
- **FirstSeen / LastSeen**: Time window of attacker activity
- **Duration**: How long attacker maintained access/probing

**Next Steps:**
1. **Correlate with Query 1/1B**: Did these IPs also attempt authentication?
2. **Enrich IPs**: Use `python enrich_ips.py <IP1> <IP2> ...` to get abuse scores, geolocation, VPN/proxy detection
3. **Block confirmed malicious IPs**: Update NSG/firewall rules
4. **Check for successful logins**: Review authentication logs for these IPs

**Tip:** Some IPs with high AbuseIPDB scores may be legitimate security scanners (e.g., Censys, Shodan). Check the `whitelisted` field in AbuseIPDB to distinguish.

---

## Query 2C: Investigation - Successful Logins Following Network Connections

**Purpose:** Correlate successful network connections (Query 2B) with successful authentication attempts to identify potential compromises.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-step correlation/investigation query with manual device parameter (`<HONEYPOT_DEVICE>`). Uses `let` subquery feeding into join — requires restructuring for CD single-query format. Intended for post-incident investigation, not automated detection."
-->
```kql
// Query 2C: Correlation - Network Connections → Successful Authentication
// STEP 1: Get IPs that successfully connected to honeypot services
let SuccessfulConnections = DeviceNetworkEvents
    | where TimeGenerated > ago(14d)
    | where DeviceName startswith "<HONEYPOT_DEVICE>"  // Use startswith — FQDN safe
    | where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted", "ConnectionFound")
    | where LocalPort in (3389, 80, 443, 445, 22, 21, 23, 8080, 8443)
    | where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
    | distinct RemoteIP;
// STEP 2: Check if ANY of those IPs successfully authenticated
DeviceLogonEvents
| where TimeGenerated > ago(14d)
| where DeviceName startswith "<HONEYPOT_DEVICE>"  // Use startswith — FQDN safe
| where RemoteIP in (SuccessfulConnections)
| where ActionType == "LogonSuccess"  // ⚠️ CRITICAL: Successful logins from attackers
| summarize
    SuccessfulLogins = count(),
    FirstLogin = min(TimeGenerated),
    LastLogin = max(TimeGenerated),
    Accounts = make_set(AccountName),
    LogonTypes = make_set(LogonType)
    by RemoteIP, DeviceName
| project RemoteIP, SuccessfulLogins, Accounts, LogonTypes, FirstLogin, LastLogin
| order by SuccessfulLogins desc
```

**⚠️ CRITICAL ALERT:**
Any results from this query indicate **CONFIRMED COMPROMISE** - external attackers successfully authenticated to your system.

**Immediate Response Actions:**
1. **Isolate device** from network immediately
2. **Reset passwords** for all compromised accounts
3. **Revoke sessions** for affected accounts
4. **Full forensic investigation** - check for malware, lateral movement, data exfiltration
5. **Block attacking IPs** at perimeter firewall/NSG
6. **Review audit logs** for attacker actions post-authentication

---

## Query 3: Combined View - Devices with BOTH Issues

**Purpose:** Find devices experiencing both authentication failures AND network connection problems - likely indicators of active targeting or compromise.

**Thresholds:**
- Minimum 5 failed logons
- Minimum 10 failed network connections
- Only shows devices meeting BOTH criteria

```kql
// Query 3: Combined View - Failed Logons AND Network Connection Failures
// Devices experiencing both authentication and network connection issues
DeviceLogonEvents
| where TimeGenerated > ago(14d)
| where ActionType == "LogonFailed"
| summarize LogonFailures = count() by DeviceName
| where LogonFailures >= 5
| join kind=inner (
    DeviceNetworkEvents
    | where TimeGenerated > ago(14d)
    | where ActionType in ("ConnectionFailed", "InboundConnectionBlocked")
    | summarize NetworkFailures = count() by DeviceName
    | where NetworkFailures >= 10
) on DeviceName
| project DeviceName, LogonFailures, NetworkFailures, TotalIssues = LogonFailures + NetworkFailures
| order by TotalIssues desc
| take 10
```

**Expected Results:**
- **DeviceName**: Device under active attack
- **LogonFailures**: Failed authentication attempts
- **NetworkFailures**: Failed network connections
- **TotalIssues**: Combined total (prioritization metric)

**Indicators of Compromise:**
- Any results from this query warrant immediate investigation
- High correlation between authentication and network failures = coordinated attack
- Typical attack pattern: Port scan → Service enumeration → Authentication attempts
- Recommend: Review firewall logs, check for successful logins from same IPs, inspect device for malware

> **⚠️ False Positive Warning:** The `NetworkFailures` count from `DeviceNetworkEvents` may include **internal monitoring noise** (e.g., `monitoringhost.exe` connecting to localhost, Azure monitoring agents, etc.) rather than external attacks. In testing, alpine-srv1 showed 32 "network failures" — all were internal `::1` / `127.0.0.1` connections from monitoring processes, not external attackers. The `LogonFailures` count from `DeviceLogonEvents` is also heavily under-sampled (see Query 1 Coverage Note). For accurate attack volume, cross-reference with **SecurityEvent** (Query 1B) for authentication data and **Query 2B** for external inbound connections.

---

## Query 4: Aggregated Failed Login Report (Honeypot View)

**Purpose:** Use Defender's aggregated reporting feature to detect repeated sign-in failures with reduced log volume.

**Note:** Aggregated events condense multiple similar events into a single record with metadata about occurrence count.

> **⚠️ Availability:** The `LogonFailedAggregatedReport` ActionType is **not present on all devices**. In testing, alpine-srv1 (which had 409 `LogonFailed` events) produced **0** aggregated report events. This feature depends on MDE agent version, device configuration, and the volume/pattern of failures. If this query returns 0 results, fall back to Query 1 (individual events) or Query 1B (SecurityEvent) for failed logon detection.

```kql
// Query 4: Aggregated Failed Login Report (14 days)
// Leverages Defender's aggregated reporting to reduce log volume while detecting attacks
DeviceLogonEvents
| where TimeGenerated > ago(14d)
| where ActionType == "LogonFailedAggregatedReport"
| extend uniqueEventsAggregated = toint(todynamic(AdditionalFields).uniqueEventsAggregated)
| where uniqueEventsAggregated > 10
| project-reorder TimeGenerated, DeviceName, DeviceId, uniqueEventsAggregated, LogonType, AccountName, AccountDomain, AccountSid
| order by uniqueEventsAggregated desc
| take 20
```

**Expected Results:**
- **uniqueEventsAggregated**: Number of similar failed login events condensed into this record
- Threshold of >10 indicates persistent attack attempts
- More efficient than scanning every individual failed login event

**Use Case:**
- Perfect for detecting slow brute force attacks (below typical alerting thresholds)
- Reduces data volume while maintaining detection capability
- Recommended for scheduled reports and automated alerting

---

## Query 5: Failed Network Connections by Protocol

**Purpose:** Break down network failures by protocol to identify attack types (RDP scans, SSH brute force, SMB exploits).

```kql
// Query 5: Failed Network Connections by Protocol (14 days)
// Categorizes network failures by protocol to identify attack vectors
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where ActionType in ("ConnectionFailed", "InboundConnectionBlocked")
| summarize 
    FailedConnections = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueRemoteIPs = dcount(RemoteIP),
    Devices = make_set(DeviceName, 5),
    RemoteIPs = make_set(RemoteIP, 5)
    by Protocol, RemotePort
| where FailedConnections >= 10
| extend AttackType = case(
    RemotePort == 3389, "RDP Brute Force",
    RemotePort == 22, "SSH Brute Force",
    RemotePort in (445, 139), "SMB/NetBIOS Exploit",
    RemotePort in (135, 593), "RPC/DCE Enumeration",
    RemotePort == 389, "LDAP Attack",
    RemotePort in (80, 443, 8080, 8443), "Web Service Attack",
    "Other Protocol"
)
| project Protocol, RemotePort, AttackType, FailedConnections, UniqueDevices, UniqueRemoteIPs, Devices, RemoteIPs
| order by FailedConnections desc
```

**Expected Results:**
- **Protocol**: Network protocol (TCP, UDP, ICMP)
- **RemotePort**: Target port number
- **AttackType**: Categorized attack vector
- **FailedConnections**: Total failed attempts
- **UniqueDevices**: Number of your devices targeted
- **UniqueRemoteIPs**: Number of attacking IPs
- **Devices**: Sample devices affected
- **RemoteIPs**: Sample attacking IPs

**Use Case:**
- Identify primary attack vectors targeting your environment
- Prioritize firewall rule updates based on most frequent attacks
- Correlate with threat intelligence feeds for known attack campaigns

---

## Query 6: Timeline View - Failed Attempts Over Time

**Purpose:** Visualize attack patterns over the 14-day period to identify spikes and ongoing campaigns.

```kql
// Query 6: Timeline View - Failed Logons and Network Connections Over Time
// Visualizes attack patterns to identify spikes and persistent threats
union 
(
    DeviceLogonEvents
    | where TimeGenerated > ago(14d)
    | where ActionType == "LogonFailed"
    | summarize FailedLogons = count() by bin(TimeGenerated, 1h)
    | extend EventType = "Failed Logons"
),
(
    DeviceNetworkEvents
    | where TimeGenerated > ago(14d)
    | where ActionType in ("ConnectionFailed", "InboundConnectionBlocked")
    | summarize FailedConnections = count() by bin(TimeGenerated, 1h)
    | extend EventType = "Failed Network Connections"
)
| extend EventCount = coalesce(FailedLogons, FailedConnections)
| project TimeGenerated, EventType, EventCount
| order by TimeGenerated asc
| render timechart
```

**Expected Results:**
- Time series chart showing hourly failed events over 14 days
- Two series: Failed Logons (authentication) and Failed Network Connections
- **Visualization:** Use "Time Chart" in Azure portal for best results

**Use Case:**
- Identify attack campaigns (sustained elevated activity)
- Detect DDoS attempts (massive spikes in short periods)
- Correlate with known incidents or security events
- Establish baseline for normal failed connection rates

---

## Query 7: Geographic Source Analysis (Requires Threat Intelligence)

**Purpose:** Identify attacking IP addresses and correlate with geographic locations and threat intelligence.

```kql
// Query 7: Geographic Source Analysis of Failed Logon Attempts
// Correlates attacking IPs with locations and threat intelligence data
DeviceLogonEvents
| where TimeGenerated > ago(14d)
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize 
    FailedAttempts = count(),
    TargetedDevices = dcount(DeviceName),
    TargetedAccounts = dcount(AccountName),
    Devices = make_set(DeviceName, 5),
    Accounts = make_set(AccountName, 5)
    by RemoteIP
| where FailedAttempts >= 10
| order by FailedAttempts desc
| take 50
```

**Expected Results:**
- **RemoteIP**: Attacking IP address
- **FailedAttempts**: Total failed login attempts from this IP
- **TargetedDevices**: Number of your devices this IP attacked
- **TargetedAccounts**: Number of accounts this IP targeted
- **Devices**: Sample device names
- **Accounts**: Sample account names

**Next Steps:**
1. **Copy IP addresses** from results
2. **Enrich using external tools:**
   - AbuseIPDB (check abuse confidence score)
   - Threat intelligence platforms (VirusTotal, AlienVault)
   - ipinfo.io or MaxMind (geolocation, ISP, VPN detection)
3. **Block at firewall** if confirmed malicious
4. **Check for successful logins** from these IPs with this query:
   ```kql
   DeviceLogonEvents
   | where RemoteIP in ("<IP1>", "<IP2>", "<IP3>")
   | where ActionType == "LogonSuccess"
   ```

**Integration with workspace tools:**
Use the `enrich_ips.py` utility in this workspace to automate IP enrichment:
```powershell
python enrich_ips.py <IP1> <IP2> <IP3>
```

---

## Query 8: Anomaly Detection - Unusual Failed Login Patterns

**Purpose:** Detect devices with abnormal failed login patterns compared to historical baselines.

```kql
// Query 8: Anomaly Detection - Devices with Unusual Failed Login Patterns
// Identifies devices with failed login rates significantly above their baseline
let BaselinePeriod = 7d;
let RecentPeriod = 1d;
let Threshold = 3.0; // Alert if recent failures are 3x baseline average
// Calculate baseline average
let Baseline = DeviceLogonEvents
    | where TimeGenerated between (ago(BaselinePeriod + RecentPeriod) .. ago(RecentPeriod))
    | where ActionType == "LogonFailed"
    | summarize BaselineFailures = count() by DeviceName
    | extend BaselineAvgPerDay = BaselineFailures / 7.0;
// Calculate recent activity
let Recent = DeviceLogonEvents
    | where TimeGenerated > ago(RecentPeriod)
    | where ActionType == "LogonFailed"
    | summarize RecentFailures = count() by DeviceName;
// Compare and flag anomalies
Baseline
| join kind=inner (Recent) on DeviceName
| extend AnomalyRatio = RecentFailures / BaselineAvgPerDay
| where AnomalyRatio >= Threshold
| project DeviceName, BaselineAvgPerDay, RecentFailures, AnomalyRatio
| order by AnomalyRatio desc
```

**Expected Results:**
- **DeviceName**: Device with unusual activity
- **BaselineAvgPerDay**: Normal daily failed login rate (from previous 7 days)
- **RecentFailures**: Failed logins in last 24 hours
- **AnomalyRatio**: How many times above baseline (3.0 = 300% increase)

**Use Case:**
- Detect NEW attack campaigns targeting previously safe devices
- Identify compromised credentials (sudden spike in authentication attempts)
- Automated alerting based on deviation from normal behavior
- Adjust `Threshold` variable based on your environment (lower = more sensitive)

---

## Tuning and Customization

### Adjust Thresholds

All queries use conservative thresholds to minimize false positives. Adjust based on your environment:

```kql
// Lower threshold for high-security environments
| where FailedAttempts >= 3  // Instead of 5

// Increase threshold for noisy environments
| where FailedAttempts >= 20  // Instead of 5
```

### Change Time Range

All queries use 14 days. Modify the lookback period:

```kql
// Last 7 days
| where TimeGenerated > ago(7d)

// Last 30 days
| where TimeGenerated > ago(30d)

// Specific date range
| where TimeGenerated between (datetime(2026-01-01) .. datetime(2026-01-13))
```

### Filter by Specific Devices

Focus on specific device groups:

```kql
// Domain controllers only
| where DeviceName has_any ("DC1", "DC2", "DC-")

// Exclude known noisy devices
| where DeviceName !in ("test-vm", "lab-system")

// Specific IP subnets
| where RemoteIP startswith "185."  // Specific network block
```

### Add Exclusions for Known Good IPs

Exclude legitimate failed connections (VPN, monitoring tools):

```kql
// Add after the initial where clause
| where RemoteIP !in ("10.0.0.1", "192.168.1.1")  // Internal IPs
| where RemoteIP !startswith "10."  // Entire private subnet
```

---

## Alert Rule Recommendations

### High Priority Alert: Active Brute Force Attack
- **Trigger:** Query 1 results with `FailedAttempts >= 50` and `Duration < 5 minutes`
- **Severity:** High
- **Action:** Auto-block IP at firewall, notify SOC

### Medium Priority Alert: Password Spraying
- **Trigger:** Query 1 results with `UniqueAccounts >= 20`
- **Severity:** Medium
- **Action:** Review affected accounts, check for successful logins

### Low Priority Alert: Network Scanning
- **Trigger:** Query 2 results with `UniqueRemoteIPs >= 30`
- **Severity:** Low
- **Action:** Review and update firewall rules

### Critical Alert: Dual Attack Pattern
- **Trigger:** Any results from Query 3
- **Severity:** Critical
- **Action:** Isolate device, full forensic investigation

---

## Investigation Workflow

When queries return results:

1. **Validate Threat:**
   - Check if remote IPs are known malicious (threat intel)
   - Review successful logins from same source IPs
   - Correlate with other security events

2. **Assess Impact:**
   - Were any login attempts successful?
   - What accounts were targeted (privileged vs. standard)?
   - How many devices affected?

3. **Contain Threat:**
   - Block attacking IPs at firewall/NSG
   - Reset passwords for targeted accounts
   - Enable MFA if not already deployed
   - Isolate compromised devices

4. **Investigate Root Cause:**
   - Review device logs for malware
   - Check for credential theft indicators
   - Examine network traffic for lateral movement
   - Review recent software changes or vulnerabilities

5. **Document and Report:**
   - Create incident record
   - Document timeline of events
   - Record mitigation actions taken
   - Share indicators of compromise (IOCs) with team

---

## Integration with Security Tools

### Export to CSV for Analysis
```kql
// Add to end of any query
| evaluate bag_unpack(Accounts)  // Expand arrays to columns
```

### PowerShell Integration
```powershell
# Run query and export results
$query = @"
DeviceLogonEvents
| where TimeGenerated > ago(14d)
| where ActionType == "LogonFailed"
| summarize count() by RemoteIP
| where count_ >= 10
"@

# Use Azure CLI or PowerShell to execute
Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query | Export-Csv "failed_logins.csv"
```

### Sentinel Analytics Rules

Convert these queries into Sentinel Analytics Rules:
1. Copy query to Sentinel Analytics blade
2. Set entity mappings (IP, Account, Host)
3. Configure alert grouping and suppression
4. Define incident creation logic
5. Set automation playbooks (auto-block IPs, notify teams)

---

## Performance Optimization

For large environments with millions of events:

### 1. Add Early Filters
```kql
// Filter by specific device group first
| where DeviceName has "PROD-"
| where TimeGenerated > ago(14d)
```

### 2. Use Summarize Early
```kql
// Aggregate before filtering
| summarize count() by DeviceName, RemoteIP
| where count_ >= 5
```

### 3. Limit Result Sets
```kql
// Always use take/top
| take 100  // Limit to 100 results
```

### 4. Use Materialize for Reused Data
```kql
let ReusableData = materialize(
    DeviceLogonEvents
    | where TimeGenerated > ago(14d)
    | where ActionType == "LogonFailed"
);
// Now use ReusableData multiple times efficiently
```

---

## Schema Reference

### DeviceLogonEvents Key Columns
- **TimeGenerated**: Event timestamp (Sentinel)
- **DeviceName**: Fully qualified domain name
- **ActionType**: LogonFailed, LogonSuccess, LogonAttempted
- **RemoteIP**: Source IP of logon attempt
- **AccountName**: Target account username
- **AccountDomain**: Domain of target account
- **LogonType**: Network, RemoteInteractive, Interactive, etc.
- **AdditionalFields**: JSON with extra metadata

### DeviceNetworkEvents Key Columns
- **TimeGenerated**: Event timestamp (Sentinel)
- **DeviceName**: Fully qualified domain name
- **ActionType**: ConnectionSuccess, ConnectionFailed, InboundConnectionBlocked
- **RemoteIP**: Remote endpoint IP
- **RemotePort**: Remote port number
- **LocalIP**: Local IP address
- **Protocol**: TCP, UDP, ICMP, etc.
- **InitiatingProcessAccountName**: Process owner account

---

## Platform Differences

**⚠️ CRITICAL: Sentinel vs. Defender XDR Syntax**

| Feature | Microsoft Sentinel | Defender XDR (Advanced Hunting) |
|---------|-------------------|--------------------------------|
| Timestamp Column | `TimeGenerated` | `Timestamp` |
| Time Filter | `TimeGenerated > ago(14d)` | `Timestamp > ago(14d)` |
| Documentation | Azure Monitor logs schema | Microsoft 365 Defender schema |

**All queries in this document use Sentinel syntax (`TimeGenerated`).**

To use these queries in Defender XDR Advanced Hunting portal:
```kql
# Find and replace
TimeGenerated → Timestamp
```

---

## Additional Resources

- **Microsoft Learn:** [DeviceLogonEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- **Microsoft Learn:** [DeviceNetworkEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- **Defender XDR Docs:** [Advanced Hunting best practices](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices)
- **Sentinel Analytics:** [Create custom detection rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)

---

## Version History

- **v1.1** (2026-01-13): Added Query 2B (Honeypot successful connections) and Query 2C (Compromise correlation)
  - Real-world honeypot attack analysis (185.156.73.74, 185.243.96.116, etc.)
  - IP enrichment results showing 22-100% abuse scores
  - Censys scanner identification and false positive guidance
  - Enhanced Query 1 with coordinated attack campaign findings
  - Network layer → Authentication layer correlation workflows
- **v1.0** (2026-01-13): Initial release with 8 production-tested queries for Sentinel
  - All queries validated against live Sentinel workspace
  - Includes real-world test results and examples

---

## Support

For questions or issues with these queries:
1. Review the schema reference and platform differences sections
2. Check Microsoft Learn documentation for latest schema changes
3. Test queries with `| take 10` first to validate syntax
4. Adjust thresholds based on your environment's baseline activity

**Workspace Integration:**
- Use `enrich_ips.py` for IP address enrichment
- Reference `.github/copilot-instructions.md` for investigation workflows
- Follow KQL query authoring skill guidelines in `.github/skills/kql-query-authoring/`
