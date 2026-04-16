# SMB/NTLM Threat Detection — Brute-Force, Lateral Movement & External Access

**Created:** 2026-04-16  
**Platform:** Both  
**Tables:** SecurityEvent, DeviceLogonEvents  
**Keywords:** SMB, NTLM, lateral movement, brute force, password spray, credential stuffing, failed logon, network logon, EventID 4624, EventID 4625, LogonType 3, Network, external SMB, internet-facing, port 445, Kerberos  
**MITRE:** T1021.002, T1110.001, T1110.003, T1133, TA0008, TA0006  
**Domains:** endpoint, identity  
**Timeframe:** Last 7 days (configurable)

---

## Overview

This file covers **SMB/NTLM network logon threat scenarios** with queries for both `SecurityEvent` and `DeviceLogonEvents`:

- **Part A:** Internal lateral movement via SMB/NTLM (compromised workstation pivoting across the domain)
- **Part B:** External Network logon brute-force via `SecurityEvent` (has SubStatus failure codes for triage)
- **Part C:** External Network logon brute-force via `DeviceLogonEvents` (richer device context, no failure codes)

**Companion files:**
- **RDP threats:** See `queries/endpoint/rdp_threat_detection.md` for RemoteInteractive (LogonType 10) detection — applies when NLA is disabled
- **Threat Pulse Q4:** Surfaces both RDP and Network Logon brute-force — the `Surface` column distinguishes `Endpoint (RDP)` from `Endpoint (Network Logon)`. Note: `Network Logon` is ambiguous (could be SMB or NLA-RDP) — see NLA caveat below

**Key difference from RDP file:** SMB/NTLM uses `LogonType == 3` (Network) in SecurityEvent and `LogonType == "Network"` in DeviceLogonEvents. The `Protocol` column in DeviceLogonEvents distinguishes `NTLM` (SMB) from `Kerberos` (domain auth). SecurityEvent provides `SubStatus` failure reason codes that DeviceLogonEvents lacks — critical for distinguishing username enumeration (`0xC0000064`) from bad password (`0xC000006A`).

### ⚠️ NLA-RDP Ambiguity — READ BEFORE INTERPRETING RESULTS

**`LogonType 3` (Network) + `NTLM` protocol does NOT guarantee SMB traffic.** RDP with Network Level Authentication (NLA) enabled produces **identical** logon events: `LogonType == "Network"`, `Protocol == "NTLM"`, `ActionType == "LogonFailed"`. NLA performs CredSSP authentication at the TLS layer *before* the RDP session is established, so Windows logs it as a Network logon, not RemoteInteractive.

**Before concluding "SMB brute-force", you MUST disambiguate the port:**

```kql
// Disambiguation: Check which port the external IPs are actually connecting to
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName == "<TARGET_DEVICE>"
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| where LocalPort in (445, 3389)
| summarize Connections = count(), UniqueIPs = dcount(RemoteIP) by LocalPort
```

| Result | Interpretation |
|--------|----------------|
| **Port 445 only** | Confirmed SMB brute-force — these queries apply directly |
| **Port 3389 only** | NLA-RDP brute-force — use `rdp_threat_detection.md` instead |
| **Both ports** | Mixed — split analysis by port, use both query files |
| **Neither port** | Other Network service — investigate `DeviceNetworkEvents` for actual port |

**Common misinterpretation:** Internet-facing devices with port 3389 exposed will show massive `Network` + `NTLM` logon failures that look like SMB spray but are actually RDP-via-NLA. Always cross-reference with Threat Pulse Q11 (internet exposure) or `DeviceNetworkEvents` port data before reporting "SMB exposure."

---

---

## Quick Reference — Query Index

**Investigation shortcuts:**
- **Internet-facing device with SMB brute-force** (TP Q4, Q11): **Q7/Q10** (scope attack) → **Q8/Q11** (success check) → **Q9/Q12** (breach correlation)
- **SMB failure reason triage** (TP Q4): **Q5/Q7** (has SubStatus) — Q10 does NOT surface failure reasons
- **Internal lateral movement from incident device** (TP Q1): **Q3** (baseline) → **Q2** (failed-then-success) → **Q4** (spray across targets) → **Q5** (failure reasons)
- **Post-compromise SMB timeline** (TP Q1, incident follow-up): **Q6** (chronological progression for a specific source IP)
- **Part B vs Part C:** Use Part B (SecurityEvent) if connector is configured — provides SubStatus failure reasons. Fall back to Part C (DeviceLogonEvents) if not — richer device context but no failure codes

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Successful Internal SMB Authentications (Baseline)](#query-1-successful-internal-smb-authentications-baseline) | Dashboard | `DeviceLogonEvents` |
| 2 | [Internal SMB Lateral Movement - Failed Then Success (PRIMARY DETECT...](#query-2-internal-smb-lateral-movement---failed-then-success-primary-detection) | Detection | `DeviceLogonEvents` |
| 3 | [Internal SMB Activity Summary with Failure Rates](#query-3-internal-smb-activity-summary-with-failure-rates) | Dashboard | `DeviceLogonEvents` |
| 4 | [Internal SMB Spray - One Source, Many Targets](#query-4-internal-smb-spray---one-source-many-targets) | Detection | `DeviceLogonEvents` |
| 5 | [Failed SMB Attempts by Failure Reason](#query-5-failed-smb-attempts-by-failure-reason) | Investigation | `DeviceLogonEvents` + `SecurityEvent` |
| 6 | [SMB Timeline - Visualize Attack Progression](#query-6-smb-timeline---visualize-attack-progression) | Investigation | `DeviceLogonEvents` |
| 7 | [External SMB Brute-Force Summary (SecurityEvent)](#query-7-external-smb-brute-force-summary-securityevent) | Dashboard | `SecurityEvent` |
| 8 | [External SMB Successful Access (SecurityEvent)](#query-8-external-smb-successful-access-securityevent) | Investigation | `SecurityEvent` |
| 9 | [External SMB Failed-Then-Success Correlation (SecurityEvent)](#query-9-external-smb-failed-then-success-correlation-securityevent) | Investigation | `SecurityEvent` |
| 10 | [External SMB Brute-Force Detection (DeviceLogonEvents)](#query-10-external-smb-brute-force-detection-devicelogonevents) | Detection | `DeviceLogonEvents` |
| 11 | [Successful External SMB Access (DeviceLogonEvents)](#query-11-successful-external-smb-access-devicelogonevents) | Investigation | `DeviceLogonEvents` |
| 12 | [External SMB Failed-Then-Success Correlation (DeviceLogonEvents)](#query-12-external-smb-failed-then-success-correlation-devicelogonevents) | Investigation | `DeviceLogonEvents` |


## Part A: Internal Lateral Movement (DeviceLogonEvents)

> **Source filter:** RFC 1918 private IPs only. For external/internet-facing SMB, skip to [Part B](#part-b-external-smb-brute-force-securityevent).

### Query 1: Successful Internal SMB Authentications (Baseline)

**Purpose:** Identify all successful internal Network logons to establish baseline SMB activity patterns

**Use this query to:**
- Understand normal SMB/NTLM usage patterns in your environment
- Identify which systems accept Network logons and from where
- Verify query is returning data before running detection logic

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline verification query. Returns raw events with `take 100` for data validation, not detection logic."
-->
```kql
// Successful Internal SMB/Network Connections (Last 7 Days)
// Use this query first to verify DeviceLogonEvents data is available
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where isnotempty(RemoteIP)
| where RemoteIP startswith "10." or RemoteIP startswith "192.168."
    or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
| project Timestamp, DeviceName, AccountName, AccountDomain, RemoteIP,
    Protocol, IsLocalAdmin
| order by Timestamp desc
| take 100
```

**Expected Results:**
- `Timestamp`: When the Network logon occurred
- `DeviceName`: Target system that was accessed
- `AccountName`: User account that logged on
- `RemoteIP`: Internal IP address of the source system
- `Protocol`: Authentication protocol (`NTLM`, `Kerberos`, `Negotiate`)
- `IsLocalAdmin`: Whether the account has local admin rights on the target

**Tuning:**
- Filter by protocol: Add `| where Protocol == "NTLM"` to isolate SMB-specific activity
- Focus on specific systems: Add `| where DeviceName has "server-name"`
- Exclude machine accounts: Add `| where AccountName !endswith "$"`

---

### Query 2: Internal SMB Lateral Movement - Failed Then Success (PRIMARY DETECTION)

**Purpose:** Detect potential credential stuffing or pass-the-hash attacks where multiple failed Network logon attempts precede a successful logon from the same internal source

**Thresholds:**
- Minimum 3 failed attempts
- Within 30-minute window before successful logon
- From same source IP to same target device

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
title: "SMB Lateral Movement: {{FailedAttempts}} failures then logon on {{DeviceName}} from {{RemoteIP}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Multi-let correlation query. CD supports `let` blocks. Remove `order by` for CD. Thresholds (failureThreshold=3, windowTime=30m) are tunable."
-->
```kql
// Internal SMB Lateral Movement — Failed Then Success
// Detects internal Network logons with 3+ failed attempts within 30 minutes before successful logon
let timeframe = 7d;
let failureThreshold = 3;
let windowTime = 30m;
let Failed = DeviceLogonEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "LogonFailed"
    | where LogonType == "Network"
    | where isnotempty(RemoteIP)
    | where RemoteIP startswith "10." or RemoteIP startswith "192.168."
        or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    | summarize
        FailedAttempts = count(),
        FailedAccounts = make_set(AccountName, 5),
        Protocols = make_set(Protocol, 3),
        FirstFailure = min(Timestamp),
        LastFailure = max(Timestamp)
        by RemoteIP, DeviceName;
let Success = DeviceLogonEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "LogonSuccess"
    | where LogonType == "Network"
    | where isnotempty(RemoteIP)
    | where RemoteIP startswith "10." or RemoteIP startswith "192.168."
        or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    | project SuccessTime = Timestamp, DeviceName, SuccessAccount = AccountName,
        RemoteIP, Protocol, IsLocalAdmin;
Failed
| where FailedAttempts >= failureThreshold
| join kind=inner Success on RemoteIP, DeviceName
| where SuccessTime between (FirstFailure .. (LastFailure + windowTime))
| project RemoteIP, DeviceName, FailedAttempts, FailedAccounts,
    FirstFailure, LastFailure, SuccessTime, SuccessAccount, Protocol, IsLocalAdmin, Protocols
| order by FailedAttempts desc
```

**Expected Results:**
- `RemoteIP`: Source IP performing the lateral movement
- `DeviceName`: Target system that was accessed
- `FailedAttempts`: Count of failed attempts before success
- `FailedAccounts`: Accounts that failed authentication
- `SuccessAccount`: Account that successfully logged on
- `Protocol`: Auth protocol of the successful logon
- `IsLocalAdmin`: Whether the successful account is local admin

**Indicators of Lateral Movement:**
- **Different success vs failure accounts:** Attacker tried multiple creds, found valid one
- **NTLM protocol on Kerberos-capable domain:** Pass-the-hash attack (NTLM doesn't require domain controller interaction)
- **IsLocalAdmin = true:** Attacker gained admin access
- **Short time window (<5 min):** Automated tooling (Mimikatz, CrackMapExec)
- **Server-to-server or workstation-to-server:** Unusual Network logon flow

**Tuning:**
- **More sensitive:** Decrease `failureThreshold` to 2
- **Less noise:** Increase `failureThreshold` to 5
- **Tighter window:** Decrease `windowTime` to 10m

**False Positives:**
- GPO-triggered service account logons with cached stale credentials
- SCCM/ConfigMgr client push installations
- Monitoring tools scanning multiple endpoints with service accounts

---

### Query 3: Internal SMB Activity Summary with Failure Rates

**Purpose:** Aggregate view of all internal Network logon activity showing success/failure patterns for baselining and anomaly identification

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline aggregation query. Summarizes all internal Network logon activity per RemoteIP for pattern analysis, not alertable detection."
-->
```kql
// Internal SMB Activity Summary by Source IP
// Shows all internal Network logon activity (successes and failures) for baselining
let timeframe = 7d;
DeviceLogonEvents
| where Timestamp > ago(timeframe)
| where LogonType == "Network"
| where isnotempty(RemoteIP)
| where RemoteIP startswith "10." or RemoteIP startswith "192.168."
    or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
| summarize
    TotalAttempts = count(),
    SuccessCount = countif(ActionType == "LogonSuccess"),
    FailCount = countif(ActionType == "LogonFailed"),
    UniqueTargetDevices = dcount(DeviceName),
    TargetDevices = make_set(DeviceName, 10),
    UniqueAccounts = dcount(AccountName),
    Accounts = make_set(AccountName, 5),
    Protocols = make_set(Protocol, 3),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP
| extend FailureRate = round(FailCount * 100.0 / TotalAttempts, 1)
| where FailCount > 0
| project-reorder RemoteIP, UniqueTargetDevices, UniqueAccounts, TotalAttempts,
    SuccessCount, FailCount, FailureRate, Protocols
| order by FailCount desc, UniqueTargetDevices desc
```

**Expected Results:**
- `RemoteIP`: Source system IP
- `UniqueTargetDevices`: Number of different devices targeted
- `TotalAttempts`: Total Network logon attempts
- `SuccessCount` / `FailCount`: Success and failure counts
- `FailureRate`: Percentage of failed attempts
- `Protocols`: Auth protocols used (`NTLM`, `Kerberos`)

**Indicators of Suspicious Activity:**
- **High failure rate (>30%) + NTLM:** Possible pass-the-hash or credential stuffing
- **Many target devices + failures:** Lateral movement spray
- **100% failure rate:** Failed attack or misconfigured service
- **NTLM-only in Kerberos domain:** PtH attack indicator (attackers use NTLM to bypass Kerberos)

---

### Query 4: Internal SMB Spray - One Source, Many Targets

**Purpose:** Detect an internal system performing Network logon attempts against multiple other systems — classic post-exploitation behavior (CrackMapExec, Mimikatz, Impacket)

**Thresholds:**
- Minimum 3 unique target devices
- Within 1-hour window
- From single internal source IP

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "LateralMovement"
title: "SMB Spray: {{RemoteIP}} targeted {{UniqueTargets}} systems via {{TopProtocol}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Threshold-based spray detection. Each row = one spray instance from a source IP. Remove `order by` for CD. Thresholds (targetThreshold=3, windowTime=1h) are tunable."
-->
```kql
// Internal SMB Spray Detection — One Source, Many Targets
// Identifies single internal source attempting Network logons to multiple systems
let timeframe = 7d;
let targetThreshold = 3;
let windowTime = 1h;
DeviceLogonEvents
| where Timestamp > ago(timeframe)
| where LogonType == "Network"
| where isnotempty(RemoteIP)
| where RemoteIP startswith "10." or RemoteIP startswith "192.168."
    or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
| summarize
    TotalAttempts = count(),
    SuccessCount = countif(ActionType == "LogonSuccess"),
    FailCount = countif(ActionType == "LogonFailed"),
    UniqueTargets = dcount(DeviceName),
    TargetSystems = make_set(DeviceName, 10),
    Accounts = make_set(AccountName, 5),
    Protocols = make_set(Protocol, 3),
    FirstAttempt = min(Timestamp),
    LastAttempt = max(Timestamp)
    by RemoteIP, bin(Timestamp, windowTime)
| where UniqueTargets >= targetThreshold
| extend TimeSpan = LastAttempt - FirstAttempt
| extend TopProtocol = tostring(Protocols[0])
| project-reorder Timestamp, RemoteIP, UniqueTargets, SuccessCount, FailCount,
    TotalAttempts, TopProtocol, TimeSpan
| order by UniqueTargets desc, Timestamp desc
```

**Expected Results:**
- `RemoteIP`: Source system performing the spray
- `UniqueTargets`: Number of different systems targeted
- `SuccessCount`: Successful Network logons
- `FailCount`: Failed attempts
- `TopProtocol`: Primary auth protocol used
- `TimeSpan`: Duration of spray activity

**Indicators of Lateral Movement:**
- **NTLM-only + many targets + mixed success/fail:** CrackMapExec or similar tool
- **All successes + many targets:** Active lateral movement with valid credentials
- **Kerberos + all successes:** Likely legitimate (GPO, SCCM) — but verify account
- **After-hours timing:** Attacker activity
- **Workstation → servers:** Unusual direction for Network logons

**Tuning:**
- **Exclude domain controllers:** DCs legitimately contact many devices. Add `| where RemoteIP !in ("<DC_IP_1>", "<DC_IP_2>")`
- **Exclude known admin tools:** SCCM, monitoring, backup servers
- **Focus on NTLM:** Add `| where Protocols has "NTLM"` for PtH-specific detection

---

### Query 5: Failed SMB Attempts by Failure Reason

**Purpose:** Understand why Network logon authentications are failing — distinguishes username enumeration from password guessing

**Sub-Status Codes (Common):**
- `0xC0000064`: User name does not exist — **username enumeration**
- `0xC000006A`: Bad password — **credential guessing**
- `0xC000006D`: Bad username or password (alternate)
- `0xC000006E`: Account restriction (disabled, locked, expired)
- `0xC0000072`: Account disabled
- `0xC0000234`: Account locked out
- `0xC0000193`: Account expired
- `0xC0000071`: Password expired

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summary aggregation by FailureReason/SubStatus. Intended for failure reason analysis and baselining, not per-event alerting. Requires SecurityEvent table."
-->
```kql
// Failed SMB Attempts — Categorized by Failure Reason
// Uses SecurityEvent for SubStatus codes (DeviceLogonEvents lacks this)
let timeframe = 7d;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4625
| where LogonType == 3
| extend SourceIP = IpAddress
| where isnotempty(SourceIP)
| where SourceIP startswith "10." or SourceIP startswith "192.168."
    or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
| extend FailureReason = case(
    SubStatus == "0xc0000064", "User does not exist",
    SubStatus == "0xc000006a", "Bad password",
    SubStatus == "0xc000006d", "Bad password (alternate)",
    SubStatus == "0xc000006e", "Account restriction",
    SubStatus == "0xc0000072", "Account disabled",
    SubStatus == "0xc0000234", "Account locked out",
    SubStatus == "0xc0000193", "Account expired",
    SubStatus == "0xc0000071", "Password expired",
    strcat("Other: ", SubStatus))
| summarize
    FailureCount = count(),
    UniqueAccounts = dcount(TargetAccount),
    UniqueSources = dcount(SourceIP),
    Accounts = make_set(TargetAccount, 5),
    SourceIPs = make_set(SourceIP, 5),
    TargetComputers = make_set(Computer, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by FailureReason, SubStatus
| project-reorder FailureReason, FailureCount, UniqueAccounts, UniqueSources, FirstSeen, LastSeen
| order by FailureCount desc
```

**Indicators of Malicious Activity:**
- **"User does not exist" dominant (>90%):** Username enumeration / dictionary spray — attacker doesn't know valid accounts
- **"Bad password" dominant:** Targeted credential guessing — attacker knows valid usernames
- **Mix of both:** Sophisticated spray with partial account list
- **"Account locked out" spikes:** Brute-force triggering lockout policy
- **NTLM failures on Kerberos-capable accounts:** Possible pass-the-hash attempt

---

### Query 6: SMB Timeline - Visualize Attack Progression

**Purpose:** Create a timeline view of Network logon activity from a specific source IP to understand attack progression

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation/timeline query requiring manual IP parameter (`<SOURCE_IP>`). Intended for ad-hoc forensic analysis after suspicious source is identified."
-->
```kql
// SMB Attack Timeline — Detailed View
// Replace <SOURCE_IP> with IP address under investigation
let timeframe = 7d;
let sourceIPFilter = "<SOURCE_IP>";
DeviceLogonEvents
| where Timestamp > ago(timeframe)
| where LogonType == "Network"
| where RemoteIP == sourceIPFilter
| extend
    EventType = iff(ActionType == "LogonSuccess", "✅ Success", "❌ Failed")
| project
    Timestamp,
    EventType,
    RemoteIP,
    TargetDevice = DeviceName,
    AccountName,
    AccountDomain,
    Protocol,
    IsLocalAdmin
| order by Timestamp asc
```

**Usage:**
1. **First:** Run Q2 or Q4 to identify suspicious source IPs
2. **Then:** Replace `<SOURCE_IP>` with the IP from those queries
3. **Analyze:** Look for patterns in the timeline

**What to look for:**
- **Rapid NTLM failures then Kerberos success:** Attacker switched from PtH to stolen ticket
- **Success on multiple targets in sequence:** Active lateral movement
- **IsLocalAdmin = true entries:** Attacker gained privileged access
- **Protocol switch mid-attack:** Evasion technique

---

## Part B: External Network Logon Brute-Force (SecurityEvent)

> **Source filter:** Non-RFC 1918 IPs only. Use for internet-facing devices flagged by Threat Pulse Q4/Q11 or exposure investigations. SecurityEvent provides SubStatus failure reason codes — critical for distinguishing username enumeration from password guessing.
>
> **⚠️ NLA caveat:** These queries filter on `LogonType 3` (Network) which includes BOTH SMB (port 445) and NLA-RDP (port 3389). Run the [disambiguation query](#-nla-rdp-ambiguity--read-before-interpreting-results) first to confirm the attack vector before reporting findings as "SMB brute-force."

### Query 7: External SMB Brute-Force Summary (SecurityEvent)

**Purpose:** Identify external IPs brute-forcing SMB/NTLM on internet-facing devices. Aggregates failed logon attempts by source IP with failure reason breakdown and timeline.

**MITRE:** T1110.001, T1110.003, T1133 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External SMB Brute-Force: {{IpAddress}} → {{Computer}} ({{FailedAttempts}} failures, {{UniqueAccounts}} accounts)"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "No minimum threshold — every external Network logon failure surfaces. For CD deployment, consider adding `| where FailedAttempts >= 10` to reduce alert volume. Entity substitution: add `| where Computer startswith 'HOSTNAME'` to scope to a specific device."
-->
```kql
// External SMB Brute-Force Summary (SecurityEvent)
// SubStatus breakdown for failure reason triage
let timeframe = 7d;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4625
| where LogonType == 3
| extend SourceIP = IpAddress
| where isnotempty(SourceIP)
| where not(SourceIP startswith "10." or SourceIP startswith "192.168."
    or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
| extend FailureReason = case(
    SubStatus == "0xc0000064", "User does not exist",
    SubStatus == "0xc000006a", "Bad password",
    SubStatus == "0xc000006d", "Bad password (alt)",
    SubStatus == "0xc0000072", "Account disabled",
    SubStatus == "0xc000006e", "Account restriction",
    SubStatus == "0xc0000234", "Account locked out",
    strcat("Other: ", SubStatus))
| summarize
    FailedAttempts = count(),
    UniqueAccounts = dcount(TargetAccount),
    SampleAccounts = make_set(TargetAccount, 5),
    TopFailureReasons = make_set(FailureReason, 3),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP = IpAddress, Computer
| order by FailedAttempts desc
| take 25
```

**Entity substitution:** Add `| where Computer startswith "<HOSTNAME>"` after the `EventID` filter to scope to a specific device.

**Verdict guidance:**
- **`UniqueAccounts >= 50` + "User does not exist":** Massive dictionary spray — automated scanner
- **`FailedAttempts >= 1000` + few accounts:** Persistent brute-force — single-target hammering
- **"Bad password" + low account count:** Targeted password guessing with known valid usernames
- **"Account locked out" events:** Brute-force triggered lockout policy — verify lockout threshold

**Why SecurityEvent over DeviceLogonEvents for external SMB:** The `SubStatus` field is the key differentiator. External SMB attacks are overwhelmingly username enumeration (`0xC0000064` — 99%+ in typical environments). Knowing this tells you the attacker is guessing blindly vs having a valid account list.

---

### Query 8: External SMB Successful Access (SecurityEvent)

**Purpose:** Detect successful Network logons from external IPs. High-severity — any external SMB success on a non-VPN host is suspicious.

**MITRE:** T1021.002, T1133 | **Tactic:** Initial Access, Lateral Movement

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External SMB Access: {{Account}} from {{SourceIP}} on {{Computer}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "High-severity alert. Exclude known VPN/management IPs via allowlist."
-->
```kql
// Successful External SMB/Network Access (SecurityEvent)
let timeframe = 7d;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4624
| where LogonType == 3
| extend SourceIP = IpAddress
| where isnotempty(SourceIP)
| where not(SourceIP startswith "10." or SourceIP startswith "192.168."
    or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
| project TimeGenerated, Computer, Account, SourceIP, LogonType,
    AuthenticationPackageName, WorkstationName
| order by TimeGenerated desc
```

**Tuning:** Exclude known management IPs: `| where SourceIP !in ("1.2.3.4", "5.6.7.8")`

---

### Query 9: External SMB Failed-Then-Success Correlation (SecurityEvent)

**Purpose:** Highest-fidelity external breach detection — correlates failed external Network logon attempts with a subsequent success from the same IP. This means an attacker guessed correct credentials via SMB.

**MITRE:** T1110.001, T1021.002 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External SMB Breach: {{IpAddress}} brute-forced {{TargetComputer}} ({{FailedAttempts}} failures then success as {{SuccessfulAccount}})"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "Multi-let correlation query. CD supports `let` blocks. Remove `order by` for CD. Thresholds (failureThreshold=3, windowTime=30m) are tunable."
-->
```kql
// External SMB Failed-Then-Success (SecurityEvent)
let timeframe = 7d;
let failureThreshold = 3;
let windowTime = 30m;
let ExternalFailed = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4625
    | where LogonType == 3
    | extend SourceIP = IpAddress
    | where isnotempty(SourceIP)
    | where not(SourceIP startswith "10." or SourceIP startswith "192.168."
        or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
        or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
    | summarize
        FailedAttempts = count(),
        FailedAccounts = make_set(TargetAccount, 5),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by IpAddress, TargetComputer = Computer;
let ExternalSuccess = SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where EventID == 4624
    | where LogonType == 3
    | extend SourceIP = IpAddress
    | where isnotempty(SourceIP)
    | where not(SourceIP startswith "10." or SourceIP startswith "192.168."
        or SourceIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
        or SourceIP in ("127.0.0.1", "::1", "0.0.0.0", "-"))
    | project SuccessTime = TimeGenerated, TargetComputer = Computer,
        SuccessfulAccount = Account, IpAddress, AuthenticationPackageName;
ExternalFailed
| where FailedAttempts >= failureThreshold
| join kind=inner ExternalSuccess on IpAddress, TargetComputer
| where SuccessTime between (FirstFailure .. (LastFailure + windowTime))
| project IpAddress, TargetComputer, FailedAttempts, FailedAccounts,
    FirstFailure, LastFailure, SuccessTime, SuccessfulAccount, AuthenticationPackageName
| order by FailedAttempts desc
```

---

## Part C: External Network Logon — DeviceLogonEvents (MDE)

> **When to use:** These queries use the `DeviceLogonEvents` table from Microsoft Defender for Endpoint. Use them in environments with MDE onboarded devices — they provide richer context (`RemoteIP`, `Protocol`, `IsLocalAdmin`) without requiring SecurityEvent log forwarding. Available in both Advanced Hunting (30d) and Sentinel Data Lake (90d+).
>
> **⚠️ NLA caveat:** `LogonType == "Network"` includes both SMB and NLA-RDP. Run the [disambiguation query](#-nla-rdp-ambiguity--read-before-interpreting-results) to confirm the actual port before reporting.

### Query 10: External SMB Brute-Force Detection (DeviceLogonEvents)

**Purpose:** Detect external IPs performing SMB/NTLM brute-force against MDE-enrolled devices. Covers both password spray (1 IP → many users) and brute-force (1 IP → many attempts) patterns.

**MITRE:** T1110.001, T1110.003 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External SMB Brute-Force: {{RemoteIP}} targeted {{TargetUsers}} users on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "DeviceLogonEvents alternative to Q7. No minimum threshold. For CD deployment, consider adding `| where FailedAttempts >= 10` to reduce alert volume."
-->
```kql
// External SMB Brute-Force Detection (DeviceLogonEvents)
// Platform: Both (AH uses Timestamp, Data Lake uses TimeGenerated)
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| where LogonType == "Network"
| where isnotempty(RemoteIP)
| where not(RemoteIP startswith "10." or RemoteIP startswith "192.168."
    or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    or RemoteIP in ("127.0.0.1", "::1", "0.0.0.0"))
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(AccountName),
    SampleTargets = make_set(AccountName, 5),
    TargetDevices = make_set(DeviceName, 3),
    Protocols = make_set(Protocol, 3),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP
| order by TargetUsers desc, FailedAttempts desc
```

**Tuning:**
- Add `| where FailedAttempts >= 50` for noisy internet-facing devices with high scan volume
- Add `| where DeviceName in ("server1", "server2")` to scope to known internet-facing assets
- For Data Lake (90d+): replace `Timestamp` with `TimeGenerated`

---

### Query 11: Successful External SMB Access (DeviceLogonEvents)

**Purpose:** Detect successful Network logons from external (non-RFC1918) IP addresses via MDE telemetry. Critical for identifying successful breaches on internet-facing endpoints.

**MITRE:** T1021.002, T1133 | **Tactic:** Lateral Movement, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External SMB Success: {{AccountName}} from {{RemoteIP}} on {{DeviceName}}"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "DeviceLogonEvents alternative to Q8. High-severity. Exclude known VPN/management IPs via allowlist. For Data Lake: replace Timestamp with TimeGenerated."
-->
```kql
// Successful External SMB Access (DeviceLogonEvents)
// Platform: Both (AH uses Timestamp, Data Lake uses TimeGenerated)
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| where isnotempty(RemoteIP)
| where RemoteIP != "0.0.0.0" and RemoteIP != "::1" and RemoteIP != "127.0.0.1"
| where not(RemoteIP startswith "10." or RemoteIP startswith "192.168."
    or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.")
| project Timestamp, DeviceName, AccountName, AccountDomain, RemoteIP,
    Protocol, IsLocalAdmin
| order by Timestamp desc
```

**Tuning:**
- Exclude known management IPs: `| where RemoteIP !in ("1.2.3.4", "5.6.7.8")`
- Scope to critical assets: `| where DeviceName in ("dc01", "sql-prod")`
- For Data Lake: replace `Timestamp` with `TimeGenerated`

---

### Query 12: External SMB Failed-Then-Success Correlation (DeviceLogonEvents)

**Purpose:** Correlate failed external Network logon attempts with subsequent successful logons from the same IP — the highest-fidelity indicator of a successful external SMB brute-force attack.

**MITRE:** T1110.001, T1021.002 | **Tactic:** Credential Access, Initial Access

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "External SMB Breach: {{RemoteIP}} brute-forced {{DeviceName}} ({{FailedAttempts}} failures then success)"
impactedAssets:
  - type: "device"
    identifier: "deviceName"
adaptation_notes: "DeviceLogonEvents alternative to Q9. Thresholds (failureThreshold=3, windowTime=30m) are tunable. For Data Lake: replace Timestamp with TimeGenerated."
-->
```kql
// External SMB Failed-Then-Success (DeviceLogonEvents)
// Platform: Both (AH uses Timestamp, Data Lake uses TimeGenerated)
let timeframe = 7d;
let failureThreshold = 3;
let windowTime = 30m;
let Failed = DeviceLogonEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "LogonFailed"
    | where LogonType == "Network"
    | where isnotempty(RemoteIP)
    | where not(RemoteIP startswith "10." or RemoteIP startswith "192.168."
        or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
        or RemoteIP in ("127.0.0.1", "::1", "0.0.0.0"))
    | summarize
        FailedAttempts = count(),
        FailedAccounts = make_set(AccountName, 5),
        FirstFailure = min(Timestamp),
        LastFailure = max(Timestamp)
        by RemoteIP, DeviceName;
let Success = DeviceLogonEvents
    | where Timestamp > ago(timeframe)
    | where ActionType == "LogonSuccess"
    | where LogonType == "Network"
    | where isnotempty(RemoteIP)
    | where not(RemoteIP startswith "10." or RemoteIP startswith "192.168."
        or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
        or RemoteIP in ("127.0.0.1", "::1", "0.0.0.0"))
    | project SuccessTime = Timestamp, DeviceName, SuccessAccount = AccountName,
        RemoteIP, Protocol, IsLocalAdmin;
Failed
| where FailedAttempts >= failureThreshold
| join kind=inner Success on RemoteIP, DeviceName
| where SuccessTime between (FirstFailure .. (LastFailure + windowTime))
| project RemoteIP, DeviceName, FailedAttempts, FailedAccounts,
    FirstFailure, LastFailure, SuccessTime, SuccessAccount, Protocol, IsLocalAdmin
| order by FailedAttempts desc
```

**Tuning:**
- `failureThreshold`: Minimum failed attempts before flagging (default: 3)
- `windowTime`: Time window after last failure to check for success (default: 30m)
- For Data Lake: replace `Timestamp` with `TimeGenerated`

---

## Detection Rule Deployment

### Recommended Custom Detection Rules

| Priority | Query | Scenario | Severity |
|----------|-------|----------|----------|
| 1 | **Q9/Q12** (External Failed-Then-Success) | External SMB brute-force succeeded | High |
| 2 | **Q8/Q11** (External SMB Success) | Any external Network logon | High |
| 3 | **Q2** (Internal Failed-Then-Success) | Internal lateral movement | Medium |
| 4 | **Q4** (Internal SMB Spray) | Internal spray across targets | Medium |
| 5 | **Q7/Q10** (External Brute-Force Summary) | External brute-force in progress | Medium |

### Entity Mappings (applies to all rules)

- Account → SuccessAccount / AccountName
- Host → DeviceName / Computer
- IP → RemoteIP / SourceIP

### Tactics & Techniques

- **External attacks:** Tactic: Initial Access, Credential Access | Technique: T1110.001, T1110.003, T1021.002
- **Internal movement:** Tactic: Lateral Movement | Technique: T1021.002

---

## Tuning Recommendations

### Reducing False Positives (Internal)

1. **Exclude domain controllers (high priority):**
   ```kql
   | where RemoteIP !in ("<DC_IP_1>", "<DC_IP_2>")
   ```

2. **Exclude SCCM/monitoring servers:**
   ```kql
   | where RemoteIP !in ("<SCCM_IP>", "<MONITORING_IP>")
   ```

3. **Filter out machine account noise:**
   ```kql
   | where AccountName !endswith "$"  // Exclude computer accounts
   ```

4. **Focus on NTLM (pass-the-hash indicator):**
   ```kql
   | where Protocol == "NTLM"  // PtH attacks use NTLM
   ```

### Reducing False Positives (External)

1. **Exclude known management/VPN IPs:**
   ```kql
   | where SourceIP !in ("1.2.3.4", "5.6.7.8")
   ```

2. **Focus on high-value targets only:**
   ```kql
   | where Computer has "dc" or Computer has "sql" or Computer has "srv"
   ```

---

## Investigation Workflow

### Internal Lateral Movement (Part A alerts)

1. **Baseline check:** Run Q3 for the source IP's overall Network logon activity profile
2. **Timeline analysis:** Run Q6 with the suspicious source IP
3. **Spray confirmation:** Run Q4 to check if the source is targeting multiple systems
4. **Failure reason analysis:** Run Q5 — "User does not exist" = blind spray, "Bad password" = targeted guessing
5. **Protocol check:** NTLM-only in a Kerberos domain = strong PtH indicator
6. **Reverse lookup:** Identify the device behind the source IP via `DeviceNetworkInfo` or `DeviceInfo`
7. **Response:** Isolate source device, reset compromised credentials, review target systems for post-compromise activity

### External Brute-Force (Part B/C alerts)

1. **Scope the attack:** Run Q7/Q10 to see all external IPs targeting the device
2. **Check for breach:** Run Q9/Q12 — any failed-then-success correlation is critical
3. **Verify successful access:** Run Q8/Q11 — any external SMB success warrants immediate investigation
4. **Failure reason triage:** Run Q7 (SecurityEvent) for SubStatus breakdown — 99% "User does not exist" = blind scan, "Bad password" = attacker has valid usernames
5. **Enrich attacker IPs:** Use `ioc-investigation` skill or `enrich_ips.py` for threat intel on source IPs
6. **Response:** Block IPs at NSG/firewall, disable SMB over internet (port 445), investigate device for post-compromise activity

---

## Prerequisites

### Required Data

- **DeviceLogonEvents** from MDE-enrolled devices (Windows and Linux)
- **SecurityEvent** table populated from Windows Security Event logs (for SubStatus failure codes)
- **Event ID 4624** (Successful Logon) and **Event ID 4625** (Failed Logon) collection enabled
- **Audit Logon Events** enabled in Windows Security Policy

### Key Differences: SecurityEvent vs DeviceLogonEvents for SMB

| Feature | SecurityEvent | DeviceLogonEvents |
|---------|--------------|-------------------|
| SubStatus failure codes | ✅ Full detail | ❌ Not available |
| Protocol (NTLM/Kerberos) | ✅ AuthenticationPackageName | ✅ Protocol column |
| IsLocalAdmin flag | ❌ Not available | ✅ Direct column |
| Device context | Basic (Computer name) | Rich (DeviceName, DeviceId) |
| Retention (Data Lake) | 90d+ | 90d+ |
| Retention (Advanced Hunting) | 30d | 30d |

### Test Data Availability

Run this query to verify data collection:
```kql
// Verify Network logon data is available
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Network"
| summarize Count = count() by ActionType, Protocol
| order by Count desc
```

---

## Additional Resources

**Microsoft Documentation:**
- [Event ID 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) - An account was successfully logged on
- [Event ID 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) - An account failed to log on
- [SMB Security Enhancements](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)

**MITRE ATT&CK:**
- [T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [TA0008 - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

**Security Best Practices:**
- Block SMB (port 445) at the perimeter firewall — SMB should never be exposed to the internet
- Disable NTLM where possible — use Kerberos for domain authentication
- Enable SMB Signing to prevent relay attacks
- Use LAPS for local admin password management
- Implement tiered administration (Tier 0/1/2 model)
- Monitor for pass-the-hash indicators (NTLM-only logons in Kerberos environments)

---

## Version History

- **v1.0 (2026-04-16):** Initial query collection
  - 12 queries across 3 parts (Internal/External SecurityEvent/External DeviceLogonEvents)
  - Validated against live lab data: 108K+ external failures, 295 IPs, internal lateral movement confirmed
  - All queries validated for syntax and schema compatibility
