# Anomaly & Behavior Threat Detection — Sentinel UEBA + MCAS Hunting

**Created:** 2026-03-26  
**Updated:** 2026-04-14  
**Platform:** Both  
**Tables:** Anomalies, BehaviorEntities, BehaviorInfo, SecurityIncident, SecurityAlert  
**Keywords:** anomaly, UEBA, MCAS, behavior, impossible travel, brute force, mass download, OAuth credential, account manipulation, privilege granted, anomalous sign-in, failed sign-in, ML anomaly, container drift, entity decomposition, below-threshold, score, anomaly reasons  
**MITRE:** T1078, T1078.004, T1098, T1098.001, T1110, T1110.001, T1136, T1074, T1190, T1531, T1059, T1485, T1562, TA0001, TA0003, TA0005, TA0006, TA0009  
**Domains:** identity, endpoint, cloud  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This file combines queries for **two complementary anomaly data sources** in the Microsoft security stack:

### 1. Sentinel Anomalies Table (UEBA + ML)

The `Anomalies` table contains scored behavioral detections from two engines:
- **UEBA anomalies** — Entity-focused behavioral baselines (user history, peer comparison, org-wide patterns). Examples: Anomalous Sign-in, Anomalous Account Manipulation, Anomalous Failed Sign-in.
- **ML-based anomalies** — Customizable rule templates using statistical/ML models. Examples: Attempted brute force, Anomalous Azure operations, Suspicious login volume.

Both populate the same `Anomalies` table. Available in **both** Advanced Hunting and Data Lake.

**Key columns:**
| Column | Type | Notes |
|--------|------|-------|
| `AnomalyTemplateName` | string | Rule name (e.g., "UEBA Anomalous Account Manipulation") |
| `Score` | real | 0.0–1.0. Higher = more anomalous. ≥0.7 High, 0.3–0.7 Medium, <0.3 Low |
| `UserPrincipalName` | string | Affected user (may be empty for device/infra anomalies) |
| `SourceIpAddress` | string | Source IP (may be empty for some UEBA types) |
| `SourceDevice` | string | Source device (populated for Windows Security log anomalies only) |
| `AnomalyReasons` | dynamic | Array of `{Name, IsAnomalous}` objects. Filter `IsAnomalous == true` for actual flags |
| `Tactics` | string | JSON string (NOT array) — use `parse_json()` before aggregation |
| `Techniques` | string | JSON string (NOT array) — use `parse_json()` before aggregation |
| `Description` | string | Analyst-ready description with embedded entities, IPs, countries, TI matches |
| `DeviceInsights` | dynamic | Contains `ThreatIntelIndicatorType` (e.g., "BruteForce") — often TITAN false positive on corporate IPs |
| `Entities` | string | JSON array of entities involved (for entity-based lookups) |
| `StartTime` / `EndTime` | datetime | Anomaly time window (distinct from `TimeGenerated` which is ingestion time) |

**Pitfalls:**
- ⚠️ `Tactics` and `Techniques` are **JSON strings**, not arrays — `parse_json()` before `make_set()` or `mv-expand`
- ⚠️ `AnomalyReasons` contains both anomalous and non-anomalous flags — always filter `tobool(reason.IsAnomalous) == true`
- ⚠️ `DeviceInsights.ThreatIntelIndicatorType` frequently shows `BruteForce` on corporate/Azure egress IPs (TITAN dynamic reputation FP). Weight Score and AnomalyFlags over TI matches
- ⚠️ `UserPrincipalName` is directly populated — use `=~` for user-scoped queries (no `mv-apply` on Entities needed)
- ⚠️ Score 0.0–1.0: ≥0.7 High, 0.3–0.7 Medium, <0.3 Low
- ⚠️ `SourceDevice` is only populated for Windows Security log anomalies (ML-based brute force, suspicious logins). UEBA anomalies use `SourceIpAddress` instead. For device lookups, prefer `Entities has "<hostname>"` or `Description has "<hostname>"`

### 2. BehaviorEntities & BehaviorInfo (MCAS + Defender for Cloud)

**Preview** companion tables populated by **MCAS** and **Defender for Cloud**. Surface below-alert-threshold contextual detections. **AH-only** — not available in Data Lake.

- **BehaviorInfo** = 1 row per behavior (header: description, MITRE techniques, time window)
- **BehaviorEntities** = N rows per behavior (entity decomposition: User, IP, App, Device, Container, etc.)
- Joined via `BehaviorId`

**Complementarity:** In this environment, Anomalies covers 115 users (393 events) while BehaviorEntities covers 14 users (40 behaviors) with only 4 users overlapping — they surface **largely independent signals**.

---

---

## Quick Reference — Query Index

**Investigation shortcuts:**
- **Fleet anomaly triage** (TP when Q1 returns 0 High incidents): **Q1** → **Q2** → **Q3** → **Q4**
- **Risky user anomaly context** (TP Q3, or any user drill-down): **Q7** (single-user Anomalies profile) → **Q14** (user MCAS/UEBA BehaviorInfo) → **Q8** (IP lookup for user's source IPs). Always run both Q7 and Q14 — `Anomalies` and `BehaviorInfo` are independent tables with different detection engines
- **Spray/brute-force IP context** (TP Q4): **Q8** (IP anomaly lookup) → **Q9** (cross-ref with incidents)
- **MCAS behavior enrichment** (TP Q9 Compromised Sign-In): **Q14** (user MCAS behaviors) → **Q17** (impossible travel) → **Q7** (cross-check Anomalies for same user)
- **Persistence/privilege anomaly hunt** (TP Q10 RoleManagement): **Q5** (tactic heatmap) → **Q4** (high-score Persistence filter)
> **⛔ Shortcut Default Rule:** When a matching shortcut exists for the investigation context, **use it**. Only run the full query set for "comprehensive anomaly review" or standalone posture assessments.
### Section 1: Sentinel Anomalies (UEBA + ML)
### Section 2: BehaviorEntities & BehaviorInfo (MCAS + Defender for Cloud)

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Anomaly Overview — Volume & Score Distribution](#query-1-anomaly-overview--volume--score-distribution) | Dashboard | `AvgScore` |
| 2 | [Volume by Anomaly Template Name](#query-2-volume-by-anomaly-template-name) | Dashboard | `AvgScore` + `MaxScore` |
| 3 | [Top Users by Anomaly Count](#query-3-top-users-by-anomaly-count) | Detection | `AvgScore` + `MaxScore` |
| 4 | [High-Score Anomalies (≥ 0.7) with Anomaly Flags](#query-4-high-score-anomalies--07-with-anomaly-flags) | Posture | — |
| 5 | [Anomalies by MITRE Tactic](#query-5-anomalies-by-mitre-tactic) | Detection | `AvgScore` + `MaxScore` |
| 6 | [Daily Anomaly Trend](#query-6-daily-anomaly-trend) | Dashboard | `HighScore` |
| 7 | [Single-User Anomaly Profile](#query-7-single-user-anomaly-profile) | Detection | `AvgScore` + `MaxScore` |
| 8 | [IP-Based Anomaly Lookup](#query-8-ip-based-anomaly-lookup) | Detection | — |
| 9 | [Cross-Reference Anomalies with SecurityIncident](#query-9-cross-reference-anomalies-with-securityincident) | Detection | `HasAlert` + multi |
| 10 | [Behavior Overview — Volume by ActionType and Source](#query-10-behavior-overview--volume-by-actiontype-and-source) | Dashboard | `BehaviorInfo` |
| 11 | [Behavior Detail with MITRE Mapping](#query-11-behavior-detail-with-mitre-mapping) | Investigation | `BehaviorInfo` |
| 12 | [Entity Decomposition for a Specific Behavior](#query-12-entity-decomposition-for-a-specific-behavior) | Investigation | — |
| 13 | [All Entity Types and Roles Distribution](#query-13-all-entity-types-and-roles-distribution) | Investigation | — |
| 14 | [Enrich User Investigation — MCAS Behaviors for a UPN](#query-14-enrich-user-investigation--mcas-behaviors-for-a-upn) | Investigation | `BehaviorInfo` |
| 15 | [Enrich IP Investigation — Behaviors Involving an IP](#query-15-enrich-ip-investigation--behaviors-involving-an-ip) | Investigation | `BehaviorInfo` |
| 16 | [OAuth App Credential Abuse — Unusual Credential Additions](#query-16-oauth-app-credential-abuse--unusual-credential-additions) | Investigation | `BehaviorInfo` |
| 17 | [Impossible Travel Summary with IP Extraction](#query-17-impossible-travel-summary-with-ip-extraction) | Dashboard | `BehaviorInfo` + `ImpossibleTravelActivity` |
| 18 | [Kubernetes Container Drift / Malware Behaviors](#query-18-kubernetes-container-drift--malware-behaviors) | Investigation | `BehaviorInfo` |
| 19 | [Cross-Reference Behaviors with SecurityAlert](#query-19-cross-reference-behaviors-with-securityalert) | Detection | `BehaviorInfo` + multi |


## Section 1: Sentinel Anomalies (UEBA + ML)

### Query 1: Anomaly Overview — Volume & Score Distribution

**Purpose:** Quick fleet-level pulse — total anomaly volume, active rule count, and score distribution. Good starting point for any anomaly review.

**Tool:** `RunAdvancedHuntingQuery` (default) or `mcp_sentinel-data_query_lake` (>30d)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summary/dashboard query, not a detection."
-->
```kql
Anomalies
| where TimeGenerated > ago(30d)
| summarize
    TotalAnomalies = count(),
    DistinctRules = dcount(AnomalyTemplateName),
    DistinctUsers = dcount(UserPrincipalName),
    AvgScore = round(avg(Score), 3),
    HighScoreCount = countif(Score >= 0.7),
    MedScoreCount = countif(Score >= 0.3 and Score < 0.7),
    LowScoreCount = countif(Score < 0.3),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
```

---

### Query 2: Volume by Anomaly Template Name

**Purpose:** Breakdown by anomaly rule — which detection types fire most, how many distinct users they affect, and their score ranges. Primary fleet triage view.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/dashboard query."
-->
```kql
Anomalies
| where TimeGenerated > ago(30d)
| summarize
    Count = count(),
    DistinctUsers = dcount(UserPrincipalName),
    AvgScore = round(avg(Score), 3),
    MaxScore = max(Score),
    Tactics = make_set(parse_json(Tactics)),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AnomalyTemplateName
| mv-apply t = Tactics to typeof(string) on (summarize Tactics = make_set(t))
| extend Tactics = set_difference(Tactics, dynamic([""]))
| order by Count desc
```

---

### Query 3: Top Users by Anomaly Count

**Purpose:** Risk-rank users by anomaly detection volume. Surfaces users with the most behavioral flags — useful for Threat Pulse drill-down when no high-severity incidents exist but the identity landscape has noise.

> **CTF/lab account note:** Red team and CTF accounts (e.g., `*@ctf.alpineskihouse.co`, `DomainDominance_*`) will dominate top scores. Filter with `where AccountUpn !has "ctf"` in production environments.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Risk ranking query."
-->
```kql
Anomalies
| where TimeGenerated > ago(30d)
| summarize
    AnomalyCount = count(),
    DistinctTypes = dcount(AnomalyTemplateName),
    MaxScore = max(Score),
    AvgScore = round(avg(Score), 3),
    Templates = make_set(AnomalyTemplateName, 5),
    SourceIPs = make_set(SourceIpAddress, 5),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName
| where isnotempty(UserPrincipalName)
| order by MaxScore desc, AnomalyCount desc
| take 15
```

---

### Query 4: High-Score Anomalies (≥ 0.7) with Anomaly Flags

**Purpose:** The "fire alarm" query — surfaces only high-confidence anomalies with their specific anomalous reason flags extracted. Use as a triage starting point when looking for actionable signals.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Triage query with mv-apply. High-score threshold is configurable."
-->
```kql
Anomalies
| where TimeGenerated > ago(30d)
| where Score >= 0.7
| mv-apply reason = AnomalyReasons on (
    where tobool(reason.IsAnomalous) == true
    | project FlagName = tostring(reason.Name))
| summarize
    AnomalyFlags = make_set(FlagName),
    Occurrences = count(),
    SourceIPs = make_set(SourceIpAddress, 5)
    by AnomalyTemplateName, UserPrincipalName,
       Tactics = tostring(parse_json(Tactics)),
       Techniques = tostring(parse_json(Techniques)),
       Score
| order by Score desc, Occurrences desc
| take 20
```

**Key flags to watch:**
- `FirstTimeUserPerformedAction` — action never seen from this user
- `FirstTimeUserConnectedFromCountry` — geographic novelty
- `ActionUncommonlyPerformedByUser` — action deviates from user baseline
- `UncommonHighVolumeOfActions` — volume spike for this user
- `CountryUncommonlyConnectedFromByUser` — geographic anomaly
- `SimilarActionWasNotPerformedInThePast` — no historical precedent

---

### Query 5: Anomalies by MITRE Tactic

**Purpose:** Threat landscape heatmap — what ATT&CK tactics are the anomaly rules detecting? Helps prioritize investigation domains (Persistence heavy? CredentialAccess spike?).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/dashboard query."
-->
```kql
Anomalies
| where TimeGenerated > ago(30d)
| extend ParsedTactics = parse_json(Tactics)
| mv-expand Tactic = ParsedTactics
| extend Tactic = tostring(Tactic)
| where isnotempty(Tactic)
| summarize
    Count = count(),
    DistinctTemplates = dcount(AnomalyTemplateName),
    DistinctUsers = dcount(UserPrincipalName),
    AvgScore = round(avg(Score), 3),
    MaxScore = max(Score),
    Templates = make_set(AnomalyTemplateName, 5)
    by Tactic
| order by Count desc
```

---

### Query 6: Daily Anomaly Trend

**Purpose:** Temporal pattern view — spot daily spikes in anomaly volume and high-score count. Useful for correlating anomaly surges with incident timelines or attack campaigns.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Trend/dashboard query."
-->
```kql
Anomalies
| where TimeGenerated > ago(30d)
| summarize
    TotalAnomalies = count(),
    HighScore = countif(Score >= 0.7),
    DistinctUsers = dcount(UserPrincipalName),
    DistinctTemplates = dcount(AnomalyTemplateName)
    by Day = bin(TimeGenerated, 1d)
| order by Day asc
```

---

### Query 7: Single-User Anomaly Profile

**Purpose:** Full anomaly profile for a specific user — aggregated by anomaly template with flags, scores, IPs, and MITRE context. This is the entity drill-down from fleet views (Q3) or from Threat Pulse Q3 (risky identity).

> **Usage:** Replace `<UPN>` with the target user's UPN. This is the same query as user-investigation Q12.

**Tool:** `RunAdvancedHuntingQuery` (default) or `mcp_sentinel-data_query_lake` (>30d)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Entity drill-down query."
-->
```kql
let targetUPN = '<UPN>';
Anomalies
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ targetUPN
| extend TI_Type = tostring(DeviceInsights.ThreatIntelIndicatorType)
| mv-apply reason = AnomalyReasons on (
    where tobool(reason.IsAnomalous) == true
    | project FlagName = tostring(reason.Name))
| summarize
    Occurrences = dcount(Id),
    MaxScore = max(Score),
    AvgScore = round(avg(Score), 2),
    Tactics = make_set(parse_json(Tactics)),
    Techniques = make_set(parse_json(Techniques)),
    SourceIPs = make_set(SourceIpAddress, 5),
    AnomalyFlags = make_set(FlagName),
    TI_Flags = make_set_if(TI_Type, isnotempty(TI_Type)),
    FirstSeen = min(StartTime),
    LastSeen = max(EndTime),
    SampleDescription = take_any(Description)
    by AnomalyTemplateName
| mv-apply t = Tactics to typeof(string) on (summarize Tactics = make_set(t))
| mv-apply t = Techniques to typeof(string) on (summarize Techniques = make_set(t))
| extend Tactics = set_difference(Tactics, dynamic([""]))
| extend Techniques = set_difference(Techniques, dynamic([""]))
| order by MaxScore desc, Occurrences desc
```

**⚠️ TI False Positive:** `DeviceInsights.ThreatIntelIndicatorType` frequently shows `BruteForce` on corporate/Azure egress IPs (TITAN dynamic reputation). Weight `Score` and `AnomalyFlags` over the TI match — a 0.2-score anomaly with a BruteForce TI hit on a known corporate IP is noise.

---

### Query 8: IP-Based Anomaly Lookup

**Purpose:** Find all anomalies involving a specific IP address — useful when investigating spray source IPs (TP Q4), enriching IoC investigations, or tracing activity from a known attacker IP across the anomaly landscape.

> **Usage:** Replace `<IP_ADDRESS>` with the target IP.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Entity drill-down query."
-->
```kql
let targetIP = "<IP_ADDRESS>";
Anomalies
| where TimeGenerated > ago(30d)
| where SourceIpAddress == targetIP or Entities has targetIP
| project TimeGenerated, AnomalyTemplateName, UserPrincipalName, Score,
    SourceIpAddress, Description
| order by TimeGenerated desc
| take 20
```

---

### Query 9: Cross-Reference Anomalies with SecurityIncident

**Purpose:** Identify which anomaly types have corresponding incidents (covered) vs. which are anomaly-only signals (investigation gaps). High "anomaly-only %" means the anomaly type surfaces activity that never triggers an incident — potential detection gap.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Gap analysis / posture query. Cross-table join."
-->
```kql
let lookback = 30d;
let anomaly_users = Anomalies
| where TimeGenerated > ago(lookback)
| where isnotempty(UserPrincipalName)
| summarize AnomalyCount = count(), MaxScore = max(Score) by UserPrincipalName, AnomalyTemplateName;
let incident_users = SecurityAlert
| where TimeGenerated > ago(lookback)
| extend ParsedEntities = parse_json(Entities)
| mv-expand Entity = ParsedEntities
| where tostring(Entity.Type) == "account"
| extend EntityUPN = tolower(strcat(tostring(Entity.Name), "@", tostring(Entity.UPNSuffix)))
| where isnotempty(EntityUPN)
| summarize AlertCount = count() by EntityUPN;
anomaly_users
| join kind=leftouter incident_users on $left.UserPrincipalName == $right.EntityUPN
| extend HasAlert = isnotempty(AlertCount)
| summarize
    UsersWithAlerts = dcountif(UserPrincipalName, HasAlert),
    UsersWithoutAlerts = dcountif(UserPrincipalName, not(HasAlert)),
    TotalAnomalies = sum(AnomalyCount),
    MaxScore = max(MaxScore)
    by AnomalyTemplateName
| extend AnomalyOnlyPct = round(100.0 * UsersWithoutAlerts / (UsersWithAlerts + UsersWithoutAlerts), 1)
| order by AnomalyOnlyPct desc, TotalAnomalies desc
```

---

## Section 2: BehaviorEntities & BehaviorInfo (MCAS + Defender for Cloud)

> **⚠️ AH-only** — BehaviorEntities and BehaviorInfo do NOT exist in Sentinel Data Lake. Always use `RunAdvancedHuntingQuery`.
>
> **⚠️ Preview** — schema may change substantially before GA.
>
> **⚠️ `Categories` and `AttackTechniques` are JSON strings**, not arrays. Use `parse_json()` before `mv-expand`.
>
> **⚠️ Low volume** — these are behavioral detections, not raw events. Expect dozens/hundreds per month, not thousands.

**Data model:**
- **BehaviorInfo** = 1 row per behavior (header: description, MITRE, time window, UPN)
- **BehaviorEntities** = N rows per behavior (entity decomposition: User, IP, App, Device, Container)
- Joined via `BehaviorId`

---

### Query 10: Behavior Overview — Volume by ActionType and Source

**Purpose:** Understand what behavior types are active in your tenant and their relative volume.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Dashboard query — BehaviorInfo is AH-only Preview table."
-->
```kql
BehaviorInfo
| where Timestamp > ago(30d)
| summarize
    BehaviorCount = dcount(BehaviorId),
    AffectedUsers = dcount(AccountUpn),
    EarliestBehavior = min(Timestamp),
    LatestBehavior = max(Timestamp)
    by ServiceSource, ActionType
| order by BehaviorCount desc
```

---

### Query 11: Behavior Detail with MITRE Mapping

**Purpose:** List all behaviors with parsed MITRE techniques for triage or reporting.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation query — AttackTechniques is a JSON string requiring parse_json."
-->
```kql
BehaviorInfo
| where Timestamp > ago(30d)
| extend Techniques = parse_json(AttackTechniques)
| mv-expand Technique = Techniques
| extend Technique = tostring(Technique)
| project Timestamp, BehaviorId, ActionType, Description, ServiceSource,
    AccountUpn, Technique, StartTime, EndTime
| order by Timestamp desc
```

---

### Query 12: Entity Decomposition for a Specific Behavior

**Purpose:** Drill into a single behavior to see all involved entities and their roles. Replace the BehaviorId filter.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Entity drill-down — requires known BehaviorId."
-->
```kql
BehaviorEntities
| where Timestamp > ago(30d)
| where BehaviorId == "<BehaviorId>"
| project EntityType, EntityRole, DetailedEntityRole,
    AccountUpn, RemoteIP, Application, OAuthApplicationId,
    DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine,
    AdditionalFields
| order by EntityRole asc, EntityType asc
```

---

### Query 13: All Entity Types and Roles Distribution

**Purpose:** Understand the entity decomposition patterns across all behavior types. Useful for planning which entity types to extract in custom workflows.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation/planning query."
-->
```kql
BehaviorEntities
| where Timestamp > ago(30d)
| summarize Count = count() by ActionType, EntityType, EntityRole
| order by ActionType asc, Count desc
```

---

### Query 14: Enrich User Investigation — MCAS Behaviors for a UPN

**Purpose:** During a user investigation, check if the user has MCAS/UEBA behaviors that may not have generated SecurityAlerts. Useful as a supplementary query in the user-investigation skill.

> **Usage:** Replace `<UPN>` with the target user's UPN.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Entity drill-down — user enrichment."
-->
```kql
let targetUser = "<UPN>";
let lookback = 30d;
BehaviorInfo
| where Timestamp > ago(lookback)
| where AccountUpn =~ targetUser
| join kind=leftouter (
    BehaviorEntities
    | where Timestamp > ago(lookback)
    | where EntityType == "Ip" and EntityRole == "Related"
    | project BehaviorId, RelatedIP = RemoteIP
) on BehaviorId
| summarize
    RelatedIPs = make_set(RelatedIP, 20),
    Occurrences = count()
    by BehaviorId, ActionType, Description, Categories, AttackTechniques, StartTime, EndTime
| order by StartTime desc
```

---

### Query 15: Enrich IP Investigation — Behaviors Involving an IP

**Purpose:** During an IoC/IP investigation, check if the IP appeared in any UEBA/MCAS behaviors.

> **Usage:** Replace `<IP_ADDRESS>` with the target IP.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Entity drill-down — IP enrichment."
-->
```kql
let targetIP = "<IP_ADDRESS>";
let lookback = 30d;
BehaviorEntities
| where Timestamp > ago(lookback)
| where RemoteIP == targetIP
| join kind=inner (
    BehaviorInfo
    | where Timestamp > ago(lookback)
    | project BehaviorId, ActionType, Description, AttackTechniques, AccountUpn, StartTime
) on BehaviorId
| project StartTime, ActionType, Description, AccountUpn, AttackTechniques, EntityRole
| order by StartTime desc
```

---

### Query 16: OAuth App Credential Abuse — Unusual Credential Additions

**Purpose:** Hunt for suspicious OAuth app credential additions detected by MCAS. These may indicate app compromise for lateral movement or data exfiltration.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Hunting query — specific ActionType filter."
-->
```kql
BehaviorInfo
| where Timestamp > ago(30d)
| where ActionType == "UnusualAdditionOfCredentialsToAnOauthApp"
| join kind=inner (
    BehaviorEntities
    | where Timestamp > ago(30d)
    | where EntityType == "OAuthApplication"
    | project BehaviorId, OAuthApplicationId, Application
) on BehaviorId
| project Timestamp, AccountUpn, Description, OAuthApplicationId, Application, AttackTechniques
| order by Timestamp desc
```

---

### Query 17: Impossible Travel Summary with IP Extraction

**Purpose:** Summarize impossible travel behaviors with the involved IPs and cloud applications extracted from entity rows.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Hunting query — specific ActionType filter."
-->
```kql
BehaviorInfo
| where Timestamp > ago(30d)
| where ActionType == "ImpossibleTravelActivity"
| join kind=inner (
    BehaviorEntities
    | where Timestamp > ago(30d)
    | summarize
        IPs = make_set(RemoteIP, 10),
        Apps = make_set(Application, 10)
        by BehaviorId
) on BehaviorId
| extend IPs = set_difference(IPs, dynamic([""]))
| extend Apps = set_difference(Apps, dynamic([""]))
| project Timestamp, AccountUpn, IPs, Apps, Description, StartTime, EndTime
| order by Timestamp desc
```

---

### Query 18: Kubernetes Container Drift / Malware Behaviors

**Purpose:** Hunt for container security behaviors from Defender for Cloud. Extracts process command lines and container image details.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation query — K8s/container security, Defender for Cloud-specific."
-->
```kql
BehaviorEntities
| where Timestamp > ago(30d)
| where ServiceSource == "Microsoft Defender for Cloud"
| where EntityType == "Process"
| extend AF = parse_json(AdditionalFields)
| extend ProcessId = tostring(AF.ProcessId),
    CommandLine = tostring(AF.CommandLine),
    ParentProcess = tostring(AF.ParentProcess.ImageFile.Name)
| join kind=inner (
    BehaviorInfo
    | where Timestamp > ago(30d)
    | where ServiceSource == "Microsoft Defender for Cloud"
    | project BehaviorId, ActionType, Description
) on BehaviorId
| project Timestamp, ActionType, Description, FileName, FolderPath, CommandLine,
    ParentProcess, ProcessId
| order by Timestamp desc
```

---

### Query 19: Cross-Reference Behaviors with SecurityAlert

**Purpose:** Identify which behaviors also generated SecurityAlerts (overlap) vs. which are behavior-only (unique signal). Helps assess the incremental value of BehaviorEntities in your environment.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Gap analysis query — cross-table join."
-->
```kql
let lookback = 30d;
let behaviors = BehaviorInfo
| where Timestamp > ago(lookback)
| project BehaviorId, ActionType, AccountUpn, BehaviorTime = Timestamp, Description;
let alerts = SecurityAlert
| where TimeGenerated > ago(lookback)
| extend AlertEntities = parse_json(Entities)
| mv-expand Entity = AlertEntities
| extend EntityUPN = tostring(Entity.Upn)
| where isnotempty(EntityUPN)
| summarize AlertCount = count(), AlertNames = make_set(AlertName, 5) by EntityUPN
| project EntityUPN, AlertCount, AlertNames;
behaviors
| join kind=leftouter alerts on $left.AccountUpn == $right.EntityUPN
| extend HasMatchingAlert = isnotempty(AlertCount)
| summarize
    BehaviorsWithAlerts = countif(HasMatchingAlert),
    BehaviorsWithoutAlerts = countif(not(HasMatchingAlert))
    by ActionType
| extend BehaviorOnlyPct = round(100.0 * BehaviorsWithoutAlerts / (BehaviorsWithAlerts + BehaviorsWithoutAlerts), 1)
| order by BehaviorsWithoutAlerts desc
```
