# BehaviorEntities & BehaviorInfo — UEBA / MCAS Behavior Hunting

**Created:** 2026-03-26  
**Platform:** Microsoft Defender XDR (Advanced Hunting only)  
**Tables:** BehaviorEntities, BehaviorInfo  
**Keywords:** behavior, UEBA, MCAS, impossible travel, brute force, mass download, OAuth credential, container drift, malware, K8s, entity decomposition, below-threshold  
**MITRE:** T1078, T1078.004, T1098, T1098.001, T1110, T1110.001, T1074, TA0001, TA0003, TA0006, TA0009  
**Timeframe:** Last 30 days (configurable, AH max retention)

---

## Overview

BehaviorEntities and BehaviorInfo are **Preview** companion tables populated by **Microsoft Defender for Cloud Apps (MCAS)** and **Sentinel UEBA**. They surface contextual detections that may sit **below the alert threshold** — signals that don't necessarily generate a SecurityAlert but still indicate noteworthy activity.

**Data model:**
- **BehaviorInfo** = 1 row per behavior (header: description, MITRE ATT&CK techniques, time window, affected UPN)
- **BehaviorEntities** = N rows per behavior (one row per involved entity: User, IP, CloudApplication, OAuthApplication, Device, File, Container, K8s resources, etc.)
- Joined via `BehaviorId`

**Known service sources in practice:** Microsoft Cloud App Security, Microsoft Defender for Cloud

**Key columns:**
| Column | Table | Notes |
|--------|-------|-------|
| `BehaviorId` | Both | Join key |
| `ActionType` | Both | Detection type (e.g., `ImpossibleTravelActivity`, `K8S.NODE_DriftBlocked`) |
| `Categories` | Both | MITRE tactic as JSON string (e.g., `["InitialAccess"]`) |
| `AttackTechniques` | BehaviorInfo | MITRE techniques as JSON string (e.g., `["Valid Accounts (T1078)"]`) |
| `Description` | BehaviorInfo | Analyst-ready natural language description with embedded IPs, countries, app names |
| `EntityType` | BehaviorEntities | Type of entity row: `User`, `Ip`, `CloudApplication`, `OAuthApplication`, `Machine`, `File`, `Process`, `Container`, `KubernetesPod`, `ContainerImage`, etc. |
| `EntityRole` | BehaviorEntities | `Impacted` (target) or `Related` (contextual) |
| `AdditionalFields` | BehaviorEntities | Deeply nested JSON — especially rich for K8s entities (full cluster→namespace→pod→container→process tree) |

**Pitfalls:**
- ⚠️ **AH-only** — does NOT exist in Sentinel Data Lake. Always use `RunAdvancedHuntingQuery`
- ⚠️ **Preview** — schema may change substantially before GA
- ⚠️ `Categories` and `AttackTechniques` are **JSON strings**, not arrays. Use `parse_json()` before `mv-expand`
- ⚠️ `AdditionalFields` for K8s behaviors contains multi-level nested JSON with `$id`/`$ref` circular references — parse carefully
- ⚠️ Low volume — these are behavioral detections, not raw events. Expect dozens/hundreds per month, not thousands

---

## Query 1: Behavior Overview — Volume by ActionType and Source

**Purpose:** Understand what behavior types are active in your tenant and their relative volume.

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

## Query 2: Behavior Detail with MITRE Mapping

**Purpose:** List all behaviors with parsed MITRE techniques for triage or reporting.

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

## Query 3: Entity Decomposition for a Specific Behavior

**Purpose:** Drill into a single behavior to see all involved entities and their roles. Replace the BehaviorId filter.

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

## Query 4: Enrich User Investigation — MCAS Behaviors for a UPN

**Purpose:** During a user investigation, check if the user has MCAS/UEBA behaviors that may not have generated SecurityAlerts. Useful as a supplementary query in the user-investigation skill.

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

## Query 5: Enrich IP Investigation — Behaviors Involving an IP

**Purpose:** During an IoC/IP investigation, check if the IP appeared in any UEBA/MCAS behaviors.

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

## Query 6: OAuth App Credential Abuse — Unusual Credential Additions

**Purpose:** Hunt for suspicious OAuth app credential additions detected by MCAS. These may indicate app compromise for lateral movement or data exfiltration.

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

## Query 7: Impossible Travel Summary with IP Extraction

**Purpose:** Summarize impossible travel behaviors with the involved IPs and cloud applications extracted from entity rows.

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

## Query 8: Kubernetes Container Drift / Malware Behaviors

**Purpose:** Hunt for container security behaviors from Defender for Cloud. Extracts process command lines and container image details.

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

## Query 9: Cross-Reference Behaviors with SecurityAlert

**Purpose:** Identify which behaviors also generated SecurityAlerts (overlap) vs. which are behavior-only (unique signal). Helps assess the incremental value of BehaviorEntities in your environment.

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

---

## Query 10: All Entity Types and Roles Distribution

**Purpose:** Understand the entity decomposition patterns across all behavior types. Useful for planning which entity types to extract in custom workflows.

```kql
BehaviorEntities
| where Timestamp > ago(30d)
| summarize Count = count() by ActionType, EntityType, EntityRole
| order by ActionType asc, Count desc
```
