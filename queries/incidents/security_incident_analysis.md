# SecurityIncident — Incident Analysis & Entity Correlation

**Created:** 2026-04-11  
**Platform:** Both (SecurityIncident in Sentinel Data Lake + SecurityAlert join via Advanced Hunting)  
**Tables:** SecurityIncident, SecurityAlert  
**Keywords:** incident, alert, triage, MITRE, tactics, techniques, entities, accounts, devices, classification, severity, tags, labels, owner, unassigned, age, correlation, attack chain, TP rate  
**MITRE:** TA0001, TA0002, TA0003, TA0004, TA0005, TA0006, TA0007, TA0008, TA0009, TA0010, TA0011, TA0040, TA0042, TA0043  
**Domains:** incidents  
**Timeframe:** Last 30 days (configurable)

---

## Overview

The `SecurityIncident` table aggregates correlated alerts into incidents for investigation. These queries provide deep analysis of incident lifecycle, entity extraction, MITRE ATT&CK coverage, classification trends, and SOC operational metrics.

**Key schema notes:**
- `Status` field values: `New`, `Active`, `Closed`
- `Severity` field values: `High`, `Critical`, `Medium`, `Low`, `Informational`
- `Classification` field values: `TruePositive`, `BenignPositive`, `FalsePositive`, `Undetermined`
- `AlertIds` contains `SystemAlertId` GUIDs — join to `SecurityAlert` on `SystemAlertId`
- `Labels` is a dynamic array of `{labelName, labelType}` objects — `AutoAssigned` (ML) or `User` (SOC/automation)
- `Owner` is a dynamic object — extract UPN with `tostring(Owner.userPrincipalName)`
- `AdditionalData` contains `alertsCount`, `tactics`, `techniques`, `alertProductNames`, `providerIncidentUrl`
- `ProviderIncidentId` is the Defender XDR incident ID — use for portal URLs and Triage MCP calls
- **⚠️ `SecurityAlert.Status` is immutable** (always "New") — only `SecurityIncident.Status` reflects real investigation state

**Portal URL pattern:** `https://security.microsoft.com/incidents/{ProviderIncidentId}`

---

## Query 1: Open High-Severity Incidents — Newest First with Entity & Tag Enrichment

**Purpose:** Top 10 newest open High/Critical incidents sorted by day then alert count. Extracts account/device entities from alerts and incident tags for cross-query correlation. The definitive "what needs attention now" query.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-join enrichment query with entity extraction and tag parsing. Aggregates across incidents — not suitable for row-level CD detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active")
| where Severity in ("High", "Critical")
| extend ParsedLabels = parse_json(Labels)
| mv-apply Label = ParsedLabels on (
    summarize Tags = make_set(tostring(Label.labelName), 5)
)
| extend Tags = set_difference(Tags, dynamic([""]))
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | extend ParsedEntities = parse_json(Entities)
    | mv-expand Entity = ParsedEntities
    | extend EntityType = tostring(Entity.Type),
        AccountUPN = case(
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.UPNSuffix)),
            tolower(strcat(tostring(Entity.Name), "@", tostring(Entity.UPNSuffix))),
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.AadUserId)),
            tostring(Entity.AadUserId),
            ""),
        HostName = iff(tostring(Entity.Type) == "host", tolower(tostring(Entity.HostName)), "")
    | project SystemAlertId, Tactics, Techniques, AlertName, AlertSeverity, AccountUPN, HostName
) on $left.AlertId == $right.SystemAlertId
| mv-expand Technique = parse_json(Techniques)
| extend Technique = tostring(Technique)
| extend TacticsSplit = split(Tactics, ", ")
| mv-expand Tactic = TacticsSplit
| extend Tactic = tostring(Tactic)
| summarize 
    Tactics = make_set(Tactic),
    Techniques = make_set(Technique),
    AlertNames = make_set(AlertName, 5),
    AlertCount = dcount(AlertId),
    Accounts = make_set_if(AccountUPN, isnotempty(AccountUPN), 5),
    Devices = make_set_if(HostName, isnotempty(HostName), 5),
    Tags = take_any(Tags)
    by ProviderIncidentId, Title, Severity, Status, CreatedTime,
       OwnerUPN = tostring(Owner.userPrincipalName)
| extend Techniques = set_difference(Techniques, dynamic([""]))
| extend Tactics = set_difference(Tactics, dynamic([""]))
| extend AgeDisplay = case(
    datetime_diff('minute', now(), CreatedTime) < 60, strcat(datetime_diff('minute', now(), CreatedTime), "m ago"),
    datetime_diff('hour', now(), CreatedTime) < 24, strcat(datetime_diff('hour', now(), CreatedTime), "h ago"),
    strcat(datetime_diff('day', now(), CreatedTime), "d ago"))
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId)
| project ProviderIncidentId, Title, Severity, AgeDisplay, AlertCount, 
    OwnerUPN, Tactics, Techniques, Accounts, Devices, Tags, PortalUrl, AlertNames, CreatedTime
| order by bin(CreatedTime, 1d) desc, AlertCount desc
| take 10
```

---

## Query 2: Incident Classification Trends — 30-Day Rolling

**Purpose:** Weekly breakdown of incident classifications (TP/BP/FP/Undetermined) with severity distribution. Reveals TP rate trends, classification backlogs, and whether the SOC is keeping up with closures.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/trend query — weekly classification breakdown. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| extend Week = startofweek(ClosedTime)
| summarize
    Total = dcount(IncidentNumber),
    TruePositive = dcountif(IncidentNumber, Classification == "TruePositive"),
    BenignPositive = dcountif(IncidentNumber, Classification == "BenignPositive"),
    FalsePositive = dcountif(IncidentNumber, Classification == "FalsePositive"),
    Undetermined = dcountif(IncidentNumber, Classification == "Undetermined"),
    HighCritical = dcountif(IncidentNumber, Severity in ("High", "Critical")),
    AvgAlertCount = avg(toint(parse_json(AdditionalData).alertsCount))
    by Week
| extend TPRate = round(todouble(TruePositive) / todouble(Total) * 100, 1)
| order by Week desc
```

---

## Query 3: Unassigned Incident Backlog

**Purpose:** Identifies open incidents with no owner assigned, grouped by severity and age bucket. Critical for SOC hygiene — unassigned High/Critical incidents are a red flag.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/hygiene query — surfaces unassigned incidents by severity and age. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active")
| where isempty(tostring(Owner.userPrincipalName))
| extend AgeBucket = case(
    datetime_diff('hour', now(), CreatedTime) < 24, "< 24h",
    datetime_diff('day', now(), CreatedTime) < 7, "1-7d",
    datetime_diff('day', now(), CreatedTime) < 30, "7-30d",
    "> 30d")
| summarize
    Count = dcount(IncidentNumber),
    TotalAlerts = sum(toint(parse_json(AdditionalData).alertsCount)),
    SampleTitles = make_set(Title, 3)
    by Severity, AgeBucket
| order by Severity asc, AgeBucket asc
```

---

## Query 4: MITRE ATT&CK Tactic Distribution Across Open Incidents

**Purpose:** Which MITRE ATT&CK tactics are most represented in current open incidents? Useful for understanding the active threat landscape and identifying coverage gaps.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/coverage query — tactic distribution across open incidents. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active")
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project SystemAlertId, Tactics, Techniques
) on $left.AlertId == $right.SystemAlertId
| extend TacticsSplit = split(Tactics, ", ")
| mv-expand Tactic = TacticsSplit
| extend Tactic = tostring(Tactic)
| where isnotempty(Tactic) and Tactic != ""
| mv-expand Technique = parse_json(Techniques)
| extend Technique = tostring(Technique)
| where isnotempty(Technique) and Technique != ""
| summarize 
    IncidentCount = dcount(IncidentNumber),
    Techniques = make_set(Technique, 10),
    SampleTitles = make_set(Title, 3)
    by Tactic
| order by IncidentCount desc
```

---

## Query 5: Entity Hotspot — Most Targeted Accounts and Devices

**Purpose:** Which accounts and devices appear across the most incidents? Identifies repeat targets that may indicate persistent compromise, lateral movement paths, or high-value asset targeting.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/entity query — identifies most targeted entities across incidents. No row-level detection."
-->
```kql
let IncidentEntities = SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active")
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=inner (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | extend ParsedEntities = parse_json(Entities)
    | mv-expand Entity = ParsedEntities
    | extend EntityType = tostring(Entity.Type),
        EntityValue = case(
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.UPNSuffix)),
            tolower(strcat(tostring(Entity.Name), "@", tostring(Entity.UPNSuffix))),
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.AadUserId)),
            tostring(Entity.AadUserId),
            tostring(Entity.Type) == "host", tolower(tostring(Entity.HostName)),
            "")
    | where isnotempty(EntityValue)
    | where EntityType in ("account", "host")
    | project SystemAlertId, EntityType, EntityValue
) on $left.AlertId == $right.SystemAlertId;
// Top targeted accounts
let TopAccounts = IncidentEntities
| where EntityType == "account"
| summarize 
    IncidentCount = dcount(IncidentNumber),
    Incidents = make_set(ProviderIncidentId, 5),
    Severities = make_set(Severity, 5)
    by EntityValue
| extend EntityType = "Account"
| order by IncidentCount desc
| take 10;
// Top targeted devices
let TopDevices = IncidentEntities
| where EntityType == "host"
| summarize 
    IncidentCount = dcount(IncidentNumber),
    Incidents = make_set(ProviderIncidentId, 5),
    Severities = make_set(Severity, 5)
    by EntityValue
| extend EntityType = "Device"
| order by IncidentCount desc
| take 10;
union TopAccounts, TopDevices
| order by IncidentCount desc
```

---

## Query 6: Incident Tag Analysis — AutoAssigned vs User Tags

**Purpose:** What tags (labels) are being applied to incidents, by whom (ML vs SOC), and what do they classify? Reveals Defender XDR's ML classification patterns and SOC tagging workflows.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/governance query — tag usage analysis across incidents. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend ParsedLabels = parse_json(Labels)
| mv-expand Label = ParsedLabels
| extend TagName = tostring(Label.labelName), TagType = tostring(Label.labelType)
| where isnotempty(TagName)
| summarize
    IncidentCount = dcount(IncidentNumber),
    OpenCount = dcountif(IncidentNumber, Status in ("New", "Active")),
    ClosedCount = dcountif(IncidentNumber, Status == "Closed"),
    Severities = make_set(Severity, 5)
    by TagName, TagType
| order by IncidentCount desc
```

---

## Query 7: Alert-to-Incident Correlation Depth

**Purpose:** How many alerts are being correlated into each incident? Incidents with high alert counts indicate complex multi-stage attacks. Single-alert incidents may be candidates for tuning or auto-closure.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/hygiene query — alert count distribution for incident complexity analysis. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend AlertCount = toint(parse_json(AdditionalData).alertsCount)
| extend AlertBucket = case(
    AlertCount == 1, "1 (singleton)",
    AlertCount <= 5, "2-5",
    AlertCount <= 20, "6-20",
    AlertCount <= 50, "21-50",
    AlertCount <= 100, "51-100",
    strcat("> 100"))
| summarize
    IncidentCount = dcount(IncidentNumber),
    AvgAge = avg(datetime_diff('day', now(), CreatedTime)),
    OpenCount = dcountif(IncidentNumber, Status in ("New", "Active")),
    TPCount = dcountif(IncidentNumber, Classification == "TruePositive")
    by AlertBucket, Severity
| order by AlertBucket asc, Severity asc
```

---

## Query 8: Incident Product Source Breakdown

**Purpose:** Which detection products are generating alerts that feed into incidents? Reveals whether coverage is balanced across MDE, MDI, MDO, MCAS, Sentinel, Purview, etc.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/coverage query — product source distribution across incidents. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend Products = parse_json(tostring(parse_json(AdditionalData).alertProductNames))
| mv-expand Product = Products
| extend Product = tostring(Product)
| where isnotempty(Product)
| summarize
    IncidentCount = dcount(IncidentNumber),
    OpenCount = dcountif(IncidentNumber, Status in ("New", "Active")),
    TPCount = dcountif(IncidentNumber, Classification == "TruePositive"),
    HighCritical = dcountif(IncidentNumber, Severity in ("High", "Critical"))
    by Product
| order by IncidentCount desc
```

---

## Query 9: Incident Velocity — New Incidents per Day

**Purpose:** How many new incidents are being created daily? Trend analysis reveals spikes (attack campaign), drops (tuning success), or sustained baselines. Broken down by severity.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/trend query — daily incident creation rate. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend Day = startofday(CreatedTime)
| summarize
    Total = dcount(IncidentNumber),
    High = dcountif(IncidentNumber, Severity in ("High", "Critical")),
    Medium = dcountif(IncidentNumber, Severity == "Medium"),
    Low = dcountif(IncidentNumber, Severity in ("Low", "Informational"))
    by Day
| order by Day desc
```

---

## Query 10: Mean Time to Close (MTTC) by Severity

**Purpose:** SOC efficiency metric — how long does it take to close incidents? Broken down by severity and classification to distinguish real threat remediation time from FP dismissal time.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/SOC metrics query — MTTC calculation. No row-level detection."
-->
```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| where isnotempty(ClosedTime) and isnotempty(CreatedTime)
| extend MTTC_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize
    IncidentCount = dcount(IncidentNumber),
    AvgMTTC_Hours = round(avg(MTTC_Hours), 1),
    MedianMTTC_Hours = round(percentile(MTTC_Hours, 50), 1),
    P90_MTTC_Hours = round(percentile(MTTC_Hours, 90), 1)
    by Severity, Classification
| order by Severity asc, Classification asc
```
