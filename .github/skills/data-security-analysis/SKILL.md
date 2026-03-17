---
name: data-security-analysis
description: 'Use this skill when asked to analyze data security events, sensitive information type (SIT) access patterns, DLP policy matches, or Purview insider risk activity. Triggers on keywords like "data security", "sensitive information type", "SIT access", "who accessed sensitive data", "DLP events", "DataSecurityEvents", "EDM access", "exact data match", "credit card access", "sensitive file access", "insider risk activity", "Purview data security", "SIT breakdown", "classify access", or when investigating which users accessed documents containing specific sensitive information types. This skill queries DataSecurityEvents in Advanced Hunting to produce comprehensive SIT access analysis including volume breakdowns, user-level drill-downs, file inventories, action type distribution, DLP policy correlation, temporal patterns, and risk-ranked user summaries. Supports inline chat and markdown file output. Designed for large environments (100k+ users) with aggressive summarization and tiered drill-down.'
---

# Data Security Events Analysis — Instructions

## Purpose

This skill analyzes **DataSecurityEvents** (Microsoft Purview Insider Risk Management / DLP telemetry) to answer questions about **who accessed documents containing sensitive information types (SITs)** — including EDM (Exact Data Match), built-in SITs (credit cards, SSNs, etc.), and trainable classifiers.

**Primary Table:** `DataSecurityEvents` (Defender XDR Advanced Hunting)

| Use Case | Example Question |
|----------|-----------------|
| SIT access audit | "Who accessed files with credit card numbers in the last 30 days?" |
| EDM monitoring | "Show me all access to documents matching our EDM SIT" |
| DLP event analysis | "What DLP policy matches occurred this week?" |
| Insider risk triage | "Which users have the most sensitive data interactions?" |
| SIT landscape overview | "What sensitive information types exist in our environment?" |

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[SIT GUID Mapping Strategy](#sit-guid-mapping-strategy)** - How SIT GUIDs are resolved to names
3. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
4. **[Quick Start](#quick-start-tldr)** - 6-step execution pattern
5. **[Execution Workflow](#execution-workflow)** - 4-phase analysis process
6. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns (Queries 1-10)
7. **[Report Template](#report-template)** - Rendering rules (10 rules) + output format specification
8. **[Known Pitfalls](#known-pitfalls)** - Table quirks and edge cases (18 entries)
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY data security analysis:**

1. **ALWAYS use `RunAdvancedHuntingQuery`** — DataSecurityEvents is an Advanced Hunting table, NOT available in Sentinel Data Lake
2. **ALWAYS run Query 1 (SIT Discovery) first** — establishes which SITs are active and builds the GUID-to-Name mapping
3. **ALWAYS use `summarize` aggressively** — this table can have 600k+ rows in 30 days even in mid-size tenants. NEVER retrieve raw rows except for targeted samples
4. **ALWAYS pre-filter with `has` before `mv-expand`** on `SensitiveInfoTypeInfo` — the `has "<GUID>"` filter avoids expensive expansion on non-matching rows
5. **ALWAYS use `tostring()` + double `parse_json()`** for SensitiveInfoTypeInfo — it's `Collection(String)`, not native dynamic
6. **NEVER report SIT GUIDs without attempting name resolution** — use the mapping strategy below
7. **ALWAYS ask for output mode** if not specified: inline chat or markdown file
8. **Prerequisite:** DataSecurityEvents requires **Insider Risk Management opt-in** to share data with Defender XDR. If the table returns 0 rows or "table not found", inform the user of this requirement

### ⛔ PROHIBITED ACTIONS

| Action | Status |
|--------|--------|
| Querying DataSecurityEvents via `mcp_sentinel-data_query_lake` | ❌ **PROHIBITED** — AH-only table |
| Retrieving raw rows without `summarize` or `take` limit | ❌ **PROHIBITED** — table is massive |
| Reporting SIT GUIDs without name resolution attempt | ❌ **PROHIBITED** |
| Running `mv-expand` on SensitiveInfoTypeInfo without pre-filtering with `has` | ❌ **PROHIBITED** — performance killer at scale |
| Assuming `SensitiveInfoTypeInfo` is native dynamic | ❌ **PROHIBITED** — it's `Collection(String)`, requires double-parse |

---

## SIT GUID Mapping Strategy

### The Problem

`DataSecurityEvents.SensitiveInfoTypeInfo` contains SIT **GUIDs**, not human-readable names. SIT GUIDs fall into three categories:

| Category | Resolvable via KQL? | Example |
|----------|---------------------|---------|
| **Built-in Microsoft SITs** | ✅ Yes — use embedded mapping | `50842eb7-...-b085` → "Credit Card Number" |
| **Custom/EDM SITs** | ❌ No — org-specific GUIDs | `b28fcea1-...-9291` → "Project Obsidian" (custom) |
| **Trainable Classifiers (ML)** | ❌ No — `ClassifierType: "MLModel"` | `77a140be-...-7560` → unknown ML classifier |

### Resolution Strategy (3 tiers, in order)

#### Tier 1: Embedded Well-Known SIT Mapping (instant, no auth)

The query library below includes a `datatable` of the **most common Microsoft SIT GUIDs** encountered in production environments. This covers ~90% of detections in typical tenants.

#### Tier 2: User-Provided Custom SIT Mapping (config-driven)

If the user has custom/EDM SITs, they can provide a mapping in `config.json` under a `sit_mapping` key:

```json
{
  "sit_mapping": {
    "<custom-sit-guid-1>": "Your Custom SIT Name",
    "<custom-sit-guid-2>": "Your EDM SIT Name"
  }
}
```

**At skill startup:** Check if `config.json` has a `sit_mapping` section. If yes, merge it into the KQL `datatable` for name resolution.

#### Tier 3: PowerShell Resolution (optional, on-demand)

If unresolved GUIDs remain after Tier 1+2, **offer** to resolve them via PowerShell:

> "I found N SIT GUIDs that aren't in the built-in mapping. Would you like me to resolve them via `Get-DlpSensitiveInformationType`? This requires an active Security & Compliance PowerShell session (`Connect-IPPSSession`)."

If the user agrees:

```powershell
# Requires: Install-Module ExchangeOnlineManagement
# Requires: Connect-IPPSSession -UserPrincipalName <UPN>
Get-DlpSensitiveInformationType -Identity "<GUID>" | Select-Object Name, Id, Publisher
```

**After resolution:** Offer to save the mapping to `config.json` for future runs.

#### Post-Resolution Persistence (MANDATORY)

After Tier 3 PowerShell resolution completes, **always offer** to persist the resolved GUIDs:

> "I resolved N SIT GUIDs via PowerShell. Would you like me to save these to `config.json` under `sit_mapping` so future runs resolve them automatically via Tier 2?"

If the user agrees, read the current `config.json`, add/merge a `sit_mapping` object with the resolved GUIDs, and write it back. Format:

```json
{
  "sit_mapping": {
    "<guid>": "<resolved-name>",
    "<guid>": "<resolved-name>"
  }
}
```

**Why this matters:** Without persistence, every new session re-encounters the same unresolved GUIDs. The first report in a workspace should resolve and persist; subsequent runs benefit automatically.

### Trainable Classifiers

GUIDs with `ClassifierType: "MLModel"` are **trainable classifiers** and may not resolve via `Get-DlpSensitiveInformationType`. Display them as:
- `[ML Classifier] <GUID>` if unresolved
- Check if the GUID appears in the well-known mapping (some trainable classifiers have known GUIDs)

---

## Output Modes

**ASK the user which they prefer** if not explicitly specified. Both may be selected.

### Mode 1: Inline Chat Summary (Default)
- Render analysis directly in chat
- Includes summary tables, top-N breakdowns, risk-ranked user list
- Best for quick review and follow-up questions

### Mode 2: Markdown File Report
- Save to `reports/data-security/DataSecurity_Analysis_<scope>_<timestamp>.md`
- Full detail including all phases, temporal charts, file inventories
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename pattern:** `DataSecurity_Analysis_<scope>_YYYYMMDD_HHMMSS.md`
  - `<scope>` = `tenant_wide`, `sit_<SITname>`, `user_<username>`, etc.

---

## Quick Start (TL;DR)

1. **Determine scope** → Tenant-wide overview? Specific SIT? Specific user? Time range?
2. **Check config.json** → Look for `sit_mapping` section for custom SIT names
3. **Run Phase 1** → Query 1 (SIT Discovery) to find active SITs and build mapping
4. **Run Phase 2** → Queries 2-5 (breakdowns by action type, user, file, time)
5. **Run Phase 3** → Queries 6-8 (DLP correlation, workload, SIT drill-down), Query 10b (file-based spikes)
6. **Output Results** → Render in selected mode(s), offer PowerShell resolution for unknowns

---

## Execution Workflow

### Phase 1: Discovery & Mapping (always run first)

**Goal:** Establish what SITs exist in the data, their volume, and resolve GUIDs to names.

1. Run **Query 1** (SIT Discovery) — returns top SIT GUIDs with hit counts
2. Apply Tier 1 mapping (embedded `datatable`) to resolve known GUIDs
3. Check `config.json` for Tier 2 mapping to resolve custom GUIDs
4. Flag any remaining unresolved GUIDs for optional Tier 3 (PowerShell)
5. Present the SIT landscape to the user before proceeding

### Phase 2: Breakdown Analysis

**Goal:** Decompose SIT access patterns by multiple dimensions.

Run these queries in parallel where possible:

| Query | Dimension | Purpose |
|-------|-----------|---------|
| Query 2 | **Action Type** | What operations triggered SIT detections (file read, download, copy, Copilot response, etc.) |
| Query 3 | **User Ranking** | Top users by SIT interaction volume — risk-ranked |
| Query 4 | **File Inventory** | Top files/documents containing the most SIT detections |
| Query 5 | **Temporal Pattern** | Daily/hourly volume trend to spot spikes |

### Phase 3: Deep Dive (conditional on scope)

| Scenario | Run These |
|----------|-----------|
| **Tenant-wide overview** | Query 6 (DLP policy matches), Query 7 (Workload breakdown) |
| **Specific SIT investigation** | Query 8 (Single-SIT deep dive with full user/file/action breakdown) |
| **Specific user investigation** | Query 9 (Single-user SIT access profile) |
| **Anomaly detection** | Query 10b (file-based spikes — PRIMARY), Query 10 (overall spikes — secondary, includes Copilot) |

### Phase 4: Report Generation

Render findings using the Report Template below.

---

## Sample KQL Queries

### Well-Known SIT GUID Mapping (datatable)

Use this `let` block as a prefix for any query that needs name resolution. It covers the most common Microsoft SITs plus placeholders for custom SITs from `config.json`.

```kql
// Well-known SIT GUID mapping — covers ~90% of typical detections
// Add custom/EDM SIT GUIDs from config.json sit_mapping section
let SITMapping = datatable(SITId: string, SITName: string) [
    // ── Financial ──
    "50842eb7-edc8-4019-85dd-5a5c1f2bb085", "Credit Card Number",
    "cb353f78-2b72-4c3c-8827-92ebe4f69fdf", "ABA Routing Number",
    "78e09124-f2c3-4656-b32a-c1a132cd2711", "Brazil CPF Number",
    // ── Identity / PII ──
    "a44669fe-0d48-453d-a9b1-2cc83f2cba77", "U.S. Social Security Number (SSN)",
    "a7dd5e5f-e7f9-4626-a2c6-86a8cb6830d2", "IP Address v4",
    "1daa4ad5-e2dd-4ca4-a788-54722c09efb2", "IP Address",
    "50b8b56b-4ef8-44c2-a924-03374f5831ce", "All Full Names",
    "8548332d-6d71-41f8-97db-cc3b5fa544e6", "All Physical Addresses",
    "44aa44f2-63d1-41df-af0d-970283ac41e2", "U.S. Physical Addresses",
    "d1d18c85-1203-46f5-b32f-2d6309de4e5b", "Australia Physical Addresses",
    "6fa57f91-314a-4561-8248-7ab921957448", "Philippines Passport Number",
    "d0001c83-e72f-4360-98d3-f5a41dc5a380", "Indonesia Passport Number",
    // ── Healthcare ──
    "065bdd91-ef07-40d3-b8a4-0aea722eaa49", "All Medical Terms And Conditions",
    "17066377-466d-43ff-997f-c9240414021c", "Diseases",
    "f6dc2d17-3549-41e2-af29-ae1846ae9542", "Types Of Medication",
    "ee05bb9c-7b87-42e1-9987-446b243245d5", "Lab Test Terms",
    // ── Azure / Cloud secrets ──
    "0f587d92-eb28-44a9-bd1c-90f2892b47aa", "Azure DocumentDB Auth Key",
    "ce1a126d-186f-4700-8c0c-486157b953fd", "Azure SQL Connection String",
    "0b34bec3-d5d6-4974-b7b0-dcdb5c90c29d", "Azure IoT Connection String",
    "c7bc98e8-551a-4c35-a92d-d2c8cda714a7", "Azure Storage Account Key",
    "095a7e6c-efd8-46d5-af7b-5298d53a49fc", "Azure Redis Cache Connection String",
    // ─── ADD CUSTOM / EDM SITs FROM config.json sit_mapping HERE ───
    // Example: "<your-edm-guid>", "Your EDM SIT Name",
    "END_MARKER", "END_MARKER"
];
```

> **Instructions:** When building queries, read `config.json` for `sit_mapping` entries and insert them into the `datatable` above, replacing the `END_MARKER` row. If no custom mapping exists, remove the `END_MARKER` row.

---

### Query 1: SIT Discovery — Active SIT Landscape

**Purpose:** Find all active SIT GUIDs, their volume, and classify them.

```kql
// Query 1: SIT Discovery — What SITs are active in this environment?
// Adjust timespan as needed (default: 30d)
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| extend ClassifierType = tostring(SITJson.ClassifierType)
| extend SITConfidence = toint(SITJson.Confidence)
| extend SITCount = toint(SITJson.Count)
| summarize 
    TotalEvents = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId),
    AvgConfidence = avg(SITConfidence),
    MaxConfidence = max(SITConfidence),
    ClassifierTypes = make_set(ClassifierType)
    by SITId
| order by TotalEvents desc
| take 50
```

**Post-processing:** Join results with the `SITMapping` datatable to resolve names. Flag any GUIDs not in the mapping as "Unknown — custom/EDM SIT" or "[ML Classifier]" based on `ClassifierTypes`.

---

### Query 2: Action Type Breakdown

**Purpose:** Break down SIT detections by what operation triggered them.

```kql
// Query 2: Action Type Breakdown — What operations trigger SIT detections?
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    EventCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId)
    by ActionType
| order by EventCount desc
```

---

### Query 3: Top Users by SIT Interaction Volume

**Purpose:** Risk-rank users by sensitive data interaction volume. Designed for 100k+ user environments.

```kql
// Query 3: Top 50 Users by SIT access volume
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    TotalEvents = count(),
    DistinctSITs = dcount(tostring(parse_json(tostring(parse_json(tostring(SensitiveInfoTypeInfo))[0])).SensitiveInfoTypeId)),
    DistinctFiles = dcount(ObjectId),
    ActionTypes = make_set(ActionType),
    Workloads = make_set(Workload),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn
| order by TotalEvents desc
| take 50
```

---

### Query 4: Top Files by SIT Detection Count

**Purpose:** Identify the most sensitive documents — files with the most SIT detections across access events.

```kql
// Query 4: Top 30 Files by SIT detection frequency
// Excludes system/operational files (DLPCache, EBWebView) that are Defender operational reads, not user-initiated
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| where isnotempty(ObjectId)
| where ObjectId !has "DLPCache" and ObjectId !has "EBWebView" and ObjectId !has "\\ProgramData\\Microsoft\\Windows Defender\\"
| summarize 
    AccessCount = count(),
    DistinctUsers = dcount(AccountUpn),
    ActionTypes = make_set(ActionType),
    LastAccessed = max(Timestamp)
    by ObjectId
| order by AccessCount desc
| take 30
```

---

### Query 5: Temporal Pattern — Daily SIT Event Volume

**Purpose:** Detect volume spikes or anomalies in SIT-related activity over time.

```kql
// Query 5: Daily SIT event volume trend — includes file-based column for spike attribution (Rule 10)
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    DailyEvents = count(), 
    FileEvents = countif(Workload !in ("Copilot", "ConnectedAIApp")),
    DistinctUsers = dcount(AccountUpn) 
    by Day = bin(Timestamp, 1d)
| order by Day asc
```

---

### Query 6: DLP Policy Match Correlation

**Purpose:** Show DLP policy matches alongside SIT detections — which policies fired and how often.

```kql
// Query 6: DLP Policy Match breakdown
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(DlpPolicyMatchInfo)
| extend DlpInfo = parse_json(DlpPolicyMatchInfo)
| mv-expand DlpPolicy = DlpInfo
| extend PolicyName = tostring(DlpPolicy.PolicyName)
| extend PolicyId = tostring(DlpPolicy.PolicyId)
| summarize 
    MatchCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId),
    ActionTypes = make_set(ActionType)
    by PolicyName
| order by MatchCount desc
```

---

### Query 7: Workload Breakdown

**Purpose:** Where is sensitive data being accessed — SharePoint, OneDrive, Exchange, Teams, Endpoints, Copilot?

```kql
// Query 7: Workload distribution of SIT events
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize 
    EventCount = count(),
    DistinctUsers = dcount(AccountUpn),
    DistinctFiles = dcount(ObjectId)
    by Workload
| order by EventCount desc
```

---

### Query 8: Single-SIT Deep Dive

**Purpose:** Full breakdown for a specific SIT GUID — who accessed it, which files, what operations, over what time period.

> **Usage:** Replace `<TARGET_SIT_GUID>` with the specific SIT GUID to investigate (e.g., an EDM SIT GUID).

```kql
// Query 8: Single-SIT deep dive — replace GUID
let targetSIT = "<TARGET_SIT_GUID>";
DataSecurityEvents
| where Timestamp > ago(30d)
| where isnotempty(SensitiveInfoTypeInfo)
| where SensitiveInfoTypeInfo has targetSIT
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| where SITId == targetSIT
| extend SITConfidence = toint(SITJson.Confidence)
| extend SITCount = toint(SITJson.Count)
| summarize 
    AccessCount = count(),
    AvgConfidence = avg(SITConfidence),
    TotalSITInstances = sum(SITCount),
    ActionTypes = make_set(ActionType),
    Workloads = make_set(Workload),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountUpn, ObjectId
| order by AccessCount desc
| take 100
```

---

### Query 9: Single-User SIT Access Profile

**Purpose:** Complete SIT interaction profile for a specific user — what SITs they accessed, which files, operations, and when.

> **Usage:** Replace `<TARGET_UPN>` with the user's UPN.

```kql
// Query 9: Single-user SIT access profile
let targetUser = "<TARGET_UPN>";
DataSecurityEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ targetUser
| where isnotempty(SensitiveInfoTypeInfo)
| mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo))
| extend SITJson = parse_json(tostring(SIT))
| extend SITId = tostring(SITJson.SensitiveInfoTypeId)
| extend SITConfidence = toint(SITJson.Confidence)
| extend SITCount = toint(SITJson.Count)
| summarize 
    AccessCount = count(),
    DistinctFiles = dcount(ObjectId),
    AvgConfidence = avg(SITConfidence),
    ActionTypes = make_set(ActionType),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by SITId
| order by AccessCount desc
```

---

### Query 10: Anomaly Detection — Users with SIT Access Spikes

**Purpose:** Compare each user's recent 7-day SIT activity against their 30-day daily average to detect sudden spikes. Designed for 100k+ user environments.

```kql
// Query 10: SIT access spike detection (7d recent vs 23d baseline) — ALL events
// NOTE: This includes Copilot events. For file-based-only spikes, use Query 10b below.
let baseline = DataSecurityEvents
| where Timestamp between (ago(30d) .. ago(7d))
| where isnotempty(SensitiveInfoTypeInfo)
| summarize BaselineTotal = count() by AccountUpn
| extend BaselineDailyAvg = round(BaselineTotal / 23.0, 1); // 23 days in baseline window
let recent = DataSecurityEvents
| where Timestamp > ago(7d)
| where isnotempty(SensitiveInfoTypeInfo)
| summarize RecentTotal = count() by AccountUpn
| extend RecentDailyAvg = round(RecentTotal / 7.0, 1);
recent
| join kind=inner baseline on AccountUpn
| extend SpikeRatio = round(RecentDailyAvg / BaselineDailyAvg, 2)
| where SpikeRatio > 2.0 and RecentTotal > 20 and BaselineTotal >= 10
| project AccountUpn, BaselineDailyAvg, RecentDailyAvg, SpikeRatio, BaselineTotal, RecentTotal
| order by SpikeRatio desc
| take 30
```

---

### Query 10b: File-Based-Only Spike Detection (Excludes Copilot)

**Purpose:** Same as Query 10 but excludes Copilot and ConnectedAIApp events to surface actual file access spikes. This is the primary risk signal — Copilot spikes often just reflect adoption changes.

```kql
// Query 10b: File-based SIT access spike detection (excludes Copilot/AI events)
let CopilotActionTypes = dynamic(["Risky prompt entered in Copilot", "Sensitive response received in Copilot",
    "Risky prompt entered in connected AI apps", "Sensitive response received in connected AI apps"]);
let baseline = DataSecurityEvents
| where Timestamp between (ago(30d) .. ago(7d))
| where isnotempty(SensitiveInfoTypeInfo)
| where not(ActionType has_any (CopilotActionTypes))
| where Workload !in ("Copilot", "ConnectedAIApp")
| summarize BaselineTotal = count() by AccountUpn
| extend BaselineDailyAvg = round(BaselineTotal / 23.0, 1);
let recent = DataSecurityEvents
| where Timestamp > ago(7d)
| where isnotempty(SensitiveInfoTypeInfo)
| where not(ActionType has_any (CopilotActionTypes))
| where Workload !in ("Copilot", "ConnectedAIApp")
| summarize RecentTotal = count() by AccountUpn
| extend RecentDailyAvg = round(RecentTotal / 7.0, 1);
recent
| join kind=inner baseline on AccountUpn
| extend SpikeRatio = round(RecentDailyAvg / BaselineDailyAvg, 2)
| where SpikeRatio > 2.0 and RecentTotal > 10 and BaselineTotal >= 10
| project AccountUpn, BaselineDailyAvg, RecentDailyAvg, SpikeRatio, BaselineTotal, RecentTotal
| order by SpikeRatio desc
| take 30
```

---

## Report Template

### Report Rendering Rules

**These rules are MANDATORY for all report output (inline chat and markdown file). Follow strictly.**

#### Rule 1: Risk Rating Scale

When assigning risk levels to users in the file-based user ranking, use this hierarchy:

| Risk Level | Evidence Required |
|------------|------------------|
| **Critical** | "Files collected and exfiltrated" ActionType present — confirmed insider risk exfiltration signal **OR** mass exfiltration pattern: ≥1,000 distinct files to removable media + file deletions within a ≤48-hour window (volume-based escalation even without the IRM-labeled ActionType) |
| **High** | Exfiltration signals below Critical thresholds (e.g., USB copies < 1,000 files without deletion pattern) OR sustained high DLP alert volume (top 2-3 by events/files) |
| **Medium** | Broad SIT diversity (10+ SIT types) OR cross-workload activity (3+ workloads) OR external domain WITHOUT explicit exfiltration signal |
| **Low** | Single-workload, moderate volume, no exfiltration or anomaly signals |

⛔ **PROHIBITED:** Rating a user with "Files collected and exfiltrated" as Medium or Low. This ActionType is always High or Critical.
⛔ **PROHIBITED:** Rating a user with ≥1,000 files USB-copied + deletion in ≤48h as anything below Critical.

#### Rule 2: Executive Summary Uses File-Based Metrics Only

The Executive Summary **MUST** cite file-based (non-Copilot) event counts and file counts for user risk descriptions. Never cite overall metrics that include Copilot volume — this inflates perceived risk.

| Context | Cite | Example |
|---------|------|---------|
| ✅ File-based risk summary | Non-Copilot events, non-Copilot files | "u3087 generated 211 file-based events across 32 files" |
| ❌ Inflated overall metrics | Total events including Copilot | ~~"u1812 — 294 total events including 185 files"~~ |

#### Rule 3: Top Users Overall Section — Copilot Compression

When Copilot events exceed 80% of total volume:
- **Do NOT render** a standalone "Top Users Overall" section dominated by Copilot service accounts
- Instead, include a brief note: "Top overall users are dominated by Copilot service accounts/heavy Copilot users — see file-based user ranking below for actual data access risk."
- If any users in the top-10 overall have **multi-workload activity** (Copilot + file operations), call them out in a single sentence rather than a full table

#### Rule 4: Copilot Count Reconciliation

When reporting Copilot vs file-based splits, ensure the counts reconcile across sections:
- Action Type breakdown Copilot total = Workload breakdown Copilot total
- If they differ (e.g., Connected AI App events counted differently), annotate the delta
- Show the reconciliation in the Action Type section: "Copilot interactions: N events (Action Types: Risky prompt X + Sensitive response Y + Combined Z = N)"

#### Rule 5: Scope & Limitations Section (Required for Markdown Reports)

Markdown file reports MUST include a **Scope & Limitations** section immediately after the Executive Summary. Include:

```markdown
## Scope & Limitations

| Consideration | Detail |
|--------------|--------|
| **Data Source** | DataSecurityEvents (Defender XDR Advanced Hunting) — requires Insider Risk Management opt-in to share data with Defender XDR |
| **Coverage** | SIT detections only — files with sensitivity labels but no SIT content match do NOT appear in this data |
| **Retention** | 30-day Advanced Hunting retention |
| **ML Classifiers** | N trainable classifier GUIDs could not be resolved — see Unresolved SIT GUIDs section |
| **Copilot Volume** | Copilot events represent X% of total volume and are separated from file-based analysis throughout this report |
```

Fill in the actual values for N and X% from the query results.

#### Rule 6: SIT Landscape Table Integrity

- Each GUID must appear **exactly once** in the SIT Landscape table — one row per GUID, no exceptions
- **NEVER group multiple GUIDs into a single row** with slash-separated values (e.g., `1e883268/d2cdc387/bf6e0b84...`). Even "copy" variants of the same SIT that share identical metrics MUST be separate rows
- After all GUID resolution tiers complete, deduplicate by GUID — if conflicts exist, prefer the most specific resolution (Tier 3 PowerShell > Tier 2 config > Tier 1 embedded)
- Group the table by category: Custom/Organization SITs, Built-in Microsoft SITs, ML Classifiers (Unresolvable)
- Do NOT include a GUID under two different names
- The total distinct SIT count cited in the Executive Summary must equal the number of rows in the SIT Landscape tables (sum of all category sub-tables)
- **Post-render verification (MANDATORY):** After building all SIT Landscape sub-tables, count the total rows. If the exec summary cites a different number, update the exec summary to match. Format: "N active SIT types" where N = sum of rows across Custom, Built-in, and Unresolved sub-tables

⛔ **PROHIBITED:** Bundling GUIDs like "Credit Card Number copy (x3)" with `6,966 ea.` — each of the 3 GUIDs must be its own row with its own exact counts
⛔ **PROHIBITED:** Exec summary citing a SIT count that doesn't match the actual row count in the SIT Landscape tables

#### Rule 7: Spike Detection — File-Based Primary, Overall Secondary

When rendering spike alerts:
- **Primary:** Always run and display **Query 10b** (file-based-only spikes) as the main spike alert section. This surfaces actual sensitive data access spikes.
- **Secondary:** Run Query 10 (all events) only if the user requests overall spikes or if there are interesting patterns worth noting. Include a clear note that these spikes are predominantly Copilot-driven.
- If only running one spike query, always prefer Query 10b.
- In the report, label sections clearly: "File-Based SIT Access Spikes" vs "Overall SIT Access Spikes (incl. Copilot)".

#### Rule 8: Top Files — Exclude System/Operational Files

The Top Files section must exclude Defender for Endpoint operational file reads:
- `C:\ProgramData\Microsoft\Windows Defender\DLPCache\*` — DLP label metadata cache reads
- `*\EBWebView\*` — Edge WebView browser cache
- Any path matching `\ProgramData\Microsoft\` that is clearly a system/cache path

If system files appear in results despite the query filter, separate them into a "System/Operational Files" subsection below the main "User-Accessed Files" list.

#### Rule 9: Risk Rating Consistency — Exec Summary Must Match User Table

Every user mentioned in the Executive Summary MUST use the **same risk rating** as in the File-Based Top Users table. If the table says 🔴 Critical, the exec summary must say Critical (and vice versa).

- After building the File-Based Top Users table (the source of truth), cross-check every user mention in the exec summary
- If there is a conflict, the User Table rating wins — update the exec summary to match
- Never rate a user differently in two sections of the same report

⛔ **PROHIBITED:** Exec summary says "High" while user table says "Critical" for the same user (or any other mismatch).

#### Rule 10: Temporal Pattern — Include File-Based Event Column

The Temporal Pattern (daily volume) section MUST include a `File Events` column alongside the total. Without this, daily spikes appear alarming when they may be entirely Copilot-driven.

| Column | Required | Source |
|--------|----------|--------|
| Date | ✅ | `bin(Timestamp, 1d)` |
| Daily Events | ✅ | Total `count()` |
| **File Events** | ✅ | `countif(Workload !in ("Copilot", "ConnectedAIApp"))` |
| Distinct Users | ✅ | `dcount(AccountUpn)` |
| Notable | ✅ | Annotation for spikes |

When annotating spikes (🔴), clarify whether the spike is Copilot-driven or file-driven:
- "🔴 Major spike — file-driven" (if File Events also spike)
- "🟡 Copilot adoption spike — file activity normal" (if only total spikes but File Events are stable)

Use Query 5 (updated) which returns both columns.

---

### Inline Chat Format

```markdown
## 📊 Data Security Events Analysis
**Scope:** <Tenant-wide / SIT: <name> / User: <UPN>>
**Time Range:** <start> to <end>
**Total Events:** <N> | **Distinct Users:** <N> | **Distinct Files:** <N>

### SIT Landscape
| # | SIT Name | GUID (short) | Events | Users | Files | Classifier |
|---|----------|-------------|--------|-------|-------|------------|
| 1 | Credit Card Number | 50842eb7... | 7,255 | 46 | 346 | Content |
| 2 | All Full Names | 50b8b56b... | 128,957 | 1,475 | 119 | Content |
| ... | | | | | | |

### Action Type Breakdown
| Action Type | Events | Users | Files |
|-------------|--------|-------|-------|
| Sensitive response received in Copilot | 228,564 | ... | ... |
| Risky prompt entered in Copilot | 390,905 | ... | ... |
| ... | | | |

### 🔴 Top Users by SIT Volume (Risk-Ranked)
| # | User | Total Events | Distinct SITs | Distinct Files | Last Active |
|---|------|-------------|---------------|----------------|-------------|
| 1 | user@domain.com | 12,345 | 8 | 42 | 2026-03-16 |
| ... | | | | | |

### ⚠️ SIT Access Spike Alerts
| User | Baseline (daily avg) | Recent (daily avg) | Spike Ratio | Status |
|------|---------------------|-------------------|-------------|--------|
| user@domain.com | 5.2 | 47.1 | 9.06x | 🔴 Spike |
| ... | | | | |

### Unresolved SIT GUIDs
<List of GUIDs not in mapping — offer PowerShell resolution>
```

### Markdown File Format

Same structure as inline, wrapped in proper markdown with:
- Report metadata header (generated timestamp, scope, tool versions)
- **Scope & Limitations section** immediately after Executive Summary (see Rule 5 above)
- Each section as H2/H3
- **File-based user ranking** as the primary risk section (NOT the Copilot-dominated overall ranking)
- DLP Policy Match section with DefaultRule explanation for empty PolicyName entries
- Code fences for any raw data samples
- Save to: `reports/data-security/DataSecurity_Analysis_<scope>_YYYYMMDD_HHMMSS.md`

---

## Known Pitfalls

| Pitfall | Detail | Mitigation |
|---------|--------|------------|
| **`SensitiveInfoTypeInfo` is `Collection(String)`, not dynamic** | Each element is a JSON **string** requiring double-parse: `parse_json(tostring(SensitiveInfoTypeInfo))` to expand array, then `parse_json(tostring(element))` to access fields | Always double-parse. Direct dot-notation fails silently |
| **Massive row counts** | 600k+ rows in 30 days for mid-size tenants; millions for 100k+ user orgs | ALWAYS `summarize` first. NEVER retrieve raw rows without `take` limit |
| **`mv-expand` is expensive** | Expanding SensitiveInfoTypeInfo across 600k rows without pre-filtering is extremely slow | Pre-filter with `where SensitiveInfoTypeInfo has "<GUID>"` before `mv-expand` |
| **Copilot dominates event volume** | "Risky prompt entered in Copilot" and "Sensitive response received in Copilot" can be 90%+ of events | Filter to specific `ActionType` values when investigating file access specifically |
| **Trainable classifiers (MLModel) don't resolve** | GUIDs with `ClassifierType: "MLModel"` may not exist in `Get-DlpSensitiveInformationType` | Display as `[ML Classifier] <GUID>` and note in report |
| **SIT GUID is per-SIT, not per-detection** | Multiple documents can match the same SIT GUID — the GUID identifies the SIT **type**, not the specific match | Use `Count` and `Confidence` fields from SITJson for detection-level detail |
| **`ObjectId` can be empty** | Copilot interaction events may not have an ObjectId (no specific file) | Filter `isnotempty(ObjectId)` for file-specific analysis |
| **IRM opt-in required** | DataSecurityEvents is populated by Insider Risk Management. No opt-in = empty table | Check for 0 results and explain the prerequisite |
| **Table schema evolves** | DataSecurityEvents is in **Preview** — column names and availability may change | Run `getschema` if queries fail with column resolution errors |
| **`DlpPolicyMatchInfo` is sparse** | Only ~0.5% of rows have DLP policy match data (the rest are IRM-only detections) | Don't assume all SIT events have DLP data; they're independent signals |
| **Duplicate GUID in SIT mapping** | One GUID can only resolve to one SIT name. If a GUID appears in both the embedded `datatable` and a Tier 2/3 resolution with a different name, the result will have duplicate rows with conflicting names. This can happen when a built-in SIT GUID overlaps with a custom SIT copy, or when PowerShell returns a different display name than the embedded mapping | After resolving all GUIDs, **deduplicate by GUID** before rendering the SIT Landscape table. If a GUID maps to multiple names, prefer the Tier 3 (PowerShell) name over Tier 1 (embedded). Never show the same GUID on two rows with different names |
| **Empty `PolicyName` = DefaultRule ("Always audit")** | DLP alerts with empty/null `PolicyName` are typically generated by the built-in `DefaultRule` that fires when "Always audit file activity for devices" is enabled (ON by default). These are NOT orphaned or misconfigured policies — they are the expected result of the default audit setting | In the DLP Policy Match section, explain: "Events with empty PolicyName are generated by the built-in DefaultRule, which audits all monitored file types (Office, PDF, CSV) on onboarded devices when 'Always audit file activity for devices' is enabled (default: ON). No explicit DLP policy is required for these events." |
| **Compound ActionType values** | Some events have ActionType values that combine multiple labels (e.g., "Risky prompt entered in Copilot, Sensitive response received in Copilot" or "Sensitive info shared on Teams, DLP Rule Matched"). These are literal string values from the data, not aggregation artifacts | Display compound ActionTypes exactly as they appear in the data. Do NOT split or merge them — they represent events where multiple conditions were met simultaneously |
| **System/operational files dominate Top Files** | Files under `C:\ProgramData\Microsoft\Windows Defender\DLPCache\RMSLabels\` and `*\EBWebView\*` are Defender for Endpoint reading sensitivity label metadata — NOT user-initiated file access. These can dominate 90%+ of the Top Files list | Query 4 filters these paths. If they still appear, separate into a "System/Operational Files" subsection. Never present DLPCache reads as user data access risk |
| **Localized SIT names in CloudAppEvents** | CloudAppEvents `DLPRuleMatch` events include SIT names, but names appear **in the user's locale** (e.g., "የዱቤ ካርድ ቁጥር" instead of "Credit Card Number" for Amharic users). Same GUID can map to different name strings depending on locale | Always aggregate by **SIT GUID**, never by SIT name. Use the GUID-to-name mapping (Tier 1/2/3) for canonical English names. This applies when cross-referencing CloudAppEvents with DataSecurityEvents |
| **Browsing events are not files — separate from Top Files** | ActionTypes like "Generative AI websites browsed" and "Gambling websites browsed" reference URLs, not files. They have no `ObjectId` file path — only a URL domain. Including them under "Top Files" is misleading | Render browsing/URL events in a separate subsection (e.g., "External / AI Service Access") below Top Files. Never mix URL-based events into the file ranking tables. Title the Top Files section accurately ("Top Files" not "Top Files & URLs") |
| **Temporal spike annotations must reference known users** | When annotating daily spikes in the Temporal Pattern table (e.g., "🔴 Major spike — u625 SharePoint batch"), the attributed user MUST appear elsewhere in the report — in the File-Based Top Users table, a drill-down section, or at minimum a footnote. Referencing a user that exists nowhere else in the report violates the evidence-based analysis rule and creates an unverifiable claim | Before annotating a spike with a user attribution, verify the user appears in the Top Users ranking. If they don't make the top-10 but are the spike driver, either: (a) add them to the user table with a note "included due to temporal spike attribution", or (b) use a generic annotation ("🔴 Major spike — file-driven") without naming the user |

---

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `Failed to resolve table 'DataSecurityEvents'` | Table not available — IRM not opted in, or not connected to Defender XDR | Inform user: "DataSecurityEvents requires Microsoft Purview Insider Risk Management opt-in to share data with Defender XDR." |
| `0 results` for SensitiveInfoTypeInfo queries | No SIT detections in timeframe, or SIT detection not enabled in IRM policies | Widen time range; check if IRM policies include SIT detection |
| `Failed to resolve column 'ObjectName'` | Schema changed or column renamed | Use `ObjectId` instead (confirmed available). Run `getschema` to verify current schema |
| PowerShell `Get-DlpSensitiveInformationType` fails | Not connected to IPPS session | Run `Connect-IPPSSession -UserPrincipalName <UPN>` first |
| `The term 'Get-DlpSensitiveInformationType' is not recognized` | Module not installed or IPPS session in different terminal | `Install-Module ExchangeOnlineManagement` then `Connect-IPPSSession` in the same terminal session |

---

## File Access Action Types Reference

When the user specifically asks about **who opened/accessed/downloaded documents**, filter to these ActionTypes:

| ActionType | Meaning |
|------------|---------|
| `Sensitive File read` | File opened on endpoint (Defender for Endpoint) |
| `File accessed on SPO` | File opened in SharePoint Online / OneDrive |
| `File downloaded from SharePoint` | File downloaded from SPO/OneDrive |
| `File copied to Removable media` | File copied to USB/removable storage |
| `File upload to cloud` | File uploaded to cloud storage |
| `Sensitive file created` | New file created with sensitive content |
| `File Archived` | File moved to archive |
| `Text copied to clipboard from sensitive file` | Clipboard copy from sensitive doc |

**Copilot-related ActionTypes** (separate category — AI interaction, not direct file access):

| ActionType | Meaning |
|------------|---------|
| `Sensitive response received in Copilot` | Copilot surfaced content matching a SIT |
| `Risky prompt entered in Copilot` | User prompt triggered risk detection |

**DLP ActionTypes:**

| ActionType | Meaning |
|------------|---------|
| `Generated High severity DLP alerts` | DLP policy triggered a high-severity alert |
| `DLP Rule Matched` | DLP rule matched (may be combined with other types) |
