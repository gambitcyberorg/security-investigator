# Secure Score Leadership Reporting — Defender for Cloud

**Created:** 2026-03-04  
**Platform:** Both  
**Tables:** SecureScores, SecureScoreControls, SecurityRecommendation  
**Keywords:** secure score, defender for cloud, leadership report, score improvement, posture, compliance, security controls, remediation, continuous export, score trend  
**MITRE:** TA0040, TA0005  
**Timeframe:** Last 90 days (configurable)  

---

## Prerequisites

These queries require **Continuous Export** of Secure Score data to a Log Analytics workspace.  
Setup guide: https://learn.microsoft.com/azure/defender-for-cloud/continuous-export

When configuring continuous export, select **both** export frequencies:
- **Streaming updates** — real-time score changes as recommendations are remediated
- **Snapshots (Preview)** — weekly point-in-time snapshots for consistent trend reporting

### Tables Populated by Continuous Export

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `SecureScores` | Overall subscription score over time | `CurrentScore`, `MaxScore`, `PercentageScore`, `IsSnapshot` |
| `SecureScoreControls` | Per-control breakdown (e.g., "Manage access and permissions") | `ControlName`, `CurrentScore`, `MaxScore`, `HealthyResources`, `UnhealthyResources` |
| `SecurityRecommendation` | Individual recommendation states per resource | `RecommendationDisplayName`, `RecommendationState`, `RecommendationSeverity` |

### Important Notes

- **`IsSnapshot`**: Weekly snapshots (`true`) vs. streaming updates (`false`). For trend analysis, filter on `IsSnapshot == false` to get the most granular data, or `IsSnapshot == true` for consistent weekly cadence.
- **`DisplayName == "ASC score"`**: The main overall Secure Score. Filter on this to exclude sub-scores like "Score grace excluded".
- **`MaxScore` can fluctuate**: As Microsoft adds/removes recommendations or resources come in/out of scope, the denominator changes. Always track `PercentageScore` alongside `CurrentScore` for accurate trending.
- **Score refresh frequency**: Streaming updates arrive when a resource's health state changes. Snapshots are weekly. Expect gaps in data — no change = no new record.

---

## Query 1 — Overall Secure Score Trend (Leadership Dashboard)

**Purpose:** Show the overall Secure Score trajectory over time. Best for executive slide decks — "Here's where we started, here's where we are."

```kql
// Secure Score trend over time — overall subscription score
// Tip: Use IsSnapshot == false for streaming granularity, or true for weekly cadence
let lookback = 90d;
SecureScores
| where TimeGenerated > ago(lookback)
| where DisplayName == "ASC score"
| where IsSnapshot == false
| project TimeGenerated, CurrentScore, MaxScore, 
    PercentageScore = round(PercentageScore * 100, 1)
| order by TimeGenerated asc
```

**Visualization:** Line chart with `TimeGenerated` on X-axis, `PercentageScore` on Y-axis. Add `CurrentScore` as a secondary series to show absolute points gained.

---

## Query 2 — Score Change Summary (Period-over-Period)

**Purpose:** "We improved our Secure Score from X% to Y% over the last N days." Direct leadership talking point.

> **Compatibility note:** Uses `top 1` instead of `arg_min`/`arg_max` in `let` blocks for Advanced Hunting compatibility.

```kql
// Compare earliest vs latest score in a given period
let lookback = 90d;
let scores = SecureScores
| where TimeGenerated > ago(lookback)
| where DisplayName == "ASC score"
| where IsSnapshot == false;
let startRow = scores | top 1 by TimeGenerated asc
| project StartTime = TimeGenerated, StartScore = CurrentScore, StartMax = MaxScore,
    StartPct = round(PercentageScore * 100, 1);
let endRow = scores | top 1 by TimeGenerated desc
| project EndTime = TimeGenerated, EndScore = CurrentScore, EndMax = MaxScore,
    EndPct = round(PercentageScore * 100, 1);
startRow | extend dummy = 1
| join kind=inner (endRow | extend dummy = 1) on dummy
| project StartTime, StartScore, StartMax, StartPct,
    EndTime, EndScore, EndMax, EndPct,
    ScoreChange = round(EndScore - StartScore, 2),
    PctChange = round(EndPct - StartPct, 1)
```

---

## Query 3 — Weekly Score Snapshots (Consistent Cadence)

**Purpose:** Weekly data points for a clean trend line. Uses snapshot exports for consistency.

```kql
// Weekly Secure Score snapshots — consistent cadence for trend reporting
let lookback = 90d;
SecureScores
| where TimeGenerated > ago(lookback)
| where DisplayName == "ASC score"
| summarize arg_max(TimeGenerated, CurrentScore, MaxScore, PercentageScore) 
    by Week = startofweek(TimeGenerated)
| extend PercentageDisplay = round(PercentageScore * 100, 1)
| project Week, CurrentScore, MaxScore, PercentageDisplay
| order by Week asc
```

---

## Query 4 — Score Improvement Events (What Moved the Needle?)

**Purpose:** Identify specific dates where the score jumped. Correlate with remediation activity.

```kql
// Detect score jumps — when did the score increase?
let lookback = 90d;
SecureScores
| where TimeGenerated > ago(lookback)
| where DisplayName == "ASC score"
| where IsSnapshot == false
| sort by TimeGenerated asc
| extend PrevScore = prev(CurrentScore), PrevTime = prev(TimeGenerated)
| extend ScoreChange = CurrentScore - PrevScore
| where isnotnull(PrevScore)
| where ScoreChange != 0
| project TimeGenerated, CurrentScore, PrevScore, 
    ScoreChange = round(ScoreChange, 2),
    PercentageScore = round(PercentageScore * 100, 1),
    Direction = iff(ScoreChange > 0, "📈 Improved", "📉 Declined"),
    MaxScore
| order by TimeGenerated asc
```

---

## Query 5 — Security Control Scorecard (Current State)

**Purpose:** Show leadership which security control areas are strong and which need investment. Executive heatmap material.

> **Important:** A control at 100% does NOT mean all resources are healthy. MDC scores controls using **weighted recommendations** — high-weight recommendations being met can yield 100% even when many low-weight recommendations have unhealthy resources. Always pair this query with Query 8 (backlog) to show the full picture.

```kql — which areas are strong vs weak
SecureScoreControls
| where IsSnapshot == false
| summarize arg_max(TimeGenerated, *) by ControlName
| where Weight > 0  // Exclude controls with no applicable resources
| extend PercentageDisplay = round(PercentageScore * 100, 1)
| extend Status = case(
    PercentageScore == 1.0, "✅ Complete",
    PercentageScore >= 0.7, "🟢 Strong",
    PercentageScore >= 0.4, "🟡 Partial",
    PercentageScore > 0, "🟠 Weak",
    "🔴 Not Started")
| project ControlName, Status, CurrentScore, MaxScore, PercentageDisplay,
    HealthyResources, UnhealthyResources, 
    TotalResources = HealthyResources + UnhealthyResources + NotApplicableResources
| order by PercentageDisplay asc
```

---

## Query 6 — Control Score Trends Over Time

**Purpose:** Track how individual control areas have improved. "We went from 20% to 85% on 'Manage access and permissions'."

```kql
// Per-control score trends over time
let lookback = 90d;
SecureScoreControls
| where TimeGenerated > ago(lookback)
| where IsSnapshot == false
| where Weight > 0
| summarize arg_max(TimeGenerated, CurrentScore, MaxScore, PercentageScore) 
    by ControlName, Week = startofweek(TimeGenerated)
| extend PercentageDisplay = round(PercentageScore * 100, 1)
| project Week, ControlName, CurrentScore, MaxScore, PercentageDisplay
| order by ControlName asc, Week asc
```

**Visualization:** Line chart per ControlName, or pivot table with controls as rows and weeks as columns.

---

## Query 7 — Remediated Recommendations (What We Fixed)

**Purpose:** The key leadership artifact — "Here are the specific security recommendations we remediated."  
Tracks recommendations that transitioned from Unhealthy to Healthy.

```kql
// Recommendations that were remediated (Unhealthy → Healthy)
// Shows what the team actually FIXED to increase the score
let lookback = 90d;
let unhealthy = SecurityRecommendation
| where TimeGenerated > ago(lookback)
| where RecommendationState == "Unhealthy"
| summarize FirstUnhealthy = min(TimeGenerated) by RecommendationDisplayName, AssessedResourceId;
let healthy = SecurityRecommendation
| where TimeGenerated > ago(lookback)
| where RecommendationState == "Healthy"
| summarize LatestHealthy = max(TimeGenerated), Severity = any(RecommendationSeverity)
    by RecommendationDisplayName, AssessedResourceId;
unhealthy
| join kind=inner healthy on RecommendationDisplayName, AssessedResourceId
| where LatestHealthy > FirstUnhealthy  // Was unhealthy, then became healthy
| summarize 
    ResourcesRemediated = dcount(AssessedResourceId),
    EarliestRemediation = min(LatestHealthy),
    LatestRemediation = max(LatestHealthy),
    Severity = any(Severity)
    by RecommendationDisplayName
| order by ResourcesRemediated desc
```

---

## Query 8 — Remaining Unhealthy Recommendations (Backlog)

**Purpose:** Show leadership what's still outstanding. Prioritized by severity and resource count.

```kql
// Current unhealthy recommendations — prioritized backlog for leadership
// Note: Uses 7d window to ensure data availability (export may not run daily)
SecurityRecommendation
| where TimeGenerated > ago(7d)
| where RecommendationState == "Unhealthy"
| summarize 
    AffectedResources = dcount(AssessedResourceId),
    LatestSeen = max(TimeGenerated)
    by RecommendationDisplayName, RecommendationSeverity
| extend SeverityOrder = case(
    RecommendationSeverity == "High", 1,
    RecommendationSeverity == "Medium", 2,
    RecommendationSeverity == "Low", 3, 4)
| order by SeverityOrder asc, AffectedResources desc
| project RecommendationDisplayName, RecommendationSeverity, AffectedResources, LatestSeen
```

---

## Query 9 — Recommendations Remediated by Severity (Impact Summary)

**Purpose:** "We fixed X High, Y Medium, Z Low recommendations." Quick executive summary.

```kql
// Count of remediated recommendations grouped by severity
let lookback = 90d;
let remediated = SecurityRecommendation
| where TimeGenerated > ago(lookback)
| where RecommendationState == "Healthy"
| summarize LatestHealthy = max(TimeGenerated), Severity = any(RecommendationSeverity) 
    by RecommendationDisplayName, AssessedResourceId
| join kind=inner (
    SecurityRecommendation
    | where TimeGenerated > ago(lookback)
    | where RecommendationState == "Unhealthy"
    | summarize FirstUnhealthy = min(TimeGenerated) by RecommendationDisplayName, AssessedResourceId
) on RecommendationDisplayName, AssessedResourceId
| where LatestHealthy > FirstUnhealthy;
remediated
| summarize 
    UniqueRecommendations = dcount(RecommendationDisplayName),
    ResourcesRemediated = count()
    by Severity
| extend SeverityOrder = case(Severity == "High", 1, Severity == "Medium", 2, Severity == "Low", 3, 4)
| order by SeverityOrder asc
| project Severity, UniqueRecommendations, ResourcesRemediated
```

---

## Query 10 — Resource Health Improvement Over Time

**Purpose:** Track how the total healthy vs unhealthy resource count shifted. Shows remediation velocity.

```kql
// Healthy vs Unhealthy resource counts across all controls over time
let lookback = 90d;
SecureScoreControls
| where TimeGenerated > ago(lookback)
| where IsSnapshot == false
| where Weight > 0
| summarize 
    TotalHealthy = sum(HealthyResources), 
    TotalUnhealthy = sum(UnhealthyResources),
    TotalNA = sum(NotApplicableResources)
    by Day = startofday(TimeGenerated)
| extend HealthPercentage = round(todouble(TotalHealthy) / (TotalHealthy + TotalUnhealthy) * 100, 1)
| project Day, TotalHealthy, TotalUnhealthy, HealthPercentage
| order by Day asc
```

**Visualization:** Stacked bar chart (Healthy vs Unhealthy) with HealthPercentage as a trend line overlay.

---

## Query 11 — Top Score Impact Opportunities (What to Fix Next)

**Purpose:** Identify which unhealthy recommendations would yield the most score improvement if remediated. Helps prioritize upcoming work for leadership.

```kql
// Top opportunities — controls with the biggest score gap to close
// Shows which control areas would yield the most score improvement if remediated
SecureScoreControls
| where IsSnapshot == false
| summarize arg_max(TimeGenerated, *) by ControlName
| where MaxScore > CurrentScore  // Controls with room to improve
| extend ControlGap = round(MaxScore - CurrentScore, 2),
    PercentAchieved = round(iff(MaxScore > 0, CurrentScore * 100.0 / MaxScore, 0.0), 1)
| project ControlName, ControlGap, CurrentScore, MaxScore, PercentAchieved,
    UnhealthyResources, Weight
| order by ControlGap desc
```

---

## Query 12 — Monthly Executive Summary Report

**Purpose:** One-query monthly roll-up combining score change, control improvements, and remediation count. Designed for a single leadership slide.

> **Compatibility note:** Uses `top 1` instead of `arg_min`/`arg_max` in `let` blocks for Advanced Hunting compatibility. Uses `ago(90d)` to find the earliest/latest records robustly (handles sparse data or delayed export start).

```kql
// Monthly executive summary — score start/end + controls improved + recs remediated
let lookback = 90d;
let scores = SecureScores
| where TimeGenerated > ago(lookback)
| where DisplayName == "ASC score"
| where IsSnapshot == false;
let scoreStart = scores | top 1 by TimeGenerated asc
| project StartTime = TimeGenerated, StartScore = CurrentScore, StartMax = MaxScore,
    StartPct = round(PercentageScore * 100, 1);
let scoreEnd = scores | top 1 by TimeGenerated desc
| project EndTime = TimeGenerated, EndScore = CurrentScore, EndMax = MaxScore,
    EndPct = round(PercentageScore * 100, 1);
// Controls that improved (compare first-half vs second-half of data range)
let controlsImproved = SecureScoreControls
| where TimeGenerated > ago(lookback)
| where IsSnapshot == false
| where Weight > 0
| summarize EarlyScore = minif(CurrentScore, TimeGenerated < ago(14d)),
            LateScore = maxif(CurrentScore, TimeGenerated > ago(14d))
    by ControlName
| where LateScore > EarlyScore
| summarize ControlsImproved = count();
// Recs remediated (Unhealthy → Healthy transitions)
let recsRemediated = SecurityRecommendation
| where TimeGenerated > ago(lookback)
| where RecommendationState == "Healthy"
| join kind=inner (
    SecurityRecommendation
    | where TimeGenerated > ago(lookback)
    | where RecommendationState == "Unhealthy"
    | summarize FirstUnhealthy = min(TimeGenerated) by RecommendationDisplayName, AssessedResourceId
) on RecommendationDisplayName, AssessedResourceId
| where TimeGenerated > FirstUnhealthy
| summarize RecsRemediated = dcount(strcat(RecommendationDisplayName, AssessedResourceId));
// Combine all metrics into a single row
scoreStart | extend dummy = 1
| join kind=inner (scoreEnd | extend dummy = 1) on dummy
| join kind=inner (controlsImproved | extend dummy = 1) on dummy
| join kind=inner (recsRemediated | extend dummy = 1) on dummy
| project StartTime, StartScore, StartMax, StartPct,
    EndTime, EndScore, EndMax, EndPct,
    ScoreChange = round(EndScore - StartScore, 2),
    PctChange = round(EndPct - StartPct, 1),
    ControlsImproved, RecsRemediated
```

> **Tuning:** Adjust the `lookback` period to match your reporting window. The query uses `top 1 asc/desc` to find the earliest and latest data points within the range, so it works even if data doesn't start on an exact date boundary.

---

## Tips for Leadership Presentations

### Narrative Arc
1. **Where we started** (Query 2 — period start score)
2. **What we did** (Query 7 — remediated recommendations)
3. **Where we are now** (Query 2 — period end score, Query 5 — control scorecard)
4. **What's next** (Query 8 — remaining backlog, Query 11 — top opportunities)

### Key Metrics for Executive Slides
| Metric | Source Query | Example |
|--------|-------------|---------|
| Score improvement (%) | Query 2 | "36% → 54% (+18 points)" |
| Recommendations fixed | Query 9 | "12 High, 8 Medium, 15 Low" |
| Resources remediated | Query 7 | "47 resources across 12 recommendations" |
| Top control improved | Query 6 | "'Manage access and permissions' → 100%" |
| Remaining backlog | Query 8 | "23 High-severity recommendations outstanding" |

### Caveats to Communicate
- **Score percentage can drop** even when remediating — if Microsoft adds new recommendations or new resources come into scope, `MaxScore` increases and `PercentageScore` drops. Always show `CurrentScore` (absolute points) alongside percentage.
- **Snapshots are weekly** — there's a 1-week delay before first snapshot appears. Streaming updates are near-real-time but only fire on state changes.
- **"Not Applicable" resources** are excluded from score calculation — they don't count as unhealthy.

---

## References

- [Secure Score in Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls)
- [Set up continuous export](https://learn.microsoft.com/azure/defender-for-cloud/continuous-export)
- [Secure Score Over Time workbook](https://learn.microsoft.com/azure/defender-for-cloud/custom-dashboards-azure-workbooks#secure-score-over-time-workbook)
- [Continuously export secure score for tracking (blog)](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/continuously-export-secure-score-for-over-time-tracking-and-reporting-preview/1922779)
- [SecureScores table schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securescores)
- [SecureScoreControls table schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securescorecontrols)
- [SecurityRecommendation table schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityrecommendation)
