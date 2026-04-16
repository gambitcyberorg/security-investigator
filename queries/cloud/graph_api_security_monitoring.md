# Graph API Security Monitoring — Threat Detection & Abuse Hunting

**Created:** 2026-04-16  
**Platform:** Both  
**Tables:** GraphAPIAuditEvents, MicrosoftGraphActivityLogs  
**Keywords:** Graph API, API abuse, reconnaissance, permission probing, credential addition, role assignment, OAuth consent, bulk enumeration, token theft, C2, mailbox access, data harvesting, throttling, application governance, service principal  
**MITRE:** T1087.003, T1069.003, T1098.001, T1098.003, T1078.004, T1550.001, T1114.002, T1119, T1530, T1071.001, T1059.009, TA0007, TA0003, TA0006, TA0009, TA0010  
**Domains:** admin, cloud, spn, identity  
**Timeframe:** Last 7–30 days (configurable)

---
## Overview

Microsoft Graph API is the unified REST API for all of Microsoft 365. Every authenticated request — reading mailboxes, enumerating users, modifying roles, accessing files — flows through `graph.microsoft.com`. Adversaries increasingly abuse Graph API for:

- **Reconnaissance** — Bulk enumeration of users, groups, roles, service principals (T1087.003, T1069.003)
- **Persistence** — Adding credentials to apps/SPNs, granting OAuth consent, assigning roles (T1098.001, T1098.003)
- **C2 channels** — Using OneDrive/SharePoint/Outlook drafts as covert communication (T1071.001)
- **Data exfiltration** — Accessing mailboxes, downloading files via drive/sites APIs (T1114.002, T1530)
- **Token theft** — Replaying stolen access tokens from multiple IPs (T1550.001)

**Table Selection**

| Table | Platform | Retention | Key Differences |
|-------|----------|-----------|-----------------|
| `GraphAPIAuditEvents` | Advanced Hunting | 30 days | `Timestamp`, `TargetWorkload`, `EntityType`. AH-only, free for Analytics tier |
| `MicrosoftGraphActivityLogs` | Data Lake / Azure Monitor | 90+ days | `TimeGenerated`, `Scopes`, `Roles`, `SessionId`, `UniqueTokenId`, `DurationMs`, `DeviceId`. Richer token/session metadata |

**Decision rule:** Use `GraphAPIAuditEvents` (AH) for ≤30d threat hunting. Use `MicrosoftGraphActivityLogs` (Data Lake) for >30d investigations or when you need token/session/scope correlation.

**URI Normalization Pattern**

All queries in this file normalize Graph API URIs by replacing GUIDs with `{id}` to enable aggregation across entities:

```kql
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
```

### ⚠️ Table Pitfalls

| Pitfall | Detail |
|---------|--------|
| `ResponseStatusCode` is **string** in `GraphAPIAuditEvents` | Use `toint(ResponseStatusCode)` for numeric comparisons or `== "403"` for string matching |
| `AccountObjectId` not `UserId` | AH table uses `AccountObjectId`; Data Lake uses `UserId`. Do not mix |
| `ApplicationId` not `AppId` | AH uses `ApplicationId`; Data Lake uses `AppId`. Always verify column name before switching platforms |
| `OAuthAppInfo` uses `OAuthAppId`, NOT `ApplicationId` | Join on `OAuthAppId` when cross-referencing with `GraphAPIAuditEvents.ApplicationId`. `OAuthAppInfo` has NO `ApplicationId` column — using it returns `Failed to resolve column`. Other key columns: `AppName`, `PrivilegeLevel`, `Permissions`, `AppOrigin`, `AppStatus` |
| `CloudAppEvents.ApplicationId` is `int`, NOT `string` | Cannot use string GUID arrays with `in` operator — returns SEM0025 type mismatch. `CloudAppEvents` uses a Defender-internal integer AppId, not the Entra GUID. To resolve app names from string GUIDs, use `SigninLogs` or `AADNonInteractiveUserSignInLogs` (which have `AppId` as string + `AppDisplayName`) |
| **Aggregation without `ApplicationId` conflates actors** | When summarizing mutation or error data by `OperationType`, `RequestMethod`, or `NormalizedPath` alone, different apps get merged into the same row — leading to misattribution (e.g., attributing App B's failures to App A because App A dominates the result set). **Always include `ApplicationId` (and `AccountObjectId` when applicable) in `summarize ... by` clauses** for any query used to attribute activity to a specific actor |
| `Scopes` not available in AH | `Scopes`, `Roles`, `SessionId`, `UniqueTokenId`, `DurationMs` are **Data Lake only** columns |
| `TargetWorkload` is AH-only | Not available in `MicrosoftGraphActivityLogs` |

### Known High-Volume Applications (False Positive Guidance)

When investigating Graph API traffic, these Microsoft first-party applications generate extremely high volumes as part of normal operations. Recognizing them prevents false-positive investigations:

| AppId | App Name | Typical Behavior | Expected Volume | Affected Queries |
|-------|----------|-------------------|-----------------|-----------------|
| `05a65629-4c1b-48c1-a78b-804c4abdd4af` | **Microsoft Cloud App Security** (App Governance) | Continuously inventories **all** service principal permissions by calling `/servicePrincipals/{id}/appRoleAssignedTo` and `/servicePrincipals/{id}/oauth2PermissionGrants` for every SPN in the tenant. This is the App Governance feature performing its permission posture scan. | Millions of GET requests per week, scanning 50K+ SPNs. Dominates endpoint volume dashboards — often the top 2 endpoints by request count. | Q1 (dominates top endpoints), Q5 (bulk GET on ServicePrincipals), Q7 (app-only SPN access), Q10/Q11 (volume anomaly baseline) |
| `01fc33a7-78ba-4d2f-a4b7-768e336e890e` | **MS-PIM** | Time-bounded role assignment lifecycle — creates and deletes `roleAssignments` on a schedule as PIM-eligible roles activate and expire. | Tens of role assignment POST + DELETE per day, all successful. IPs are Azure infrastructure. Empty `AccountObjectId` (backend service). | Q3 (role assignment mutations), Q6 (mutating operations) |
| `810dcf14-1858-4bf2-8134-4c369fa3235b` | **Azure AD Identity Governance – Entitlement Management** | Reads org info, subscribedSkus, role assignments, and tenant relationships for access package management. App-only tokens only (no user context). May also call `roleEligibilityScheduleRequests` — 404 errors indicate stale references to deleted users or expired eligibility schedules, not a security concern. | Low volume per SPN but appears across many `ServicePrincipalId` values (one per managed identity). High error rates (100%) are common — operational, not security. | Q7 (SPN app-only), Q2 (if 404s appear as errors) |

> **Filtering guidance:** Do NOT hardcode these AppIds into query exclusions. Instead, use this table to **contextualize results** during analysis — knowing that MCAS at the top of Q1 is expected lets you focus on the unexpected entries below it.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Endpoint Volume & Error Rate Dashboard](#query-1-endpoint-volume--error-rate-dashboard) | Dashboard | `GraphAPIAuditEvents` |
| 2 | [Permission Probing — 403 Forbidden Analysis](#query-2-permission-probing--403-forbidden-analysis) | Investigation | `GraphAPIAuditEvents` |
| 3 | [Credential & Role Mutation via Graph API](#query-3-credential--role-mutation-via-graph-api) | Investigation | `GraphAPIAuditEvents` |
| 4 | [Graph API C2 Indicators — Mail, Drive & Teams Abuse](#query-4-graph-api-c2-indicators--mail-drive--teams-abuse) | Investigation | `GraphAPIAuditEvents` |
| 5 | [Bulk Data Harvesting — High-Volume GET by Category](#query-5-bulk-data-harvesting--high-volume-get-by-category) | Dashboard | `GraphAPIAuditEvents` |
| 6 | [Mutating Operations — POST/PATCH/PUT/DELETE Classification](#query-6-mutating-operations--postpatchputdelete-classification) | Investigation | `GraphAPIAuditEvents` |
| 7 | [Service Principal App-Only Access (Client Credentials Flow)](#query-7-service-principal-app-only-access-client-credentials-flow) | Investigation | `GraphAPIAuditEvents` |
| 8 | [New Application First Seen — Baseline Deviation](#query-8-new-application-first-seen--baseline-deviation) | Dashboard | `GraphAPIAuditEvents` |
| 9 | [Token Replay Detection — Same Token from Multiple IPs](#query-9-token-replay-detection--same-token-from-multiple-ips) | Detection | `MicrosoftGraphActivityLogs` |
| 10 | [Traffic Volume Anomaly Detection (Time Series)](#query-10-traffic-volume-anomaly-detection-time-series) | Dashboard | `AnomalyScore` + `GraphAPIAuditEvents` |
| 11 | [Per-App Volume Anomaly — Z-Score Deviation](#query-11-per-app-volume-anomaly--z-score-deviation) | Dashboard | `GraphAPIAuditEvents` |
| 12 | [Sensitive Workload Access Heatmap](#query-12-sensitive-workload-access-heatmap) | Investigation | `GraphAPIAuditEvents` |
| 13 | [Throttled Applications — Rate Limit Abuse](#query-13-throttled-applications--rate-limit-abuse) | Investigation | `GraphAPIAuditEvents` |
| 14 | [Scope Utilization Inventory (Data Lake)](#query-14-scope-utilization-inventory-data-lake) | Posture | `MicrosoftGraphActivityLogs` |


## Queries

### Query 1: Endpoint Volume & Error Rate Dashboard

**Purpose:** Establish a comprehensive baseline of all Graph API endpoints, their request volumes, error rates, and consumer breadth. Use for initial exploration and identifying unusual endpoint concentrations.  
**Severity:** Informational  
**MITRE:** TA0007  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical baseline — requires summarize with dcount/count aggregation, not suitable for CD"
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(7d)
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
| extend NormalizedPath = replace_regex(NormalizedPath, @"'[^']*'", "'{value}'")
| extend StatusCode = toint(ResponseStatusCode)
| extend IsSuccess = StatusCode >= 200 and StatusCode < 300
| extend IsClientError = StatusCode >= 400 and StatusCode < 500
| extend IsServerError = StatusCode >= 500
| summarize 
    TotalRequests = count(),
    SuccessCount = countif(IsSuccess),
    ClientErrors = countif(IsClientError),
    ServerErrors = countif(IsServerError),
    UniqueApps = dcount(ApplicationId),
    UniqueUsers = dcount(AccountObjectId)
    by NormalizedPath, RequestMethod
| extend ErrorRate = round(todouble(ClientErrors + ServerErrors) / TotalRequests * 100, 1)
| sort by TotalRequests desc
| take 50
```

**Expected results:** Top 50 Graph API endpoints ranked by volume. High `ErrorRate` (>10%) on sensitive endpoints warrants investigation — may indicate permission probing or misconfigured automation.

**Tuning:** Adjust `ago(7d)` for broader/narrower baseline. Filter to specific `RequestMethod` for focused analysis.

---

### Query 2: Permission Probing — 403 Forbidden Analysis

**Purpose:** Detect entities systematically probing Graph API endpoints they lack permissions for. High 403 counts from a single app/user across diverse endpoints signal reconnaissance or compromised token testing.  
**Severity:** Medium  
**MITRE:** T1087.003, T1069.003, TA0007  

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Discovery"
title: "Graph API Permission Probing — {{AccountObjectId}}"
impactedAssets:
  - type: user
    identifier: accountObjectId
recommendedActions: "Investigate the app and user generating 403 errors. Check if this is expected automation or credential/token abuse. Review the target endpoints to assess what the actor was trying to access."
adaptation_notes: "Change to row-level output with arg_max, add ReportId"
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(1h)
| where ResponseStatusCode == "403"
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
| summarize 
    AttemptCount = count(),
    DistinctPaths = dcount(NormalizedPath),
    Paths = make_set(NormalizedPath, 10),
    Methods = make_set(RequestMethod)
    by ApplicationId, AccountObjectId, IpAddress
| where AttemptCount >= 10 and DistinctPaths >= 3
| sort by AttemptCount desc
```

**Expected results:** Entities with 10+ forbidden requests across 3+ distinct endpoints. Legitimate automation typically fails on a single endpoint consistently — diverse failures suggest systematic probing.

**Tuning:** Raise `AttemptCount >= 10` threshold in high-volume environments. Lower `DistinctPaths >= 3` to catch focused probing on a single sensitive resource type.

---

### Query 3: Credential & Role Mutation via Graph API

**Purpose:** Detect high-fidelity persistence operations: credential additions to apps/SPNs, role assignments, PIM activations, and OAuth consent grants made directly via Graph API. These are the most critical Graph API-based persistence techniques.  
**Severity:** High  
**MITRE:** T1098.001, T1098.003, TA0003  

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Graph API Credential/Role Mutation: {{OperationType}} by {{AccountObjectId}}"
impactedAssets:
  - type: user
    identifier: accountObjectId
recommendedActions: "Verify the credential addition, role assignment, or consent grant was authorized. Check AuditLogs for corroborating entries. For credential additions, verify the target app registration ownership and whether the credential was expected."
adaptation_notes: "Already row-level output with project. Add ReportId column."
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(1h)
| where RequestUri has_any (
    "/addPassword", "/addKey", "/removePassword", "/removeKey",
    "/federatedIdentityCredentials",
    "/roleAssignments", "/roleEligibilityScheduleRequests",
    "/oauth2PermissionGrants",
    "/appRoleAssignments"
)
| where RequestMethod in ("POST", "PATCH", "DELETE")
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
| extend StatusCode = toint(ResponseStatusCode)
| extend OperationType = case(
    NormalizedPath has "addPassword" or NormalizedPath has "addKey", "Credential Added",
    NormalizedPath has "removePassword" or NormalizedPath has "removeKey", "Credential Removed",
    NormalizedPath has "federatedIdentityCredentials", "Federated Credential",
    NormalizedPath has "roleAssignments", "Role Assignment",
    NormalizedPath has "roleEligibilityScheduleRequests", "PIM Eligibility",
    NormalizedPath has "oauth2PermissionGrants", "OAuth Consent",
    NormalizedPath has "appRoleAssignments", "App Role Assignment",
    "Other"
)
| project Timestamp, OperationType, RequestMethod, StatusCode, NormalizedPath, ApplicationId, AccountObjectId, ServicePrincipalId, IpAddress, ReportId
| sort by Timestamp desc
```

**Expected results:** Each row is a credential/role mutation event. Cross-reference with `AuditLogs` for additional detail. Credential additions from unexpected apps or IPs are high-confidence persistence indicators.

**Tuning:** Extend lookback for investigation: `ago(7d)`. Filter `| where StatusCode >= 200 and StatusCode < 300` to focus on successful mutations only.

---

### Query 4: Graph API C2 Indicators — Mail, Drive & Teams Abuse

**Purpose:** Detect Graph API access patterns consistent with command-and-control channels: mailbox reading/sending, OneDrive/SharePoint file operations, and Teams message manipulation. Prioritizes mutating operations (POST/PATCH/PUT/DELETE) and app-only (no user) mailbox access.  
**Severity:** High  
**MITRE:** T1071.001, T1114.002, T1530, TA0011  

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Graph API C2 Pattern: {{NormalizedPath}} by App {{ApplicationId}}"
impactedAssets:
  - type: user
    identifier: accountObjectId
recommendedActions: "Investigate the application making mail/drive/Teams API calls. For service principal (app-only) access, check if the app has Mail.Read/Send application permissions and whether the access pattern is expected. Draft email manipulation (POST to /messages in drafts) is a known C2 technique (FINALDRAFT, AzureOutlookC2)."
adaptation_notes: "Already row-level. Add ReportId. Remove summarize for CD variant."
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(1h)
| where RequestUri has_any (
    "/messages", "/sendMail", "/mailFolders", "/drafts",
    "/drive/root", "/drive/items", "/sites/",
    "/chats/", "/channels/", "/teams/"
)
| where RequestMethod in ("POST", "PATCH", "PUT", "DELETE")
    or (RequestMethod == "GET" and RequestUri has_any ("/messages", "/mailFolders"))
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
| extend IsAppOnly = isnotempty(ServicePrincipalId) and isempty(AccountObjectId)
| project Timestamp, RequestMethod, NormalizedPath, ApplicationId, AccountObjectId, ServicePrincipalId, IsAppOnly, IpAddress, ResponseStatusCode, ReportId
| sort by Timestamp desc
```

**Expected results:** Mail/Drive/Teams API operations. App-only (`IsAppOnly == true`) mailbox access is highest risk — legitimate interactive users accessing their own mail is expected, but service principals reading arbitrary mailboxes is not. Focus on:
- `POST` to `/sendMail` — email impersonation
- `POST`/`PATCH` to `/drafts/messages` — draft-based C2
- `GET` on `/messages` with app-only token — bulk mailbox harvesting

**Tuning:** For investigation scope, extend to `ago(7d)` and add `| summarize Count=count() by NormalizedPath, ApplicationId, IsAppOnly | sort by Count desc`.

---

### Query 5: Bulk Data Harvesting — High-Volume GET by Category

**Purpose:** Identify applications and users performing bulk data extraction via GET requests. Categorizes endpoints into security-relevant domains (Users, Roles, Mail, Files, etc.) to highlight data harvesting patterns.  
**Severity:** Medium  
**MITRE:** T1087.003, T1069.003, T1119, TA0009  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical aggregation with threshold filtering — requires summarize with count/dcount, not CD-compatible"
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(7d)
| where RequestMethod == "GET"
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
| extend ApiCategory = case(
    NormalizedPath has "/users", "Users",
    NormalizedPath has "/groups", "Groups",
    NormalizedPath has_any ("/directoryRoles", "/roleManagement"), "Roles",
    NormalizedPath has "/servicePrincipals", "ServicePrincipals",
    NormalizedPath has "/applications", "Applications",
    NormalizedPath has_any ("/messages", "/mailFolders"), "Mail",
    NormalizedPath has_any ("/drive", "/sites"), "Files",
    NormalizedPath has "/subscribedSkus", "Licensing",
    NormalizedPath has "/organization", "Organization",
    "Other"
)
| summarize 
    TotalGets = count(),
    DistinctEndpoints = dcount(NormalizedPath),
    ResponseBytes = sum(ResponseSize),
    DistinctIPs = dcount(IpAddress)
    by ApplicationId, AccountObjectId, ApiCategory
| where TotalGets > 100
| sort by TotalGets desc
| take 50
```

**Expected results:** Apps/users with high GET volumes by category. Unusual patterns: a single app reading thousands of user records, roles, or mailbox items. Cross-reference with Q7 (service principal audit) to check if app-only tokens are involved.

**Tuning:** Adjust `TotalGets > 100` threshold. Focus on specific `ApiCategory` values: `"Roles"`, `"Mail"`, and `"Users"` are highest risk for attacker reconnaissance.

---

### Query 6: Mutating Operations — POST/PATCH/PUT/DELETE Classification

**Purpose:** Comprehensive view of all write/modify/delete operations classified by mutation category. Shows the attack surface of directory modifications flowing through Graph API.  
**Severity:** Medium  
**MITRE:** T1098, T1136.003, TA0003  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query classifying mutation types — use Q3 for CD-ready credential/role detection"
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(7d)
| where RequestMethod in ("POST", "PATCH", "PUT", "DELETE")
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
| extend StatusCode = toint(ResponseStatusCode)
| extend MutationCategory = case(
    NormalizedPath has_any ("/applications", "/servicePrincipals") and NormalizedPath has_any ("/addPassword", "/addKey", "/federatedIdentityCredentials"), "Credential Addition",
    NormalizedPath has_any ("/roleAssignments", "/roleEligibilityScheduleRequests"), "Role Assignment",
    NormalizedPath has "/oauth2PermissionGrants", "Consent Grant",
    NormalizedPath has_any ("/members", "/owners") and RequestMethod == "POST", "Membership Change",
    NormalizedPath has "/conditionalAccess", "CA Policy Change",
    NormalizedPath has_any ("/sendMail", "/messages") and RequestMethod == "POST", "Mail Send",
    NormalizedPath has "/invitations", "Guest Invitation",
    NormalizedPath has_any ("/applications", "/servicePrincipals"), "App/SPN Modification",
    NormalizedPath has "/groups", "Group Modification",
    NormalizedPath has "/users", "User Modification",
    NormalizedPath has "/policies", "Policy Modification",
    "Other Mutation"
)
| summarize 
    Count = count(),
    SuccessCount = countif(StatusCode >= 200 and StatusCode < 300),
    FailedCount = countif(StatusCode >= 400),
    Endpoints = make_set(NormalizedPath, 5)
    by MutationCategory, ApplicationId, AccountObjectId, RequestMethod
| sort by Count desc
| take 50
```

**Expected results:** Classification of all write operations. Priority focus: `Credential Addition`, `Role Assignment`, `Consent Grant`, `CA Policy Change`, `Mail Send`. Use to build a change-management baseline and detect unexpected categories.

---

### Query 7: Service Principal App-Only Access (Client Credentials Flow)

**Purpose:** Identify service principals (app-only tokens, no user context) making Graph API calls. Client credentials flow is the highest-risk OAuth flow — tokens are indistinguishable from legitimate application traffic and bypass MFA. Map out which apps operate without user context.  
**Severity:** Medium  
**MITRE:** T1078.004, T1550.001, TA0003  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Inventory/posture query — requires aggregation. Use for baseline, not alerting."
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(7d)
| where isnotempty(ServicePrincipalId) and isempty(AccountObjectId)
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend NormalizedPath = replace_regex(UriPath, @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}")
| extend StatusCode = toint(ResponseStatusCode)
| summarize 
    TotalRequests = count(),
    DistinctEndpoints = dcount(NormalizedPath),
    TopPaths = make_set(NormalizedPath, 10),
    ErrorCount = countif(StatusCode >= 400),
    UniqueIPs = dcount(IpAddress),
    IPs = make_set(IpAddress, 5),
    Methods = make_set(RequestMethod)
    by ApplicationId, ServicePrincipalId
| sort by TotalRequests desc
| take 30
```

**Expected results:** All service principals operating with app-only tokens. Review each for:
- Do the `TopPaths` match the app's expected function?
- Are `IPs` from expected infrastructure (Azure, corporate)?
- Are there unexpected `Methods` (POST/DELETE on sensitive endpoints)?
- Cross-reference `ApplicationId` with `OAuthAppInfo` using `OAuthAppInfo.OAuthAppId` (NOT `ApplicationId` — column doesn't exist on `OAuthAppInfo`). Check `PrivilegeLevel`, `Permissions`, and `AppOrigin`.

---

### Query 8: New Application First Seen — Baseline Deviation

**Purpose:** Detect applications accessing Graph API for the first time in the recent window that were NOT seen in the prior baseline period. New apps may indicate compromised credentials, consent phishing grants, or shadow IT.  
**Severity:** Medium  
**MITRE:** T1078.004, T1098.003, TA0001  

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "InitialAccess"
title: "New Graph API Application Detected: {{ApplicationId}}"
impactedAssets:
  - type: user
    identifier: accountObjectId
recommendedActions: "Verify the new application is authorized. Check Entra ID app registrations for the ApplicationId, review consent grants, and confirm the app owner. If unknown, investigate as potential consent phishing or unauthorized automation."
adaptation_notes: "Refactor let-block baseline into subquery join. AH 30d limit constrains baseline to 21d+7d window."
-->

```kql
let Baseline = GraphAPIAuditEvents
| where Timestamp between (ago(28d) .. ago(7d))
| distinct ApplicationId;
GraphAPIAuditEvents
| where Timestamp > ago(7d)
| distinct ApplicationId
| join kind=leftanti Baseline on ApplicationId
| join kind=inner (
    GraphAPIAuditEvents
    | where Timestamp > ago(7d)
    | summarize 
        FirstSeen = min(Timestamp),
        RequestCount = count(),
        Methods = make_set(RequestMethod),
        UniqueUsers = dcount(AccountObjectId),
        UniqueIPs = dcount(IpAddress),
        TopEndpoints = make_set(tostring(split(RequestUri, "?")[0]), 5),
        Errors = countif(toint(ResponseStatusCode) >= 400)
        by ApplicationId
) on ApplicationId
| project ApplicationId, FirstSeen, RequestCount, Methods, UniqueUsers, UniqueIPs, Errors, TopEndpoints
| sort by RequestCount desc
```

**Expected results:** Applications seen in the last 7 days that were NOT present in the prior 21-day baseline. High-volume new apps or apps accessing sensitive endpoints (roles, mail, drive) are highest priority.

**Tuning:** AH 30-day retention constrains the baseline. For longer baselines, use `MicrosoftGraphActivityLogs` in Data Lake with 90-day lookback.

---

### Query 9: Token Replay Detection — Same Token from Multiple IPs

**Purpose:** Detect tokens used from multiple IP addresses, which may indicate token theft/replay. A legitimate token should typically originate from a single IP or a small set of known corporate egress IPs.  
**Severity:** High  
**MITRE:** T1550.001, T1539, TA0006  

**⚠️ Data Lake only** — `UniqueTokenIdentifier` is not available on `GraphAPIAuditEvents`.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Graph API Token Replay: Token used from {{DistinctIPs}} IPs by {{UserId}}"
impactedAssets:
  - type: user
    identifier: accountUpn
recommendedActions: "Investigate the user's sign-in logs for the token's originating session. Check if the IPs are from VPN/proxy rotation (expected) or geographically distant locations (token theft). Correlate with AADUserRiskEvents for concurrent risk detections. Consider revoking the user's refresh tokens."
adaptation_notes: "Data Lake table — not available in AH. Requires MicrosoftGraphActivityLogs custom detection or Sentinel analytic rule instead."
-->

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1h)
| where isnotempty(UniqueTokenId) and isnotempty(IPAddress)
| summarize 
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    RequestCount = count(),
    DistinctEndpoints = dcount(tostring(split(RequestUri, "?")[0])),
    TimeSpan = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated))
    by UniqueTokenId, AppId, UserId
| where DistinctIPs > 1
| sort by DistinctIPs desc
| take 20
```

**Expected results:** Tokens used from 2+ distinct IPs. Cross-reference with sign-in logs (`SigninLogs` join on `UniqueTokenIdentifier`) to determine if the IPs correspond to VPN egress rotation (benign) or geographically impossible travel (token theft).

**Tuning:** Exclude known corporate egress IPs: `| where not(IPAddress has_any ("10.", "172.16.", "192.168."))` before summarize. Raise threshold to `DistinctIPs > 2` in VPN-heavy environments.

---

### Query 10: Traffic Volume Anomaly Detection (Time Series)

**Purpose:** Apply `series_decompose_anomalies()` to detect statistically significant spikes or drops in overall Graph API traffic. Catches botnet-scale enumeration, DDoS, or sudden automation failures.  
**Severity:** Informational  
**MITRE:** TA0007, T1119  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Time series analysis with make-series/mv-expand — not compatible with CD row-level requirement"
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(14d)
| summarize RequestCount = count() by bin(Timestamp, 1h)
| make-series Requests = sum(RequestCount) default=0 on Timestamp from ago(14d) to now() step 1h
| extend (AnomalyFlags, AnomalyScore, ExpectedBaseline) = series_decompose_anomalies(Requests, 1.5, -1, 'linefit')
| mv-expand Timestamp to typeof(datetime), Requests to typeof(long), AnomalyFlags to typeof(int), AnomalyScore to typeof(double), ExpectedBaseline to typeof(double)
| where AnomalyFlags != 0
| project Timestamp, Requests, ExpectedBaseline = round(ExpectedBaseline, 0), AnomalyScore = round(AnomalyScore, 2), Direction = iff(AnomalyFlags > 0, "Spike", "Drop")
| sort by abs(AnomalyScore) desc
| take 20
```

**Expected results:** Hourly time slots with anomalous traffic volumes. `AnomalyScore` > 2.0 indicates strong statistical outliers. Spikes may indicate bulk enumeration; drops may indicate blocked automation or revoked credentials.

**Tuning:** Adjust `1.5` sensitivity threshold — lower values (1.0) catch more anomalies, higher values (2.0+) reduce noise. Change step from `1h` to `15m` for finer granularity.

---

### Query 11: Per-App Volume Anomaly — Z-Score Deviation

**Purpose:** Detect applications whose last-day request volume deviates significantly from their own historical baseline using Z-score analysis. Each app is compared against itself, catching app-specific anomalies that global traffic analysis misses.  
**Severity:** Medium  
**MITRE:** T1078.004, T1119, TA0007  

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Discovery"
title: "Graph API Volume Anomaly: App {{ApplicationId}} — Z-Score {{ZScore}}"
impactedAssets:
  - type: user
    identifier: accountObjectId
recommendedActions: "Investigate the application's recent API calls. A spike (positive Z-score) may indicate compromised credentials being used for bulk data harvesting. A drop (negative Z-score) may indicate revoked credentials or blocked access. Check the app's sign-in logs and recent permission changes."
adaptation_notes: "Refactor let blocks. Use inline subquery. May need to relax DayCount filter for CD compatibility."
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(21d)
| summarize DailyCount = count() by ApplicationId, Day = bin(Timestamp, 1d)
| summarize 
    AvgDaily = avg(DailyCount), 
    StdDev = stdev(DailyCount), 
    DayCount = count(), 
    MaxDay = max(DailyCount), 
    LastDay = sumif(DailyCount, Day > ago(1d)) 
    by ApplicationId
| where DayCount >= 7 and StdDev > 0
| extend ZScore = round((LastDay - AvgDaily) / StdDev, 2)
| where ZScore > 2 or ZScore < -2
| project ApplicationId, AvgDaily = round(AvgDaily, 0), StdDev = round(StdDev, 0), LastDay, ZScore, Direction = iff(ZScore > 0, "Spike", "Drop")
| sort by abs(ZScore) desc
| take 30
```

**Expected results:** Applications with statistically anomalous daily volumes. Positive Z-scores (spikes) may indicate token compromise being exploited for data harvesting. Negative Z-scores (drops) may indicate credential revocation or service disruption.

**Tuning:** Adjust Z-score threshold (`> 2` / `< -2`) — use `> 3` for high-confidence only. Increase `DayCount >= 14` for more stable baselines.

---

### Query 12: Sensitive Workload Access Heatmap

**Purpose:** Map Graph API traffic to Microsoft backend workloads using the `TargetWorkload` field. Identifies which security-sensitive services are being accessed and by which apps/users.  
**Severity:** Informational  
**MITRE:** TA0007, TA0009  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation dashboard — use for posture awareness, not alerting"
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(7d)
| where TargetWorkload has_any (
    "DirectoryServices", "IdentityProtection", "StrongAuthentication",
    "Exchange", "SecurityDetections", "Defender",
    "FileServices", "SharePoint",
    "ESTS", "CPIM", "PIM",
    "AuthenticationMethodsPolicy", "ConditionalAccess"
)
| extend StatusCode = toint(ResponseStatusCode)
| summarize 
    TotalRequests = count(),
    Errors = countif(StatusCode >= 400),
    UniqueApps = dcount(ApplicationId),
    UniqueUsers = dcount(AccountObjectId),
    Methods = make_set(RequestMethod)
    by TargetWorkload
| extend ErrorRate = round(todouble(Errors) / TotalRequests * 100, 1)
| sort by TotalRequests desc
```

**Expected results:** Security-sensitive workload access volumes. `TargetWorkload` values like `Microsoft.IdentityProtectionServices`, `Microsoft.ESTS` (token service), `Microsoft.PIM.AzureRBAC`, and `Microsoft.Exchange` warrant attention when accessed by unexpected applications or users.

---

### Query 13: Throttled Applications — Rate Limit Abuse

**Purpose:** Identify applications hitting Graph API rate limits (HTTP 429). Excessive throttling may indicate misconfigured automation, brute-force operations, or intentional API abuse.  
**Severity:** Low  
**MITRE:** T1119, TA0009  

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation query with dcount — use for operational monitoring, not CD"
-->

```kql
GraphAPIAuditEvents
| where Timestamp > ago(7d)
| where ResponseStatusCode == "429"
| extend UriPath = tostring(split(RequestUri, "?")[0])
| extend UriSegments = extract_all(@'\/([A-Za-z2]+|\$batch)($|\/|\(|\$)', dynamic([1]), tolower(UriPath))
| extend OperationResource = strcat_array(UriSegments, '/')
| summarize 
    ThrottledCount = count(),
    DistinctEndpoints = dcount(OperationResource),
    Endpoints = make_set(OperationResource, 10),
    Methods = make_set(RequestMethod)
    by ApplicationId, AccountObjectId, ServicePrincipalId
| sort by ThrottledCount desc
| take 20
```

**Expected results:** Apps hitting rate limits. Legitimate high-volume apps (Microsoft portal, provisioning agents) are expected. Unknown apps with high throttle counts may be performing bulk enumeration or data scraping.

---

### Query 14: Scope Utilization Inventory (Data Lake)

**Purpose:** Inventory which Graph API permission scopes are being exercised across all apps and users. Use for permission hygiene — identify overprivileged apps exercising dangerous scopes (Mail.ReadWrite, RoleManagement.ReadWrite.All, etc.).  
**Severity:** Informational  
**MITRE:** T1078.004, TA0003  

**⚠️ Data Lake only** — `Scopes` column is not available on `GraphAPIAuditEvents`.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Data Lake only — Scopes column unavailable in AH. Posture/inventory query, not alerting."
-->

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| where isnotempty(Scopes)
| extend ScopeList = split(Scopes, " ")
| mv-expand Scope = ScopeList to typeof(string)
| where Scope != ""
| summarize 
    UsageCount = count(),
    UniqueApps = dcount(AppId),
    UniqueUsers = dcount(UserId)
    by Scope
| sort by UsageCount desc
| take 50
```

**Expected results:** Permission scopes ranked by usage volume. High-risk scopes to watch: `Mail.ReadWrite`, `Mail.Send`, `RoleManagement.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`, `Files.ReadWrite.All`. Cross-reference with `OAuthAppInfo` (join on `OAuthAppInfo.OAuthAppId` = `AppId`) to identify apps with granted-but-unused high-privilege scopes (over-provisioning).

**Tuning:** Filter to specific dangerous scopes: `| where Scope has_any ("ReadWrite", "FullControl", ".All")` for focused privilege analysis.

---

## References

- [Microsoft Graph Activity Logs Overview — Microsoft Learn](https://learn.microsoft.com/graph/microsoft-graph-activity-logs-overview)
- [Graph API C2 Attack Surface — lolc2](https://github.com/lolc2/lolc2.github.io/blob/main/doc/graphapi.md)
- [Detecting Threats with Graph Activity Logs — Palo Alto](https://www.paloaltonetworks.com/blog/security-operations/detecting-threats-with-microsoft-graph-activity-logs/)
- [Authentication Linkable Identifiers — Microsoft Learn](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-track-linkable-identifiers)
