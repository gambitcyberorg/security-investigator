# App Registration Abuse — Attack Chain Detections

**Created:** 2026-03-30  
**Platform:** Both  
**Tables:** AuditLogs, AADServicePrincipalSignInLogs, AADUserRiskEvents, MicrosoftGraphActivityLogs  
**Keywords:** app registration, service principal, credential abuse, ownership hijack, SolarWinds, persistence, lateral movement, consent grant, secret, certificate, cross-tenant, kill chain  
**MITRE:** T1098.001, T1098.003, T1078.004, T1550.001, T1606.002, T1656, TA0003, TA0004, TA0008  
**Domains:** spn, admin  
**Timeframe:** Last 30 days (configurable)

---

## Overview

These queries detect **multi-step attack chains** targeting Entra ID App Registrations and Service Principals. Each query correlates signals across tables that are individually low-signal but become high-confidence when chained together.

**Attack Pattern (per [Guardz research](https://guardz.com/blog/abusing-entra-id-app-registrations-for-long-term-persistence/) / [SolarWinds](https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/)):**

```
User compromised → discovers app ownership → adds credential (secret/cert) →
disconnects from user session → authenticates AS the app (SPN) →
uses app permissions for lateral movement / data exfiltration / privilege escalation
```

**How this differs from existing queries:**

| Existing Resource | Coverage | Gap |
|-------------------|----------|-----|
| `app_credential_management.md` | Individual credential/ownership/consent events | No cross-table chain correlation |
| `service_principal_scope_drift.md` | SPN behavioral baseline drift | No link to preceding compromise signals |
| App Governance (Microsoft) | Anomalous app behavior, overprivileged apps | No correlation with user risk signals or multi-step chains |

**These chain queries add:** Cross-table correlation that links user compromise → app abuse → SPN activation → lateral movement into a single detection narrative.

**Graph API Posture Queries:** Current app ownership and permission state requires Graph API (AuditLogs only show changes, not current state). Graph API queries are documented in the [Posture Assessment](#posture-assessment-graph-api) section — intended for periodic proactive review, not real-time detection.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Risky User → App Operations Chain (HIGHEST SIGNAL)](#query-1-risky-user--app-operations-chain-highest-signal) | Investigation | `AADUserRiskEvents` + multi |
| 2 | [Credential Add → SPN Activation from New Origin](#query-2-credential-add--spn-activation-from-new-origin) | Investigation | `AADServicePrincipalSignInLogs` + `AuditLogs` |
| 3 | [Ownership Add → Credential Modification Chain](#query-3-ownership-add--credential-modification-chain) | Investigation | `AuditLogs` |
| 4 | [SPN Cross-Tenant Sign-Ins](#query-4-spn-cross-tenant-sign-ins) | Investigation | `AADServicePrincipalSignInLogs` |
| 5 | [Credential Add → SPN Graph API Lateral Movement](#query-5-credential-add--spn-graph-api-lateral-movement) | Investigation | `AuditLogs` + `MicrosoftGraphActivityLogs` |
| 6 | [Credential Add → Permission Escalation Chain](#query-6-credential-add--permission-escalation-chain) | Investigation | `AuditLogs` |
| 7 | [Multi-App Ownership Spread](#query-7-multi-app-ownership-spread) | Investigation | `AuditLogs` |


## ⚠️ Schema Pitfalls — Read Before Modifying

| Pitfall | Details |
|---------|---------|
| **Application ObjectId ≠ ServicePrincipal ObjectId** | The same app has different GUIDs in `TargetResources[0].id` depending on operation type. Credential operations reference the Application ObjectId; permission/consent operations reference the ServicePrincipal ObjectId. Join on `displayName` or `Actor` when correlating across operation types |
| **Ownership operations — target name in modifiedProperties** | For "Add owner to application", `TargetResources[0]` is the new owner (User type). The app name is in `TargetResources[0].modifiedProperties[1].newValue` (field `Application.DisplayName`). `TargetResources[1]` has the Application ObjectId but `displayName` is null |
| **OperationName trailing spaces** | Credential operations have trailing spaces: `"Update application – Certificates and secrets management "` — preserve them in filters |
| **`InitiatedBy` is dynamic** | Always extract with `tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)` |
| **Consent targets structure** | "Consent to application": `Target[0]` = the app receiving consent. "Add delegated permission grant": `Target[0]` = the resource API (e.g., Microsoft Graph), `Target[1]` = the app receiving permission |

---

## Query 1: Risky User → App Operations Chain (HIGHEST SIGNAL)

**Purpose:** Detect users with active Identity Protection risk detections who then perform app credential, ownership, or consent operations. This is the opening move of the Guardz/SolarWinds attack — a compromised user leveraging their app ownership.

**Kill Chain Stage:** Compromise → App Abuse

**Tables:** `AADUserRiskEvents` + `AuditLogs`

**Why high signal:** A user flagged by Identity Protection performing app credential operations within days is strong evidence of the exact attack pattern described in the Guardz research. Normal admins don't accumulate risk detections before routine app management.

```kql
// Chain Detection: Users with active risk → app credential/ownership operations
// Correlates Identity Protection risk events with ApplicationManagement operations
let lookback = 30d;
let chainWindow = 7d; // Risk event → app operation within 7 days
// Step 1: Users with unresolved or confirmed risk
let RiskyUsers = AADUserRiskEvents
| where TimeGenerated > ago(lookback)
| where RiskState in ("atRisk", "confirmedCompromised")
| summarize 
    RiskEvents = count(),
    RiskTypes = make_set(RiskEventType, 5),
    MaxRiskLevel = max(RiskLevel),
    EarliestRisk = min(TimeGenerated),
    LatestRisk = max(TimeGenerated)
    by UserPrincipalName;
// Step 2: App credential/ownership/consent operations by those users
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName has_any ("credential", "secret", "certificate", "owner", "consent", "permission")
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where isnotempty(InitiatedByUser)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppName = coalesce(
    tostring(Target.displayName),
    tostring(parse_json(tostring(parse_json(tostring(Target.modifiedProperties))[1].newValue))))
| join kind=inner RiskyUsers on $left.InitiatedByUser == $right.UserPrincipalName
| where TimeGenerated between (EarliestRisk .. (LatestRisk + chainWindow))
| project 
    RiskDetectedAt = EarliestRisk,
    AppOperationAt = TimeGenerated,
    TimeDeltaHours = datetime_diff('hour', TimeGenerated, EarliestRisk),
    User = InitiatedByUser,
    RiskTypes,
    MaxRiskLevel,
    RiskEvents,
    OperationName,
    TargetApp = TargetAppName,
    CorrelationId
| order by RiskDetectedAt desc
```

**Expected Results:**
- Each row = one app operation performed by a risky user within the chain window
- `TimeDeltaHours`: Time between first risk detection and the app operation
- `RiskTypes`: Identity Protection detection types (e.g., `suspiciousAuthAppApproval`, `unfamiliarFeatures`, `anomalousToken`)

**Triage Priority:**
- 🔴 **Critical:** `MaxRiskLevel` = high + credential add operation → likely active compromise
- 🟠 **High:** `MaxRiskLevel` = medium + ownership add → attacker positioning for persistence
- 🟡 **Medium:** `MaxRiskLevel` = low + consent grant → may be `suspiciousAuthAppApproval` self-referencing (Identity Protection flagging the same consent it detects)

**Tuning:**
- Tighten `chainWindow` to `1d` for higher precision, lower recall
- Add `| where RiskTypes !has "suspiciousAuthAppApproval"` to exclude consent-flagging-consent loops if too noisy
- Expand to include `RiskState == "remediated"` if you want to see historical chains where risk was already addressed

---

## Query 2: Credential Add → SPN Activation from New Origin

**Purpose:** After a credential (secret/certificate) is added to an app, detect when the SPN authenticates from a new IP within 72 hours. This is the SolarWinds "backdoor credential → authenticate as the app" pattern.

**Kill Chain Stage:** Persistence → SPN Impersonation

**Tables:** `AuditLogs` + `AADServicePrincipalSignInLogs`

**Why this matters:** Legitimate credential rotation typically results in sign-ins from the same infrastructure IPs. A credential add followed by sign-ins from new IPs suggests the credential was created by an attacker who then used it from their own infrastructure.

```kql
// Chain Detection: Credential added → SPN signs in within 72h
// Shows what IP/resource/credential type the SPN used post-credential-add
let lookback = 30d;
let activationWindow = 72h;
// Step 1: Credential additions with actor and target
let CredentialAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials"
  )
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppName = tostring(Target.displayName)
| extend TargetAppId = tostring(Target.id)
| extend ModifiedProps = parse_json(tostring(Target.modifiedProperties))
| extend KeyDescription = tostring(ModifiedProps[0].newValue)
| extend CredentialType = case(
    KeyDescription has "AsymmetricX509Cert", "Certificate",
    KeyDescription has "Password", "Client Secret",
    "Unknown")
| project CredAddTime = TimeGenerated, Actor, TargetAppName, TargetAppId, CredentialType, CorrelationId;
// Step 2: SPN sign-ins after credential add
CredentialAdds
| join kind=inner (
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0" // successful only
    | project SPNSignInTime = TimeGenerated, AppId, ServicePrincipalName, IPAddress, 
        Location, ResourceDisplayName, ClientCredentialType,
        ServicePrincipalCredentialKeyId
) on $left.TargetAppId == $right.AppId
| where SPNSignInTime between (CredAddTime .. (CredAddTime + activationWindow))
| summarize
    SPNSignIns = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    Resources = make_set(ResourceDisplayName, 5),
    CredTypes = make_set(ClientCredentialType, 5),
    FirstSignIn = min(SPNSignInTime),
    LastSignIn = max(SPNSignInTime)
    by CredAddTime, Actor, TargetAppName, TargetAppId, CredentialType, CorrelationId
| extend HoursToActivation = datetime_diff('hour', FirstSignIn, CredAddTime)
| order by CredAddTime desc
```

**Expected Results:**
- Each row = a credential-add event paired with the SPN sign-in activity that followed
- `HoursToActivation`: How quickly the SPN was used after the credential was added
- `DistinctIPs`: Number of unique IPs the SPN signed in from — high diversity is suspicious

**Triage Priority:**
- 🔴 **Critical:** `HoursToActivation` < 1 + new IP not in SPN's historical baseline
- 🟠 **High:** `HoursToActivation` < 24 + accessing sensitive resources (Graph, Key Vault)
- 🟡 **Medium:** Normal activation window but from multiple IPs

**Enhancement — Baseline Comparison:**

To determine if the SPN's post-credential-add IPs are **new**, compare against its 90-day baseline. Run the SPN scope drift skill (`.github/skills/scope-drift-detection/spn/SKILL.md`) on any SPN flagged by this query.

---

## Query 3: Ownership Add → Credential Modification Chain

**Purpose:** Detect the exact Guardz attack sequence — a user is added as app owner, then credentials are modified on that app within 7 days. The `SameActorAsNewOwner` flag is key: if the newly added owner immediately creates a credential, that's the attacker using the ownership to establish persistence.

**Kill Chain Stage:** Privilege Escalation → Persistence

**Tables:** `AuditLogs` (self-join)

```kql
// Chain Detection: Owner added to app → credential/permission op on same app within 7d
let lookback = 30d;
let chainWindow = 7d;
// Step 1: Ownership additions — extract new owner and target app
let OwnershipAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ ("Add owner to application", "Add owner to service principal")
| extend Target0 = parse_json(tostring(TargetResources))[0]
| extend NewOwnerUPN = tostring(Target0.userPrincipalName)
| extend NewOwnerId = tostring(Target0.id)
| extend ModProps = parse_json(tostring(Target0.modifiedProperties))
| extend TargetAppName = tostring(parse_json(tostring(ModProps[1].newValue)))
| extend TargetAppId = tostring(parse_json(tostring(ModProps[0].newValue)))
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, tostring(parse_json(tostring(InitiatedBy)).app.displayName))
| project OwnerAddTime = TimeGenerated, Actor, NewOwnerUPN, TargetAppName, TargetAppId, OperationName;
// Step 2: Credential or permission operations on the same app
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials",
    "Add delegated permission grant",
    "Consent to application",
    "Add app role assignment to service principal"
  )
| extend Target = parse_json(tostring(TargetResources))[0]
| extend CredTargetId = tostring(Target.id)
| extend CredActor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| join kind=inner OwnershipAdds on $left.CredTargetId == $right.TargetAppId
| where TimeGenerated between (OwnerAddTime .. (OwnerAddTime + chainWindow))
| project
    OwnerAddTime,
    CredOpTime = TimeGenerated,
    HoursGap = datetime_diff('hour', TimeGenerated, OwnerAddTime),
    NewOwnerUPN,
    CredActor,
    SameActorAsNewOwner = (CredActor =~ NewOwnerUPN),
    OwnershipOp = OperationName1,
    CredentialOp = OperationName,
    TargetAppName,
    TargetAppId
| order by OwnerAddTime desc
```

**Expected Results:**
- Each row = an ownership add followed by a credential/permission operation on the same app
- `SameActorAsNewOwner`: **true** = the new owner immediately used their ownership to modify credentials (highest signal)
- `HoursGap`: Time between ownership grant and credential operation

**Triage Priority:**
- 🔴 **Critical:** `SameActorAsNewOwner` = true + `HoursGap` < 1 + credential operation → scripted attack
- 🟠 **High:** `SameActorAsNewOwner` = true + `HoursGap` < 24 → manual attacker using ownership
- 🟡 **Medium:** Different actors (admin added owner, owner later legitimately rotated creds)

**Note on Join:** This query joins ownership operations (which store the app's Application ObjectId in `modifiedProperties`) with credential operations (which store the Application ObjectId in `Target[0].id`). Both use the same ID space for these specific operation types, so the join is reliable.

---

## Query 4: SPN Cross-Tenant Sign-Ins

**Purpose:** Detect service principals owned by external tenants authenticating into your tenant, or your SPNs authenticating into foreign tenants. Multi-tenant app abuse was the core SolarWinds persistence mechanism.

**Kill Chain Stage:** Lateral Movement (cross-tenant)

**Tables:** `AADServicePrincipalSignInLogs`

```kql
// Detect cross-tenant SPN authentication — foreign SPNs accessing local resources
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where ResultType == "0"
| where isnotempty(AppOwnerTenantId)
| where AppOwnerTenantId != AADTenantId
| summarize 
    SignIns = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5),
    Resources = make_set(ResourceDisplayName, 10),
    CredTypes = make_set(ClientCredentialType, 5),
    Locations = make_set(Location, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ServicePrincipalName, AppId, AppOwnerTenantId, AADTenantId
| order by SignIns desc
```

**Expected Results:**
- Each row = a cross-tenant SPN with its sign-in summary
- `AppOwnerTenantId`: The foreign tenant that owns the app
- `Resources`: What local resources the foreign SPN is accessing

**Triage Priority:**
- 🔴 **Critical:** Unknown foreign tenant SPN accessing sensitive resources (Graph, Key Vault, ARM) — possible SolarWinds-style access
- 🟠 **High:** Known partner/vendor SPN with new access patterns or new resources
- 🟡 **Low:** Microsoft first-party service SPNs (verify against [Microsoft first-party apps](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in))

**Enhancement — New Cross-Tenant SPNs:**

To find SPNs that **recently** started cross-tenant auth (didn't exist in prior baseline):

```kql
// New cross-tenant SPNs — first seen in last 7 days vs 30-day baseline
let recent = 7d;
let baseline = 30d;
let RecentCrossTenant = AADServicePrincipalSignInLogs
| where TimeGenerated > ago(recent)
| where ResultType == "0"
| where AppOwnerTenantId != AADTenantId
| distinct AppId, ServicePrincipalName, AppOwnerTenantId;
let BaselineCrossTenant = AADServicePrincipalSignInLogs
| where TimeGenerated between (ago(baseline) .. ago(recent))
| where ResultType == "0"
| where AppOwnerTenantId != AADTenantId
| distinct AppId;
RecentCrossTenant
| join kind=leftanti BaselineCrossTenant on AppId
| project ServicePrincipalName, AppId, AppOwnerTenantId
```

---

## Query 5: Credential Add → SPN Graph API Lateral Movement

**Purpose:** After a credential is added, track what Graph API calls the SPN makes. Categorizes API endpoints into sensitive categories (role management, email access, file access, etc.) to identify lateral movement and data exfiltration.

**Kill Chain Stage:** Lateral Movement / Data Exfiltration

**Tables:** `AuditLogs` + `MicrosoftGraphActivityLogs`

**Prerequisite:** `MicrosoftGraphActivityLogs` must be ingested (requires Entra ID P1/P2 + diagnostic settings enabled).

```kql
// Chain Detection: Credential added → SPN Graph API calls within 72h
// Categorizes API calls into sensitive endpoint groups
let lookback = 30d;
let monitorWindow = 72h;
// Step 1: Apps that had credentials added
let CredentialAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials"
  )
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppId = tostring(Target.id)
| extend TargetAppName = tostring(Target.displayName)
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project CredAddTime = TimeGenerated, Actor, TargetAppName, TargetAppId;
// Step 2: Graph API calls by those apps after credential add
CredentialAdds
| join kind=inner (
    MicrosoftGraphActivityLogs
    | where TimeGenerated > ago(lookback)
    | where isnotempty(ServicePrincipalId)
    | project GraphCallTime = TimeGenerated, AppId, RequestMethod, RequestUri, 
        ResponseStatusCode, ServicePrincipalId
) on $left.TargetAppId == $right.AppId
| where GraphCallTime between (CredAddTime .. (CredAddTime + monitorWindow))
| extend EndpointCategory = case(
    RequestUri has "/roleManagement/", "Role Management",
    RequestUri has_any ("/applications/", "/servicePrincipals/"), "App/SPN Management",
    RequestUri has "/users/", "User Enumeration",
    RequestUri has "/groups/", "Group Enumeration",
    RequestUri has "/identity/conditionalAccess/", "CA Policy Access",
    RequestUri has "/policies/", "Policy Management",
    RequestUri has "/security/", "Security Data",
    RequestUri has_any ("/mail/", "/messages", "/mailFolders"), "Email Access",
    RequestUri has_any ("/drives/", "/sites/"), "File Access",
    RequestUri has "/auditLogs/", "Audit Log Access",
    "Other")
| where EndpointCategory != "Other"
| summarize 
    GraphCalls = count(),
    Methods = make_set(RequestMethod, 5),
    SampleUris = make_set(RequestUri, 3),
    SuccessRate = round(100.0 * countif(ResponseStatusCode >= 200 and ResponseStatusCode < 300) / count(), 1)
    by CredAddTime, Actor, TargetAppName, TargetAppId, EndpointCategory
| order by CredAddTime desc, GraphCalls desc
```

**Expected Results:**
- Each row = a category of Graph API activity performed by an SPN after receiving a credential
- `EndpointCategory`: Classifies what the SPN was accessing
- `SampleUris`: Specific API paths for investigation

**Triage Priority:**
- 🔴 **Critical:** `Role Management` or `App/SPN Management` → privilege escalation / further persistence
- 🔴 **Critical:** `Email Access` → data exfiltration (SolarWinds primary objective)
- 🟠 **High:** `CA Policy Access` or `Policy Management` → defense evasion
- 🟠 **High:** `User Enumeration` + `Security Data` → reconnaissance
- 🟡 **Medium:** `File Access` → potential data staging

---

## Query 6: Credential Add → Permission Escalation Chain

**Purpose:** After adding a credential (establishing persistence), detect the attacker granting additional permissions or consenting to broader API access on the same app.

**Kill Chain Stage:** Persistence → Privilege Escalation

**Tables:** `AuditLogs` (self-join)

**Schema Note:** Credential operations and consent operations use different ID spaces for the same app (Application ObjectId vs ServicePrincipal ObjectId). This query joins on `Actor` + `TargetAppName` rather than ObjectId to bridge the gap.

```kql
// Chain Detection: Credential added → permission/consent on same app within 7d
let lookback = 30d;
let escalationWindow = 7d;
// Step 1: Credential additions
let CredentialAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials"
  )
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppName = tostring(Target.displayName)
| where isnotempty(TargetAppName)
| extend CredActor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where isnotempty(CredActor)
| project CredAddTime = TimeGenerated, CredActor, TargetAppName;
// Step 2: Permission grants by same actor on same-named app
let PermissionGrants = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Add delegated permission grant",
    "Consent to application",
    "Add app role assignment to service principal"
  )
| extend EscActor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where isnotempty(EscActor)
| extend Target0 = parse_json(tostring(TargetResources))[0]
| extend PermAppName = case(
    OperationName =~ "Consent to application", tostring(Target0.displayName),
    tostring(Target0.displayName))
| project PermOpTime = TimeGenerated, EscActor, PermAppName, EscalationOp = OperationName;
// Join: same actor + same app + credential first then permission
CredentialAdds
| join kind=inner PermissionGrants on $left.CredActor == $right.EscActor, $left.TargetAppName == $right.PermAppName
| where PermOpTime between (CredAddTime .. (CredAddTime + escalationWindow))
| project
    CredAddTime,
    PermissionOpTime = PermOpTime,
    HoursGap = datetime_diff('hour', PermOpTime, CredAddTime),
    Actor = CredActor,
    TargetAppName,
    EscalationOp
| order by CredAddTime desc
```

**Expected Results:**
- Each row = a credential add followed by a permission/consent operation on the same app by the same user
- `HoursGap`: Time between credential creation and permission escalation

**Triage Priority:**
- 🔴 **Critical:** `HoursGap` = 0 + consent grant → automated attack tool (credential + consent in single session)
- 🟠 **High:** Consent to powerful API (check AuditLog `modifiedProperties` for scope details)
- 🟡 **Medium:** `Add app role assignment` with larger gap → possibly legitimate admin workflow

---

## Query 7: Multi-App Ownership Spread

**Purpose:** Detect a single user being added as owner to multiple applications within a rolling window. Attackers spread ownership across apps to maximize their blast radius — if one backdoor is discovered, others remain.

**Kill Chain Stage:** Persistence (breadth)

**Tables:** `AuditLogs`

```kql
// Detect lateral ownership expansion — one user becoming owner of many apps
let lookback = 30d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ ("Add owner to application", "Add owner to service principal")
| extend Target0 = parse_json(tostring(TargetResources))[0]
| extend NewOwnerUPN = tostring(Target0.userPrincipalName)
| extend ModProps = parse_json(tostring(Target0.modifiedProperties))
| extend TargetAppName = tostring(parse_json(tostring(ModProps[1].newValue)))
| extend TargetAppId = tostring(parse_json(tostring(ModProps[0].newValue)))
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, tostring(parse_json(tostring(InitiatedBy)).app.displayName))
| where isnotempty(NewOwnerUPN)
| summarize
    AppsOwned = dcount(TargetAppId),
    AppNames = make_set(TargetAppName, 10),
    OwnershipOps = count(),
    FirstAdd = min(TimeGenerated),
    LastAdd = max(TimeGenerated),
    AddedBy = make_set(Actor, 5)
    by NewOwnerUPN
| extend SpreadWindowHours = datetime_diff('hour', LastAdd, FirstAdd)
| where AppsOwned >= 3
| order by AppsOwned desc
```

**Expected Results:**
- Each row = a user who became owner of multiple apps within the lookback period
- `AppsOwned`: Distinct apps — higher count = wider blast radius
- `SpreadWindowHours`: How quickly ownership was accumulated
- `AddedBy`: Who granted the ownership (self-add vs admin vs automation)

**Triage Priority:**
- 🔴 **Critical:** `AppsOwned` >= 5 + `SpreadWindowHours` < 24 → bulk automated ownership grab
- 🟠 **High:** Non-admin user (`AddedBy` = themselves) with `AppsOwned` >= 3
- 🟡 **Medium:** Automation account adding ownership as part of deployment (expected for CI/CD)

**Enhancement — Correlate with Risk:**

To check if any of these ownership-spread users also have risk detections, feed the `NewOwnerUPN` values into Query 1.

---

## Posture Assessment (Graph API)

These Graph API queries provide **current-state** visibility into app permissions and ownership. AuditLogs only show **changes** — Graph API is required for a point-in-time inventory.

**Kill Chain Position:** Pre-kill-chain — proactive attack surface enumeration. Answers: "If any of these owners get phished tomorrow, what's the blast radius?"

**Scaling Strategy:** Don't enumerate all app registrations (could be 1000+). Instead, query from the **permission grant side** — find what's been granted dangerous permissions, then resolve owners only for those flagged apps. This reduces thousands of apps to the dozen or so that actually matter.

### Step 1: Find the Microsoft Graph Service Principal ID

The Microsoft Graph resource service principal is the target of all application permission grants. Its well-known AppId is `00000003-0000-0000-c000-000000000000`, but its ObjectId varies per tenant.

```
GET /v1.0/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id,displayName
```

Save the returned `id` — you'll need it for Step 2.

### Step 2: List ALL Application Permission Grants to Microsoft Graph

This single call returns every app in the tenant that has been granted **application-level** permissions (not delegated) to Microsoft Graph. This is the high-privilege inventory.

```
GET /v1.0/servicePrincipals/{graph-sp-id}/appRoleAssignedTo
    ?$select=principalDisplayName,principalId,principalType,appRoleId,createdDateTime
    &$top=999
```

**Returns:** One row per permission grant. Each row contains the app name (`principalDisplayName`), the permission GUID (`appRoleId`), and when it was granted (`createdDateTime`).

### Step 3: Resolve Permission GUIDs to Names

The `appRoleId` values are GUIDs. To get human-readable permission names:

```
GET /v1.0/servicePrincipals/{graph-sp-id}/appRoles
```

**Returns:** Complete list of Microsoft Graph permission definitions with `id` (GUID), `value` (e.g., `Mail.ReadWrite`), and `displayName`.

Build a lookup table mapping `appRoleId` → `value` to enrich the Step 2 results.

### Step 4: Filter to Dangerous Permissions

**Dangerous Permission Reference — Application-Level Grants:**

| Permission | Risk | Attack Use |
|------------|------|------------|
| `Application.ReadWrite.All` | 🔴 Critical | Create/modify any app registration — further persistence |
| `AppRoleAssignment.ReadWrite.All` | 🔴 Critical | Grant itself or any app **any permission** — golden ticket |
| `RoleManagement.ReadWrite.Directory` | 🔴 Critical | Assign any directory role to any principal |
| `Directory.ReadWrite.All` | 🔴 Critical | Read/write all directory objects |
| `Policy.ReadWrite.ConditionalAccess` | 🔴 Critical | Disable CA policies — defense evasion |
| `Mail.ReadWrite` | 🟠 High | Read any user's mailbox — data exfiltration |
| `Mail.Send` | 🟠 High | Send email as any user — phishing, BEC |
| `Mail.Read` | 🟠 High | Read any user's mail — reconnaissance |
| `MailboxSettings.ReadWrite` | 🟠 High | Create forwarding rules — silent exfiltration |
| `User.ReadWrite.All` | 🟠 High | Modify any user account — credential reset |
| `Group.ReadWrite.All` | 🟠 High | Modify group membership — privilege escalation |
| `Files.ReadWrite.All` | 🟠 High | Access all SharePoint/OneDrive files |
| `Sites.ReadWrite.All` | 🟠 High | Full SharePoint site access |
| `SecurityEvents.ReadWrite.All` | 🟡 Medium | Read/modify security alerts — cover tracks |
| `User.Export.All` | 🟡 Medium | Export all user data — bulk exfiltration |
| `Exchange.ManageAsApp` | 🟡 Medium | Full Exchange management — mailbox access |

Filter the Step 2 results to only rows where the resolved permission name appears in this list.

### Step 5: Resolve Owners for Flagged Apps

**Only** for apps flagged in Step 4, retrieve their owners from the **Application object** (not the ServicePrincipal — ownership is on the app registration):

```
GET /v1.0/applications?$filter=displayName eq '{flagged-app-name}'
    &$select=id,appId,displayName,passwordCredentials,keyCredentials
    &$expand=owners($select=id,displayName,userPrincipalName)
```

**Important:** Repeat for each flagged app. For cross-tenant SPNs (apps owned by a foreign tenant), this call returns empty results — those apps have no local Application object to query.

### Step 6: Assess Owner Risk

For each owner found in Step 5, determine if they are:

1. **Standard users (non-admin):** Cross-reference against directory role assignments:
   ```
   GET /v1.0/roleManagement/directory/roleAssignments
       ?$filter=principalId eq '{owner-id}'
       &$expand=roleDefinition($select=displayName)
   ```
   If no roles → standard user → **high risk** (the Guardz attack vector — if compromised, attacker inherits app ownership)

2. **Currently risky:** Feed `owner.userPrincipalName` into **Query 1** (Risky User → App Ops Chain) to check for active Identity Protection risk events

3. **Already compromised in AuditLogs:** Check if the owner has performed suspicious app operations recently:
   ```
   GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{owner-id}'
   ```

### Step 7: Credential Hygiene Check

For apps flagged in Step 4, the Step 5 response includes `passwordCredentials` and `keyCredentials`:

| Check | Field | Risk |
|-------|-------|------|
| Multiple active secrets | `passwordCredentials[]` where `endDateTime > now` | 🟠 Multiple access methods — harder to revoke |
| Long-lived secrets | `endDateTime` > 2 years from `startDateTime` | 🟠 Stale credential risk — may leak without detection |
| No credentials at all | Empty `passwordCredentials` + `keyCredentials` | 🟢 App can't be used for SPN auth (lower risk) |
| Certificate + Secret both active | Both arrays non-empty | 🟡 Review — cert is expected, secret alongside is unusual |

### Pitfalls Discovered During Testing

| Issue | Details | Workaround |
|-------|---------|------------|
| **Cross-tenant SPNs have no local app object** | `GET /v1.0/applications?$filter=displayName eq 'X'` returns empty for SPNs owned by foreign tenants | Identify via `AADServicePrincipalSignInLogs` where `AppOwnerTenantId != AADTenantId` (Query 4). These apps can only be managed by the owning tenant |
| **Service Principal owners ≠ Application owners** | `GET /v1.0/servicePrincipals/{id}?$expand=owners` often returns empty even when the Application has owners | Always query the **Application** object for ownership, not the ServicePrincipal |
| **Red team apps may have owners stripped** | Attack simulation tools often remove ownership post-creation to evade detection | Fall back to AuditLogs `"Add application"` operation to find the original creator — AuditLogs retain the `InitiatedBy` actor forever |
| **`requiredResourceAccess` ≠ granted permissions** | The Application object's `requiredResourceAccess` shows what the app **requests**, not what's been **granted** | Use Step 2 (`appRoleAssignedTo`) for granted permissions — this is the authoritative source |

### Workflow Summary

```
Step 1: GET graph-sp-id                                    ← 1 call
Step 2: GET /appRoleAssignedTo (all grants)                ← 1 call (paginated)
Step 3: GET /appRoles (permission definitions)             ← 1 call
Step 4: Filter to dangerous perms (client-side)            ← 0 calls
Step 5: GET /applications?$expand=owners (per flagged app) ← N calls (only flagged apps)
Step 6: GET /roleAssignments (per owner)                   ← M calls (only flagged owners)
Step 7: Credential hygiene (from Step 5 response)          ← 0 calls
────────────────────────────────────────────────────────────
Total: 3 + N + M calls (typically < 20 for most tenants)
```

**When to run:** Periodically (weekly/monthly) as a proactive posture check, or on-demand when investigating a compromised user to assess their app ownership blast radius.

---

## References

- [Guardz: Abusing Entra ID App Registrations for Long-Term Persistence](https://guardz.com/blog/abusing-entra-id-app-registrations-for-long-term-persistence/)
- [Microsoft: Solorigate Coordinated Defense](https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/)
- [Microsoft: App Governance in Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance)
- [MITRE ATT&CK T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [MITRE ATT&CK T1550.001 — Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [Microsoft: Verify First-Party Apps in Sign-In Reports](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in)

### Related Workspace Resources

| Resource | Relationship |
|----------|-------------|
| `queries/identity/app_credential_management.md` | Individual event queries — complements these chains |
| `queries/identity/service_principal_scope_drift.md` | SPN behavioral baseline — use for post-detection deep dive |
| `.github/skills/scope-drift-detection/spn/SKILL.md` | Full SPN investigation workflow — run on SPNs flagged by Q2 |
| `queries/cloud/behavior_entities.md` Q6 | MCAS `UnusualAdditionOfCredentialsToAnOauthApp` detection |
