# Email Threat Landscape Q1 2026 — TTPs & IOCs

**Created:** 2026-05-01  
**Platform:** Both  
**Tables:** EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents, DeviceNetworkEvents  
**Keywords:** Tycoon2FA, Storm-1747, Kratos, Sneaky2FA, EvilTokens, RedVDS, AiTM, adversary-in-the-middle, QR code phishing, quishing, CAPTCHA-gated, SVG attachment, Base64 filename, HTML attachment, PhaaS, .ru TLD, .digital TLD, .business TLD, awstrack.me, keyword-stuffed sender, niovapahrm, hvishay, drilto, credential phishing  
**MITRE:** T1566.001, T1566.002, T1598.002, T1204.001, T1204.002, T1027.013, T1027, T1078, TA0001, TA0006  
**Domains:** email  
**Timeframe:** Last 30 days (configurable)

---

## Threat Overview

[Microsoft Threat Intelligence — Email threat landscape: Q1 2026 trends and insights (April 30, 2026)](https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/) reports approximately **8.3 billion email-based phishing threats** in Q1 2026, with several notable shifts in delivery technique. This file covers **new TTPs/IOCs not already addressed** in [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md).

**Headline shifts (Q1 2026):**

| Shift | Magnitude | Defender impact |
|---|---|---|
| **QR code phishing** (PDF/DOCX/body-embedded) | +146% over the quarter; body-embedded QRs +336% in March | Mobile QR scans bypass email Safe Links; rendered locally |
| **CAPTCHA-gated phishing** | +125% in March; SVG +49% Feb spike, PDF +356% in March | Visual decoy delays sandbox detection |
| **Tycoon2FA TLD pivot** | `.ru` rose to 41% of Tycoon2FA domains by end of March | New IOC TLD set after RedVDS + Tycoon2FA disruption |
| **Multi-PhaaS HTML campaign (March 17)** | 1.5M messages / 179k orgs / 43 countries | Keyword-stuffed sender usernames embedding URLs |
| **SVG CAPTCHA campaign (Feb 23–25)** | 1.2M messages / 53k orgs / 23 countries | Base64-encoded recipient email in SVG filename |

**Companion infrastructure:** Tycoon2FA (Storm-1747), Kratos (formerly Sneaky2FA), EvilTokens.

**Coverage delta vs existing files:**

- [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md) — covers general phishing, AiTM full chain, ZAP failure, BEC outbound, forwarding rules, Safe Links clicks, attachment summary
- [`queries/identity/aitm_threat_detection.md`](../../identity/aitm_threat_detection.md) — covers AiTM proxy detection (OfficeHome multi-country), anomalous token correlation
- **This file (NEW):** SVG CAPTCHA-gated campaign IOCs, QR code concealment vectors, Tycoon2FA TLD pivot, keyword-stuffed sender username detection, body-embedded image phishing proxy

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [SVG CAPTCHA Campaign IOC Hostnames (Feb 23–25)](#query-1-svg-captcha-campaign-ioc-hostnames-feb-2325) | Investigation | `DeviceNetworkEvents` + multi |
| 2 | [SVG Attachments with Base64-Encoded Recipient in Filename](#query-2-svg-attachments-with-base64-encoded-recipient-in-filename) | Investigation | `EmailAttachmentInfo` + `EmailEvents` |
| 3 | [All Inbound SVG Attachments — General CAPTCHA-Gated Hunt](#query-3-all-inbound-svg-attachments--general-captcha-gated-hunt) | Investigation | `EmailAttachmentInfo` + `EmailEvents` |
| 4 | [PDF/DOCX Phish Attachments — QR Code Concealment Vector](#query-4-pdfdocx-phish-attachments--qr-code-concealment-vector) | Investigation | `EmailAttachmentInfo` + `EmailEvents` |
| 5 | [Tycoon2FA Suspicious TLDs in Inbound Email URLs](#query-5-tycoon2fa-suspicious-tlds-in-inbound-email-urls) | Investigation | `EmailEvents` + `EmailUrlInfo` |
| 6 | [Keyword-Stuffed Sender Usernames (March 17 HTML Campaign)](#query-6-keyword-stuffed-sender-usernames-march-17-html-campaign) | Investigation | `EmailEvents` |
| 7 | [No-Attachment + URL Phish — Body-Embedded QR Proxy](#query-7-no-attachment--url-phish--body-embedded-qr-proxy) | Investigation | `EmailEvents` |
| 8 | [User Click-Through on Tycoon2FA-Style TLD URLs (Compromise Check)](#query-8-user-click-through-on-tycoon2fa-style-tld-urls-compromise-check) | Investigation | `UrlClickEvents` |


## IOC Reference

| Type | Value | Context |
|------|-------|---------|
| **Domain** | `niovapahrm[.]com` | Feb 23–25 SVG CAPTCHA campaign — host pattern `bouleversement.niovapahrm[.]com` |
| **Domain** | `hvishay[.]com` | Feb 23–25 SVG CAPTCHA campaign — host pattern `haematogenesis.hvishay[.]com` |
| **Domain** | `drilto[.]com` | Feb 23–25 SVG CAPTCHA campaign — host pattern `ubiquitarianism.drilto[.]com` |
| **TLD set (Tycoon2FA emerging)** | `.ru`, `.digital`, `.business`, `.contractors`, `.ceo`, `.company` | Replaces older `.sa.com`, `.es`, `.ru` (re-emerging dominant), `.dev` |
| **Filename pattern** | `*_<Base64-encoded recipient email>.svg` | Feb 23–25 SVG campaign signature |
| **Sender username pattern** | Excessively long (≥60 chars), embedded URLs (`awstrack.me`, `zoom`, `spectrumbusiness`), `Noreply-/`, `_-AAP`, listenerId | March 17 multi-PhaaS HTML campaign |
| **Subject themes** | "401K update", "credit hold", "received payment", "past due invoice", "voice message", "ACH/EFT/wire alert", "e-signature request" | Q1 2026 phishing themes |

---

---

## Query 1: SVG CAPTCHA Campaign IOC Hostnames (Feb 23–25)

Multi-table sweep for the three documented C2 hostnames from the February 23–25 SVG CAPTCHA campaign. Searches `EmailUrlInfo` (URLs in inbound email bodies/attachments), `UrlClickEvents` (Safe Links activations), and `DeviceNetworkEvents` (post-click connections from devices that opened the SVG locally in a browser).

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Q1 2026 SVG CAPTCHA Campaign IOC Domain — {{Source}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Investigate the recipient mailbox for the originating SVG attachment. Quarantine related messages via Threat Explorer. Check recipient sign-in logs for AiTM activity in the 24h after click."
adaptation_notes: "AH-native. Uses Timestamp on all three tables (XDR-native). UrlClickEvents.ActionType field describes click outcome (ClickAllowed, ClickBlocked, ClickBlockedByTenantPolicy)."
-->
```kql
// Q1 2026 Email Threat Landscape: Feb 23-25 SVG CAPTCHA campaign IOC hostnames
let lookback = 30d;
let iocHosts = dynamic(["niovapahrm.com","hvishay.com","drilto.com"]);
union
  ( EmailUrlInfo
    | where Timestamp > ago(lookback)
    | where UrlDomain has_any (iocHosts)
    | extend Source = "EmailUrlInfo"
    | project Timestamp, Source, NetworkMessageId, Url, UrlDomain ),
  ( UrlClickEvents
    | where Timestamp > ago(lookback)
    | where Url has_any (iocHosts)
    | extend Source = "UrlClickEvents"
    | project Timestamp, Source, AccountUpn, Url, IPAddress, ActionType ),
  ( DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl has_any (iocHosts)
    | extend Source = "DeviceNetworkEvents"
    | project Timestamp, Source, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP )
| order by Timestamp desc
```

**Tuning:**
- IOC list is **point-in-time** — these specific subdomains tied to the Feb 23–25 campaign. New campaigns will use new infrastructure.
- For broader hunting, replace `has_any (iocHosts)` with the suspicious-TLD pattern from Query 5.

---

## Query 2: SVG Attachments with Base64-Encoded Recipient in Filename

Detects the **Q1 2026 SVG CAPTCHA campaign filename signature**: each SVG file delivered to a target encodes the **recipient's email as Base64** in the filename (e.g., `401K_copy_<Recipient Name>_<Base64-encoded Email Address>_241.svg`). Two checks: (a) explicit match of the encoded recipient email against the filename, (b) generic Base64-suffix pattern (≥16 Base64 chars before `.svg`).

> **⚠️ Tool note:** This query trips Advanced Hunting's safety filter (`base64_encode_tostring` + recipient context). **Run via Sentinel Data Lake** (`mcp_sentinel-data_query_lake`), not `RunAdvancedHuntingQuery`.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Sentinel Data Lake only — Advanced Hunting safety filter blocks queries containing base64_encode_tostring on recipient PII. CD rules cannot use Data Lake; use Query 3 as CD-eligible alternative for general SVG inbound hunting."
-->
```kql
// Q1 2026 Email Threat Landscape: SVG attachments with Base64-encoded recipient in filename
// Run via Sentinel Data Lake (TimeGenerated). AH safety filter blocks this query shape.
let lookback = 30d;
EmailAttachmentInfo
| where TimeGenerated > ago(lookback)
| where FileName endswith ".svg"
| join kind=leftouter (
    EmailEvents
    | where TimeGenerated > ago(lookback)
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderIPv4, EmailDirection, Subject, DeliveryAction
  ) on NetworkMessageId
| extend RecipB64 = base64_encode_tostring(tostring(RecipientEmailAddress))
| extend FileNameNoExt = tostring(split(FileName, ".svg")[0])
| extend HasB64Recip = (FileNameNoExt has RecipB64 and strlen(RecipB64) > 6)
| extend LooksB64Suffix = (FileName matches regex @"[A-Za-z0-9+/=]{16,}\.svg$")
| where HasB64Recip or LooksB64Suffix
| project TimeGenerated, FileName, RecipientEmailAddress, SenderFromAddress, SenderIPv4, EmailDirection, Subject, DeliveryAction, HasB64Recip, LooksB64Suffix, NetworkMessageId
| order by TimeGenerated desc
| take 100
```

**Tuning:**
- `HasB64Recip = true` is **high-confidence** (per-recipient personalization is rarely benign).
- `LooksB64Suffix = true` alone catches generic Base64-suffixed SVGs — review delivery context before alerting.
- Exclude legitimate intra-org SVG senders if needed: `| where EmailDirection == "Inbound"`.

---

## Query 3: All Inbound SVG Attachments — General CAPTCHA-Gated Hunt

Sanity-check + general hunt for SVG attachments in inbound/intra-org mail. Q1 2026 saw **SVG +49% in February** as a CAPTCHA-gated phishing payload, then declining as PhaaS rotated to PDF/HTML — but SVG remains a niche evasion technique because it executes locally in the browser when opened.

<!-- cd-metadata
cd_ready: true
schedule: "12H"
category: "InitialAccess"
title: "Inbound SVG attachment delivered — possible CAPTCHA-gated phishing"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Review SVG content before user opens it. SVG is rarely a legitimate inbound business attachment. Check Threat Explorer for related messages and quarantine via ZAP."
adaptation_notes: "AH-native. Uses Timestamp. SVGs from Inbound mail are inherently suspicious; intra-org SVGs are usually benign (legit graphics in newsletters, Teams workflows). Default scope: Inbound only."
-->
```kql
// Q1 2026 Email Threat Landscape: All inbound SVG attachments (general CAPTCHA-gated hunt)
let lookback = 30d;
EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where FileName endswith ".svg" or FileType has "svg"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Inbound"
  ) on NetworkMessageId
| project Timestamp, FileName, FileSize, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes, DetectionMethods, NetworkMessageId
| order by Timestamp desc
| take 200
```

**Tuning:**
- `EmailDirection == "Inbound"` is the highest-signal filter — intra-org SVGs are common in marketing/newsletter automation.
- For organisations with legitimate SVG senders (design agencies, marketing platforms), allow-list via `| where SenderFromAddress !endswith "@<your-trusted-domain>.com"`.

---

## Query 4: PDF/DOCX Phish Attachments — QR Code Concealment Vector

QR codes embedded in PDF and DOCX attachments were the dominant Q1 2026 QR phishing delivery method (PDF: 65% → 70% across the quarter; DOC/DOCX +373% in March for CAPTCHA-gated payloads). Microsoft Defender for Office 365 image-scanning detects most QR codes — this query surfaces inbound PDFs/DOCXs that MDO already classified as Phish for triage and review.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "InitialAccess"
title: "Inbound {{FileType}} attachment classified as Phish — QR code concealment likely"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Open the attachment in Threat Explorer's safe sandbox to confirm QR content. Block sender + similar attachments via ZAP. Notify recipient that mobile QR scans bypass email Safe Links."
adaptation_notes: "AH-native. ThreatTypes is a String column - use 'has' not '=='. Inbound-only filter to skip intra-org PDF newsletters."
-->
```kql
// Q1 2026 Email Threat Landscape: PDF/DOCX phish attachments (QR code concealment vector)
let lookback = 30d;
EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where FileType in~ ("pdf","docx","docm","doc")
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Inbound"
    | where ThreatTypes has "Phish"
  ) on NetworkMessageId
| project Timestamp, FileName, FileType, FileSize, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DetectionMethods, NetworkMessageId
| order by Timestamp desc
| take 200
```

**Tuning:**
- For environments with mature MDO image-scanning, `DetectionMethods` may include explicit QR code references — refine with `| where DetectionMethods has "QR"` if available.
- Pair with mobile sign-in anomaly detection: a mailbox receives QR phish, then a sign-in anomaly fires from an unmanaged mobile device 5–60 minutes later — a strong QR-scan compromise pattern.

---

## Query 5: Tycoon2FA Suspicious TLDs in Inbound Email URLs

Surfaces inbound URLs in the **emerging Q1 2026 Tycoon2FA TLD set**. Following the early-March RedVDS + Tycoon2FA disruption, infrastructure pivoted heavily to `.ru` (41% of Tycoon2FA domains by end of March) and the gTLDs `.digital`, `.business`, `.contractors`, `.ceo`, `.company`.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "InitialAccess"
title: "Inbound email URL using Tycoon2FA-style TLD: .{{tld}}"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Validate sender reputation and URL category. If URL leads to a sign-in page, check recipient's subsequent sign-in for AiTM markers (OfficeHome app, anomalous token, foreign country). Quarantine via Threat Explorer if confirmed."
adaptation_notes: "AH-native. UrlDomain is string - last token after '.' is the TLD. The TLD list reflects the Q1 2026 Tycoon2FA pivot and will need refresh as infrastructure rotates. Intra-org senders excluded by Inbound filter."
-->
```kql
// Q1 2026 Email Threat Landscape: Tycoon2FA suspicious TLDs in inbound email URLs
let lookback = 30d;
let suspiciousTlds = dynamic(["ru","digital","business","contractors","ceo","company"]);
EmailUrlInfo
| where Timestamp > ago(lookback)
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Inbound"
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderIPv4, Subject, ThreatTypes, DeliveryAction
  ) on NetworkMessageId
| extend tld = tolower(tostring(split(UrlDomain, ".")[-1]))
| where tld in (suspiciousTlds)
| summarize Count=count(), Recipients=dcount(RecipientEmailAddress), Senders=dcount(SenderFromAddress),
            SampleDomains=make_set(UrlDomain, 25), Threats=make_set(ThreatTypes, 5),
            Deliveries=make_set(DeliveryAction, 5), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
            by tld
| order by Count desc
```

**Tuning:**
- `.ru` is the **highest-confidence** indicator — legitimate inbound `.ru` business mail is rare in most non-Russian organisations. Tighten with `| where tld == "ru" and ThreatTypes has "Phish"` for high-precision alerting.
- `.business`, `.ceo`, `.company` — significant false-positive risk from legitimate businesses. Combine with `ThreatTypes has "Phish"` or `DeliveryAction != "Delivered"`.
- Add organisation's known-legitimate `.ru` partners to an exclusion list as needed.

---

## Query 6: Keyword-Stuffed Sender Usernames (March 17 HTML Campaign)

Detects the **March 17, 2026 multi-PhaaS HTML campaign** signature: sender local-parts (the part before `@`) are **excessively long** (60–250+ characters), keyword-stuffed with embedded URLs, AWS tracking IDs, Zoom links, and tokens like `awstrack.me`, `Noreply-/`, `_-AAP`, `listenerId`. Examples from the campaign include `eReceipt_Payment_Alert_Noreply-/m939k6d7.r.us-west-2.awstrack.me/L0/...` and `DocExchange_Noreply-m939k6d7.r.us_west_2.awstrack.me/...`.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Inbound email from keyword-stuffed sender username — possible PhaaS campaign"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Quarantine the message and similar messages from the same SenderIPv4 via Threat Explorer. The HTML attachment will be present and locally-rendering — block via Tenant Allow/Block List."
adaptation_notes: "AH-native. Sender local-part length + embedded URL/keyword markers. Intra-org and Inbound included (campaign was largely inbound but spoofed senders may appear intra-org). Tune SenderLocalLen threshold based on org's mail patterns."
-->
```kql
// Q1 2026 Email Threat Landscape: Keyword-stuffed sender usernames (March 17 HTML campaign)
let lookback = 30d;
let knownArtifactKeywords = dynamic(["awstrack.me","listenerId","externalClickUrl","Noreply-/","Noreply_","_-AAP","spectrumbusiness","zoom.nl","amazonaws"]);
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection in ("Inbound","Intra-org")
| extend SenderLocal = tostring(split(SenderFromAddress, "@")[0])
| extend SenderLocalLen = strlen(SenderLocal)
| extend HasEmbeddedKeyword = SenderLocal has_any (knownArtifactKeywords)
| extend HasUrlChars = SenderLocal contains "/" or SenderLocal contains "?" or SenderLocal contains "=" or SenderLocal contains "%2F"
| where SenderLocalLen >= 60 or HasEmbeddedKeyword or HasUrlChars
| summarize Count=count(), Recipients=dcount(RecipientEmailAddress),
            SampleSenders=make_set(SenderFromAddress, 10), MaxLen=max(SenderLocalLen),
            Subjects=make_set(Subject, 10), Detections=make_set(DetectionMethods, 5),
            Deliveries=make_set(DeliveryAction, 5)
            by SenderIPv4
| order by Count desc
| take 50
```

**Tuning:**
- High-confidence: `HasEmbeddedKeyword == true` — these are PhaaS tooling artefacts and rarely appear in legitimate mail.
- `SenderLocalLen >= 60` alone has **moderate FP risk** — some legitimate transactional/notification systems use long local-parts. Combine with `HasEmbeddedKeyword` or `HasUrlChars` for precision.
- For high-volume organisations, raise the length threshold to 100 to focus on the campaign's most extreme samples.

---

## Query 7: No-Attachment + URL Phish — Body-Embedded QR Proxy

The Q1 2026 article reports **body-embedded QR codes surged 336% in March**. There is no native MDO `DetectionMethod` for "body-embedded QR" in `EmailEvents`, so this query uses a **structural proxy**: inbound emails classified as Phish where `AttachmentCount == 0` but `UrlCount > 0`. Body-embedded QR codes are typically delivered as inline images referencing an external host — and the underlying URL is what MDO's Phish detection actually evaluates.

<!-- cd-metadata
cd_ready: true
schedule: "3H"
category: "InitialAccess"
title: "Inbound zero-attachment phishing email with embedded URL — possible body-embedded QR"
impactedAssets:
  - type: "mailbox"
    identifier: "recipientEmailAddress"
recommendedActions: "Render the email in Threat Explorer to confirm whether body contains an inline QR image. If so, notify the recipient that mobile QR scans bypass email Safe Links and check for any subsequent sign-in anomaly from a mobile device."
adaptation_notes: "AH-native. Structural proxy (no native QR detection method on EmailEvents). The 'no attachment + URL + phish' pattern catches both true body-embedded QR campaigns and traditional link-based phish - distinguishing them requires Threat Explorer rendering."
-->
```kql
// Q1 2026 Email Threat Landscape: No-attachment + URL phish (body-embedded QR proxy)
let lookback = 30d;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish"
| where AttachmentCount == 0
| where UrlCount > 0
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderIPv4, RecipientEmailAddress,
          Subject, UrlCount, DeliveryAction, DetectionMethods, ThreatNames
| order by Timestamp desc
| take 200
```

**Tuning:**
- **Focus on Delivered:** `| where DeliveryAction == "Delivered"` — these are the messages your users actually saw.
- Pair with mobile sign-in anomalies (`SigninLogs` with `DeviceDetail.operatingSystem` in iOS/Android) for the recipient within 60 minutes — strongest body-embedded-QR compromise indicator.
- Many true positives from this query are **standard link phishing**, not QR-specific. The technique distinction matters for user awareness messaging but not for triage priority.

---

## Query 8: User Click-Through on Tycoon2FA-Style TLD URLs (Compromise Check)

Identifies users who **clicked through** Safe Links on URLs with the Q1 2026 Tycoon2FA emerging TLDs. Click-through after Safe Links warning is one of the strongest pre-compromise indicators — the user has bypassed protection and the AiTM proxy is harvesting credentials.

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "User clicked through Tycoon2FA-style URL: {{AccountUpn}}"
impactedAssets:
  - type: "user"
    identifier: "accountUpn"
recommendedActions: "Treat as suspected AiTM compromise. Revoke refresh tokens for the user immediately. Force password reset and re-register MFA. Check OfficeActivity for inbox rules and SigninLogs for non-interactive token replay from foreign IPs."
adaptation_notes: "AH-native. ActionType values: ClickAllowed (user proceeded after warning), ClickBlocked, ClickBlockedByTenantPolicy. Filter to ClickAllowed for highest-value alerts. URL TLD extracted via parse_url."
-->
```kql
// Q1 2026 Email Threat Landscape: User click-through on Tycoon2FA-style TLD URLs
let lookback = 30d;
let suspiciousTlds = dynamic(["ru","digital","business","contractors","ceo","company"]);
UrlClickEvents
| where Timestamp > ago(lookback)
| extend Host = tolower(tostring(parse_url(Url).Host))
| extend tld = tolower(tostring(split(Host, ".")[-1]))
| where tld in (suspiciousTlds)
| where ActionType in~ ("ClickAllowed","UrlClickThrough")
| project Timestamp, AccountUpn, Url, Host, tld, IPAddress, ActionType, NetworkMessageId, Workload
| order by Timestamp desc
| take 200
```

**Tuning:**
- `ActionType in~ ("ClickAllowed","UrlClickThrough")` is the high-value filter — anything else means Safe Links blocked the click.
- Pair with `EntraIdSignInEvents` for the same `AccountUpn` in the next 60 minutes; an OfficeHome sign-in from an Axios user-agent or unusual country = high-confidence AiTM compromise (cross-ref [`storm_2755_payroll_pirate.md`](./storm_2755_payroll_pirate.md) Queries 1 & 3).
- In tenants running Microsoft Attack Simulation Training (or any phishing-simulation platform), exclude the simulator's known click-source IP ranges before alerting to avoid false positives on training campaigns.

---

## References

- Microsoft Threat Intelligence — [Email threat landscape: Q1 2026 trends and insights (April 30, 2026)](https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/)
- Microsoft Threat Intelligence — [Inside Tycoon2FA: how a leading AiTM phishing kit operated at scale (March 4, 2026)](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)
- Microsoft On the Issues — [Microsoft disrupts cybercrime — RedVDS (January 14, 2026)](https://blogs.microsoft.com/on-the-issues/2026/01/14/microsoft-disrupts-cybercrime/)
- Microsoft On the Issues — [How a global coalition disrupted Tycoon (March 4, 2026)](https://blogs.microsoft.com/on-the-issues/2026/03/04/how-a-global-coalition-disrupted-tycoon/)
- Microsoft Defender Threat Analytics — Activity Profiles: Email threat landscape (Jan/Feb/March 2026), Tool Profile: Tycoon2FA, Actor Profile: Storm-1747, Technique Profile: QR code phishing
- Companion files: [`queries/email/email_threat_detection.md`](../../email/email_threat_detection.md), [`queries/identity/aitm_threat_detection.md`](../../identity/aitm_threat_detection.md), [`queries/threat-intelligence/2026-04/storm_2755_payroll_pirate.md`](./storm_2755_payroll_pirate.md)
