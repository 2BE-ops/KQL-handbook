# KQL Handbook: Microsoft Defender XDR Advanced Hunting

A working collection of KQL for Defender XDR Advanced Hunting. It covers standalone hunts, custom detection candidates, and one fully developed chapter on detection engineering and incident response for SharePoint share-lure phishing.

Everything here targets Advanced Hunting only. There is no Sentinel dependency. The queries were written against the platform's real limits and exercised against a live tenant, then sanitised for publication. Org names, tenant slugs, domains and classification lists are placeholders (`contoso`, `fabrikam`, and so on). Thresholds are real-world starting points, so tune them for your own tenant.

## Contents

| Folder | What's inside |
|---|---|
| [sharepoint-phishing/](sharepoint-phishing/README.md) | **The deep chapter.** SharePoint and OneDrive share-lure defence in two tracks: staged custom detections (an NRT tripwire plus an hourly behavioural rule) fed by a weekly tenant-classification pipeline, and a numbered incident response flow (triage, contain, verify, compromise check, internal spread, attacker sweep). Every step hands the next one paste-ready key cells |
| [defence-evasion/](defence-evasion/) | Three hunts. [amsi-bypass-attempts.kql](defence-evasion/amsi-bypass-attempts.kql) chases AMSI patching, downgrade and unhooking across six telemetry sources (script blocks, encoded commands, PSv2 downgrade, registry, DLL sideloading with signer enrichment, Set-MpPreference) and ranks findings by severity. [firewall-flush-hunt.kql](defence-evasion/firewall-flush-hunt.kql) hunts Linux `iptables`/`nft` flushes, and severity follows from which chains got flushed. [isolated-host-flush-rule.kql](defence-evasion/isolated-host-flush-rule.kql) is a custom detection candidate for a firewall flush on a host MDE has isolated, which usually means someone is breaking containment |
| [ai-agent-hunting/](ai-agent-hunting/) | [autonomous-agent-risk-hunt.kql](ai-agent-hunting/autonomous-agent-risk-hunt.kql) builds a risk-tiered inventory of AI coding agents (Claude Code, Codex, Cursor, aider and friends): approval-bypass flags, auto-accept modes, headless runs, elevation, automation parents, with the matched flags extracted as evidence |
| [identity-triage/](identity-triage/) | [user-alert-summary.kql](identity-triage/user-alert-summary.kql) collapses all alert evidence into one row per user, with weighted risk scoring and a kill-chain-breadth bonus. Identity resolves against three keys (objectId, UPN, `DOMAIN\sam`) in that order, so an empty join key can't stamp one account's alerts onto another |
| [device-attribution/](device-attribution/) | [last-known-user-by-device-id.kql](device-attribution/last-known-user-by-device-id.kql) and [last-known-user-by-device-name.kql](device-attribution/last-known-user-by-device-name.kql) answer who last used a device. They union logon, process and network telemetry, so a stale `DeviceLogonEvents` feed can't leave the question unanswered |

## Platform constraints to know first

These shape every query in the handbook.

1. **30-day retention.** Advanced Hunting keeps at most 30 days of raw data. Every baseline window has to fit inside `ago(30d)`. A baseline that also excludes the detection window, for example `between (ago(30d) .. ago(7d))`, only ever sees about 23 days. A threshold like "seen over 60+ days" can never be met, and the query empties out silently.
2. **Custom detection cadence.** The Continuous (NRT) frequency only supports simple single-table queries. Anything with a join runs at best **Every 1 hour**. Overlapping windows are safe: Defender does not re-alert on rows (ReportId plus Timestamp) it has already alerted on.
3. **`toscalar` and `make_set` caps.** A baseline built with `summarize make_set(x, N)` truncates silently at N. Size N generously and leave a comment saying so.

## Conventions

- **Canonical SharePoint tenant names.** Strip the `-my` suffix at extraction time so `contoso` and `contoso-my` count as one tenant. The standard pattern:
  `extract(@"https?://([a-z0-9-]+?)(?:-my)?\.sharepoint\.com", 1, tolower(Url))`
  Allowlists hold canonical names only, never `-my` entries.
- **Sign-in data** comes from `EntraIdSignInEvents`. `AADSignInEventsBeta` is deprecated, so don't reintroduce it.
- **One file is one query with one output.** No comment-swap blocks and no "uncomment this section" alternates. Behaviour toggles are `let` tunables at the top of the file. Optional companion queries live below the main query, clearly fenced.
- **Small-key linking.** Queries chain through short typed inputs: a tenant name, a sharer path segment, a few UPNs. Never paste message-ID arrays from one query to the next. Each query re-derives its working set from those keys and emits the next query's keys as ready-made `PasteKeys`/`PasteUpn` cells.
- **Actionable outputs.** Containment queries emit one row per entity with the columns that enable Advanced Hunting's **Take actions** button (`NetworkMessageId` + `RecipientEmailAddress` for email, `AccountObjectId` for users). Never aggregate those output paths. A `summarize` kills the action button.
- **Chapter layout.** Each chapter runs in two tracks. `detection/` holds the deployable rules (`0a`/`0b`) plus the numbered pipeline that feeds them. `incident/` is the ordered flow for an active incident. Rule and triage files come in twin pairs, and the mirror rule applies: logic and list changes go into both files. Queries are read-only, actions stay manual, and malicious-list entries alert but never block.
- **Shared lists** live in each chapter's `00-shared-lists.kql`. Advanced Hunting has no include mechanism, so copy the block into the query. When you change a list, re-paste it everywhere. Each query header says which lists it embeds.
- **Enum values are exact.** `DeliveryAction` is one of `Delivered | Junked | Blocked | Replaced`. `DeliveryLocation` values include `Inbox/folder`, `Junk folder`, `Quarantine`, `Deleted items folder`. Never match with `== "Inbox"`; use `startswith` or `has`.
- **Priorities.** P0 means confirmed user compromise is likely, P1 means act now, P2 means same day, P3 sits in the review queue, and P4/P5 are informational.
- **File naming.** Files are named `NN-verb-topic.kql` and numbered in workflow order. A `0` prefix marks foundation or product files rather than a flow step: `00-shared-lists` is a shared asset, and `0a`/`0b` are the deployable rules the numbered pipeline serves. Letter suffixes (`1a`/`1b`, `3a`/`3b`) mark alternative postures or twin pairs, not sequence.
- Prefer `has` over `contains` for indexed terms, prefer `take_any()` over the deprecated `any()`, and put `Timestamp` filters first in every table reference.

## Roadmap

Candidate next chapters: OAuth consent-grant phishing, AiTM and suspicious sign-in follow-up, inbox-rule persistence, QR-code phishing, malicious attachments.

## License

[MIT](LICENSE). Use anything here. Just verify enum values and schema assumptions against your own tenant first, see each chapter's `_probes.kql`.
