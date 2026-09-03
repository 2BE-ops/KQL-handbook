# detection/: Track 1, build and run the custom detection rules

Two staged rules plus the weekly list program that keeps them sharp and quiet. Both rules are **staged, NOT deployed**. Deployment is a deliberate, separate decision: the legitimate sender and receiver population is large, and nothing goes live until the lists and thresholds have proven themselves. Until then, run the rules manually.

**Naming:** `0a` and `0b` are the products, meaning the deployable rules. They are not flow steps. The `0` prefix means foundation, the same convention as the chapter's `00-shared-lists`. The weekly list pipeline is `1`, then `2`, then `3`, and those numbers ARE the running order. The a/b letters pair each rule with its human twin in `incident/` (0a pairs with incident/1a, 0b pairs with incident/1b).

| File | Job | Cadence when deployed |
|---|---|---|
| [0a-malicious-tenant-rule.kql](0a-malicious-tenant-rule.kql) | **Tripwire rule.** Single-table query over `EmailUrlInfo`: any mail URL pointing at a `maliciousTenants` entry alerts at delivery time, before anyone clicks | **Continuous (NRT)** |
| [0b-behavioural-rule.kql](0b-behavioural-rule.kql) | **Behavioural rule.** The original detector, bug-fixed, with list hooks. Runtime baselines: 28d clean-receive, outbound partner corroboration, cold uploaders, plus burst / per-file fan-out / subject-repetition / lookalike / impersonation / click gates. Emits per-recipient rows, never aggregated, because the rule schema needs row-shaped output. The same rows support email Take actions when run manually | Every 1 hour |
| [1-tenant-review-queue.kql](1-tenant-review-queue.kql) | Weekly inventory of unlisted tenants: evidence plus a `ReviewHint`, and a ready `TrustedPasteLine` when the clean baseline holds | Weekly, manual |
| [2-tenant-dossier.kql](2-tenant-dossier.kql) | Everything about one tenant on one screen. Vets every candidate before listing. The per-sharer section resolves the one-bad-user-on-a-legit-tenant case | Per candidate, manual |
| [3-malicious-candidates.kql](3-malicious-candidates.kql) | Hard bad evidence (threat verdicts, ZAP, delivery blocks, blocked clicks) turned into provenance-formatted `PasteLine` entries | Weekly, and after incidents |

**Division of labour:** 0a covers known-bad instantly. 0b covers unknowns behaviourally every hour (clicks, bursts, cold uploaders, impersonation). Each rule has a per-tenant human twin in `incident/`, and the mirror rule applies: logic and list changes go into both members of a pair.

**The list loop:** 1 (queue), then 2 (vet each candidate), then paste. Trusted lines come from 1's `TrustedPasteLine`, malicious lines from 3, into [00-shared-lists](../00-shared-lists.kql), then get re-pasted into every consumer (each file's `Embeds:` header line says what it carries). 0a's alert volume is directly proportional to the malicious list: an empty list means a silent rule. The list program is what turns 0b-era confusion into 0a-era speed.

## Cadence reality

- Defender's **Continuous (NRT)** frequency accepts single-table queries only: no `join`, `union` or `summarize`. That's why 0a carries no recipient or subject enrichment and no unknown-tenant gates. Those need joins, so they live in 0b (hourly) and the manual incident queries.
- 0b joins three tables, so **Every 1 hour is its floor**. Overlap between runs is safe: Defender doesn't re-alert on rows (ReportId plus Timestamp) it has already alerted on.

## NRT fallback variant (click-time tripwire)

`EmailUrlInfo` has no account, device or recipient column. If rule creation rejects 0a for lacking an impacted-asset column, use this instead. Same list, same single-table constraint, `AccountUpn` present, but it fires on click instead of at delivery:

```kusto
let maliciousTenants = dynamic([]);   // sync from 00-shared-lists.kql
UrlClickEvents
| where Workload == "Email"
| where Url has "sharepoint.com"
| extend SpTenant = extract(@"https?://([a-z0-9-]+?)(?:-my)?\.sharepoint\.com", 1, tolower(Url))
| where isnotempty(SpTenant)
| where SpTenant in (maliciousTenants)
| extend Classification = "Malicious", Severity = "P0-Critical"
| project Timestamp, ReportId, NetworkMessageId, AccountUpn, IPAddress,
          Url, SpTenant, ActionType, IsClickedThrough, Classification, Severity
```

## Deployment procedure (when the time comes)

1. Run the rule query manually over 1d and 7d, and review volume and false positives. 0a's volume is directly proportional to the malicious list, so preview every list addition with a manual run before it goes live. For 0b, review each gate's contribution before trusting the thresholds.
2. Create the rule as "STAGING - \<name\>" with no response actions, and let it run 48 to 72 hours alongside manual practice (0a on Continuous, 0b on Every 1 hour).
3. Only then rename to production and consider response actions. Start with none. Email quarantine comes only after the false-positive record is clean, and note that 0a cannot take email actions at all because `EmailUrlInfo` has no recipient column. Containment stays in incident/2 with the tenant key.
4. Schema: 0b already carries the full required schema including `NetworkMessageId` + `RecipientEmailAddress`. 0a carries `Timestamp`/`ReportId`/`NetworkMessageId`; see its header caveat about impacted-asset columns.
5. Keep list edits flowing. 00-shared-lists is the source of truth. After editing lists there, re-paste into both rule files and their incident twins.
