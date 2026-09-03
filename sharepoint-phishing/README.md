# SharePoint Phishing

This chapter covers finding and containing SharePoint/OneDrive share-lure campaigns. The scope is real `*.sharepoint.com` lures only. Every query is read-only. Actions happen manually through the **Take actions** button in Advanced Hunting, and nothing auto-blocks.

The chapter has two tracks and one shared asset:

| | Folder | Job |
|---|---|---|
| **Track 1** | [detection/](detection/README.md) | Build and run the custom detection rules (0a malicious-tenant NRT tripwire plus 0b hourly behavioural), along with the weekly list pipeline (1, then 2, then 3) that feeds them |
| **Track 2** | [incident/](incident) | Investigate an active incident: triage (1a/1b), contain (2), verify purge (3a), compromise check (4), chain analysis and victim sweep (7/6), internal spread (5), verify eviction (3b) |
| shared | [00-shared-lists.kql](00-shared-lists.kql), [_probes.kql](_probes.kql) | The tenant classification lists both tracks embed, and schema probes P1 through P9 |

## Track 1: detection (the rules plus the pipeline that feeds them)

Naming first, because it trips people up. `0a` and `0b` are the products, meaning the deployable rules. A `0` prefix means foundation rather than a flow step, same convention as `00-shared-lists`. The weekly list pipeline is `1`, then `2`, then `3`, and those numbers are the running order. Two staged rules, two postures:

- **[detection/0a](detection/0a-malicious-tenant-rule.kql)** is the tripwire. It's a single-table query over `EmailUrlInfo`, so it qualifies for Continuous (NRT), and it alerts at delivery time on any tenant on the malicious list. It's fast because the lists are already vetted.
- **[detection/0b](detection/0b-behavioural-rule.kql)** is the behavioural rule, the original detector with the bugs fixed. It builds runtime baselines and applies burst, fan-out, impersonation and click gates, and it emits one row per recipient because the rule schema needs row-shaped output. It runs hourly at best. This rule covers whatever the lists haven't classified yet.

Each rule has a per-tenant human twin in incident/ (0a pairs with incident/1a, 0b pairs with incident/1b). The mirror rule applies: logic and list changes go into both members of a pair. The pipeline keeps the lists sharp:

```
detection/1 REVIEW QUEUE (weekly, 7d)   <- evidence + ReviewHint + TrustedPasteLine
   |  vet each candidate
   v
detection/2 TENANT DOSSIER (one tenant, 30d, per-sharer section)
   |  malicious side
   v
detection/3 MALICIOUS CANDIDATES        <- hard evidence -> PasteLine
   |
   v
00-shared-lists ──re-paste──▶ consumers: detection/0a/0b · incident/1a/1b · detection/1 · detection/3
```

House rules for the lists: every entry needs a provenance comment. Trusted doesn't mean immune, since incident/1a surfaces single-sharer fan-out inside trusted tenants and 0b's pivoted gates catch it behaviourally. Malicious entries alert, they never block. The lists outlive the 30-day retention window, they are the chapter's memory. The pipeline turns 0b-era confusion into 0a-era speed. Both rules are staged rather than deployed; the deployment plan lives in [detection/README.md](detection/README.md).

## Track 2: incident (an active campaign)

```
detection/0a or 0b alert names the tenant ────────┐ (skip triage)
user report ─▶ 1A TRIAGE (mature lists)           │
           or  1B TRIAGE (confusing picture)      │  <- both: ONE ROW PER TENANT
   │ copy the PasteKeys cell (targetTenant + targetSharer, ready-made)
   ▼
2 DEEP DIVE (1 row per mailbox copy) ─▶ select rows -> Take actions -> purge
   ▼
3A VERIFY PURGE (same keys; re-run until "Fully remediated")
   ▼
4 CHECK COMPROMISE (same keys; 1 row per clicker; AccountObjectId for user actions)
   │ P0/P1 rows: evict (reset password / revoke sessions / remove persistence),
   │ and copy their PasteUpn cells
   ├─▶ 7 POST-CLICK CHAIN: harvest or payload? finds the campaign's REAL IOC (the host)
   ├─▶ 6 VICTIM SWEEP: attacker IPs -> the victims whose clicks were never logged
   ▼
5 CONTAIN INTERNAL SPREAD (1 row per internal copy) ─▶ Take actions -> purge
   │  then 3A again with 5's PasteKeys (own tenant + suspect sharer)
   ▼
3B VERIFY EVICTION (suspectUpns; re-run until every account reads OK)

Close only when 3A AND 3B both read clean. Purging every copy of a lure
from an account the attacker still holds achieves nothing.
```

Linking stays on small typed keys, pre-formatted for speed. 1A and 1B emit a `PasteKeys` cell with ready `let targetTenant` / `targetSharer` statements that paste straight into 2, 3a, 4 or 7 (1B only auto-fills the sharer when it's unambiguous). Queries 4 and 6 emit `PasteUpn` cells that feed 5's `suspectUpns` and 3b's. Query 5 emits `PasteKeys` back to 3a for the internal-wave verification. Queries 4 and 7 also accept `targetSender` and `targetSubject`, so they work for any confirmed-malicious phish shape, not just SharePoint lures. There is no message-ID pasting and no comment swapping anywhere.

**Actionable-output rule:** files 2 and 5 carry per-row `NetworkMessageId` + `RecipientEmailAddress` (email Take actions). Files 4 and 6 carry `AccountObjectId` (user Take actions). The detection/0a and 0b files carry the rule schema, and 0b's per-recipient rows also support Take actions when run manually. Never add a `summarize` to those output paths.

**The two campaign shapes**

- **Unknown tenant, everything bad.** The common case. 1A or 1B names the tenant, then you run 2 with `targetTenant` alone.
- **One compromised user on a legit tenant.** The edge case, but it's always possible. The tell is single-sharer fan-out: `TopSharer` / `TopSharerRecipients` in 1A and detection/1, `Sharers` in 1B. Trusted tenants only surface in 1A through this signal, and it trips 1B's pivoted gates. Run 2, 3a and 4 with both `targetTenant` and `targetSharer` so containment never touches the tenant's legitimate correspondence.

## Tuning knobs

| Knob | Where | Default |
|---|---|---|
| `lookback` / `detection_window` | incident/1a, 1b (1d); detection/1 (7d); incident/2 through 7 (7d, up to 30d) | - |
| `sharerFanoutAlert` | incident/1a, detection/1 | 10 |
| `trustedSharerFanoutAlert` / `lookalikeThreshold` (context cols only) | incident/1a | 25 / 0.85 |
| 1B gates: `burst_recipients` / `fanout_per_file` / `untrusted_subj_rep` / `pivoted_*` | incident/1b + detection/0b (mirror rule applies) | 20 / 10 / 20 / 50+10 |
| `maliciousTenants` size | detection/0a (NRT tripwire) | empty means silent |
| Baseline thresholds (`LooksEstablished` / `TrustedPasteLine`) | detection/1 | 10 msgs / 3 recip / 3 senders / 14d span |
| `minBadEvidence` | detection/3 | 2 |
| `postClickWindow` / `persistWindow` / `mailBurstAlert` / `shareBurstAlert` | incident/4 | 24h / 72h / 20 / 10 |
| `shareThreshold` (detector mode) | incident/5 | 15 |
| `baselineDays` (shared-infrastructure check) | incident/6 | 30d |
| `chainWindow` | incident/7 | 30m |

Unverified schema assumptions reference probes P1 through P9 in [_probes.kql](_probes.kql).

## Design history

This chapter got to its current shape through seven documented working iterations. The record stays because the reasoning is part of the handbook:

1. **Audit.** The original behavioural detector was checked against platform reality. It had a 90-day baseline under 30-day retention (structurally empty), a `FinalLocation == "Inbox"` comparison that could never match (the real value is `Inbox/folder`), invalid `DeliveryAction` literals, and four inert expressions. All fixed or retired.
2. **First two-track split.** Chained by pasted message-ID arrays. Retired, because it needed far too much pasting to operate under pressure. That failure produced the small-key linking convention.
3. **Lean rework.** Per-tenant triage first, deep-dive rows that work with Take actions, small-key linking, no comment-swap alternates. Detection and list machinery got parked until it earned its keep.
4. **1A/1B split and the list program.** The behavioural detector outperformed its leaner replacement and came back as 1B with only objective bug fixes: `DeliveredAsSpam` became `Junked`, a constant `dcount(startofday(now()))` in the uploader baseline, phrase-vs-word impersonation matching that could never match, an `arg_max` column-naming bug, nested-array vs string `set_intersect`, and clicks scoped to SharePoint URLs. Tenant-level lists graduated into 00-shared-lists with a build pipeline (queue, then dossier, then paste-ready candidates).
5. **Streamline.** 21 files became 12. The heaviest never-deployed queries were deleted and their cheap high-value gates folded into the review queue. Single-purpose queries with no home in either track were dropped.
6. **Twin restore and handoffs.** The behavioural pair returned as proper rule/triage twins (0b as a per-recipient rule schema, 1b as a per-tenant triage roll-up) under the mirror rule. Lookalike-tenant similarity was demoted to context columns, since attackers rarely bother with it and subject impersonation is the realistic signal. `PasteKeys` and `PasteUpn` cells were added. Naming settled as 0a/0b for products and 1-2-3 for the pipeline.
7. **Close the loop.** Verification split into purge (3a) and eviction (3b), and a campaign only closes when both read clean. The backwards-looking victim sweep (6) and post-click chain analysis (7) were added, because forward-from-click queries only ever find victims whose clicks got logged. Internal-spread containment (5) was rebuilt with seeded and detector modes. Probes P6 through P9 were recorded.
