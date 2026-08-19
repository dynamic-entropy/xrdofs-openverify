# OpenVerify Prometheus metrics

Metrics are written in Prometheus text exposition format via
`XRD_OPENVERIFY_METRICS_PATH` (node_exporter `textfile_collector`).

Environment variables are summarized in `include/OpenVerifyMetrics.hh`.
Rucio-first locate (`XRD_OPENVERIFY_RUCIO=1`) adds lookup/source counters below.

## Grafana dashboards

Importable JSON (Grafana → Dashboards → Import; pick your Prometheus datasource):

| File | Audience |
|------|----------|
| [`docs/grafana/openverify-developer.json`](grafana/openverify-developer.json) | Plugin internals: cache, single-flight, queue, delay histogram |
| [`docs/grafana/openverify-cms-ops.json`](grafana/openverify-cms-ops.json) | CMS XRootD OpenVerify: client AAA, OV overview, separate Rucio/cmsd probe errors, locate path, site health |

**CMS ops variables** (top of dashboard):

| Variable | Use |
|----------|-----|
| Redirector instance | Which `xrootd_instance` daemon(s) |
| Rate interval | Bin for `rate()` panels (`auto`, `1m`, `5m`, `1h`, …) |
| Site | Multi-select `host` from `verify_failures_total` and `host_busy_total` |
| Error reason | Multi-select `reason` (scoped to selected sites) |
| Delay outcome | Filter redirect-delay heatmap by outcome |

Sections:

- **Rucio / cmsd verify errors** — live probe failures by `source` (Site / Error reason filters)
- **How opens were located** — Rucio soft-fail, exhaust recovery context, accept path / attempt

New series appear after deploying a build that includes latency / avoid / site
export, and after at least one redirect has been handled (site gauges appear
once a host has a verify outcome recorded).

## Always-present series

- `xrootd_openverify_cache_lookups_total` (`miss` | `hit_positive` | `hit_negative`)
- `xrootd_openverify_runs_total` (`success` | `failure`)
- `xrootd_openverify_queue_admissions_total` (`admitted` | `queue_full` | `queue_timeout` | `host_busy`)
- `xrootd_openverify_singleflight_requests_total` (`leader` | `follower`)
- `xrootd_openverify_redirects_handled_total`
- `xrootd_openverify_redirects_avoided_total` (`quarantine` | `negative_cache` | `host_busy`)
- `xrootd_openverify_redirect_delay_seconds` (histogram by `outcome`; total hop = queue + RTT on miss)
- `xrootd_openverify_queue_wait_seconds` (histogram by `result` = `admitted` | `timeout`)
- `xrootd_openverify_verify_rtt_seconds` (histogram by `result` = `success` | `failure`)
- `xrootd_openverify_cmsd_stalls_total` / `cmsd_stall_seconds_total`
- `xrootd_openverify_cmsd_stall_seconds` (histogram of individual stall durations)
- `xrootd_openverify_accepted_total` (`source` = `rucio` \| `cmsd` \| `xrootd`; cmsd `attempt` = redirect candidate `1`|`2`|`3`; rucio `attempt` = ordered replica that passed verify `1`…`4`|`5+`; xrootd `attempt` = `1` for static fallback)
- `xrootd_openverify_static_fallback_total` (`fallback` = `transit` — static `xrootd.redirect` ENOENT hop, no verify)
- `xrootd_openverify_retry_exhausted_total`
- `xrootd_openverify_rucio_lookups_total` (`result` = `ok` \| `empty` \| `auth_error` \| `timeout` \| `error` \| `skipped`; `empty` = no replicas; `skipped` = ignore-prefix)
- `xrootd_openverify_rucio_list_cache_total` (`result` = `hit` \| `miss` — `(lfn, scheme)` LRU; not recorded for disabled/skipped)
- `xrootd_openverify_rucio_list_cache_entries` (gauge: current LRU occupancy)
- `xrootd_openverify_rucio_candidates_total`
- `xrootd_openverify_rucio_exhausted_total` (lookup `ok` but no PFN accepted → cmsd fallthrough)
- `xrootd_openverify_location_source_total` (`source` = `rucio` \| `cmsd` \| `xrootd` — locate path / static fallback, not destination site)
- `xrootd_openverify_locate_rtt_seconds` (histogram by `source` = `rucio` \| `cmsd`)

**Appear after first event:**

- `xrootd_openverify_verify_failures_total` — first verify failure (**includes per-site timeouts**)
- `xrootd_openverify_host_busy_total` — first per-host inflight-cap reject (`host`, `port`)
- `xrootd_openverify_site_*` — first per-site verify success/failure
- `xrootd_openverify_failsafe_active` / `failsafe_trips_total` / `failsafe_recent_sites` / `failsafe_max_sites` — exported with site gauges (mass-quarantine circuit breaker)

Optional label **`xrootd_instance`** when `XRD_OPENVERIFY_METRICS_INSTANCE` is set.

Use **`rate()`** / **`increase()`** on counters; gauges (`site_ewma_health`,
`site_healthy`, `failsafe_active`, `failsafe_recent_sites`) are instantaneous.

---

## Metric reference

### Cache / verify / queue / single-flight

Same meanings as before:

| Metric | Labels | Meaning |
|--------|--------|---------|
| `cache_lookups_total` | `result` | Cache consult on redirect |
| `runs_total` | `result` | Actual `open_verify` after miss |
| `queue_admissions_total` | `result` | Inflight queue gate (`admitted` \| `queue_full` \| `queue_timeout` \| `host_busy`) |
| `host_busy_total` | `host`,`port` | Leader rejected: this host already held 50% of `MAX_INFLIGHT` |
| `singleflight_requests_total` | `role` | Leader runs verify; follower waits |
| `verify_failures_total` | `source`,`host`,`port`,`reason` | Failed verifies by locate path (`rucio`\|`cmsd`) and target |

`reason` includes `operation_expired`, `socket_timeout`, `auth_failed`,
`permission_denied`, `redirect_limit`, … (see `ClassifyXrdClStatus`).

### cmsd lookup stalls (not per-site)

cmsd returns `SFS_STALL` (positive seconds) **before** a redirect target is
known, so these counters have no `host` label — they measure federation lookup
delay, not “stall at site X”. OpenVerify passes the stall through to the
protocol layer (`kXR_wait` for root; Bridge redrive for HTTP) rather than
sleeping in the plugin.

| Metric | Labels | Meaning |
|--------|--------|---------|
| `cmsd_stalls_total` | (instance) | Number of stall responses passed to the client |
| `cmsd_stall_seconds_total` | (instance) | Sum of stall seconds requested |
| `cmsd_stall_seconds` | histogram | Distribution of individual stall durations |

Histogram buckets (seconds, upper-inclusive): `1`, `2`, `3`, `5`, `10`, `15`,
`30`, `60`, `+Inf`.

Average stall duration:

```promql
rate(xrootd_openverify_cmsd_stall_seconds_total[5m])
/
clamp_min(rate(xrootd_openverify_cmsd_stalls_total[5m]), 1e-9)
```

Heatmap / bin rates:

```promql
sum by (le) (rate(xrootd_openverify_cmsd_stall_seconds_bucket[5m]))
```

### Rucio-first locate

When `XRD_OPENVERIFY_RUCIO=1`, OpenVerify queries CMS Rucio before cmsd.
Soft-fails (empty / auth / timeout / error) and all-candidates-failed fall back
to cmsd. LFNs matching `XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX` skip the REST call
(`result=skipped`) and also fall through to cmsd. Tape PFNs are excluded from the candidate list (`type=TAPE` or RSE
name ending in `_Tape`) before try-order. PFN try-order is selected by
`XRD_OPENVERIFY_RUCIO_SELECT` (`random` default; `priority`; `geoip` reserved)
— subsequent PFNs are tried only after the current verify fails. See the
**Rucio-first locate** row on
[`openverify-cms-ops.json`](grafana/openverify-cms-ops.json).

| Metric | Labels | Meaning |
|--------|--------|---------|
| `rucio_lookups_total` | `result=ok\|empty\|auth_error\|timeout\|error\|skipped` | `list_replicas` outcome; `empty` = no replicas (soft-fail); `skipped` = ignore-prefix (no REST call) |
| `rucio_list_cache_total` | `result=hit\|miss` | LRU of `(lfn, scheme)` → PFN list (TTL `XRD_OPENVERIFY_RUCIO_CACHE_TTL`) |
| `rucio_list_cache_entries` | (instance) | Current LRU occupancy |
| `rucio_candidates_total` | (instance) | PFN candidates from successful lookups |
| `rucio_exhausted_total` | (instance) | Lookup `ok` but no PFN accepted (verify/cache/quarantine/`tried=`); fall through to cmsd |
| `rucio_exhausted_recovered_total` | (instance) | Subset of exhaust where **cmsd openverify then accepted** (Rucio failed, cmsd saved the open) |
| `rucio_cmsd_compare_total` | `result=overlap\|catalog_disagree` | Diagnostic split of recovered by hostname vs Rucio list (sum = recovered) |
| `location_source_total` | `source=rucio\|cmsd\|xrootd` | Accepted open’s locate path (`xrootd` = successful static `xrootd.redirect` pass-through such as transit; **not an error**) |
| `static_fallback_total` | `fallback=transit` | Successful static ENOENT redirect accepted without verify (not an error) |

Primary fallthrough success signal: `recovered / exhausted` (how often cmsd
openverify succeeds after every Rucio PFN failed). Soft-fail→cmsd is **not**
included (Rucio never produced a tryable list). Diagnostic logs
`openverify cmsd after rucio exhaust: …` still split recovered into
`overlap` vs `catalog_disagree`.

When Rucio is enabled, cmsd + static-fallback accepts should satisfy:

`cmsd-path + xrootd-path ≤ soft-fail + rucio_exhausted`

(`soft-fail` = `empty|auth_error|timeout|error`; usually strictly smaller when cmsd also fails).
Static `xrootd` accepts (transit) are successful pass-throughs, not errors.

```promql
# Share of verified accepts from Rucio (exclude static xrootd.redirect fallback —
# transit pass-through is a successful accept, not a locate failure)
sum(rate(xrootd_openverify_location_source_total{source="rucio"}[5m]))
/
clamp_min(sum(rate(xrootd_openverify_location_source_total{source=~"rucio|cmsd"}[5m])), 1e-9)

# Soft-fail (no usable list_replicas — includes empty replica list)
sum(rate(xrootd_openverify_rucio_lookups_total{result=~"empty|auth_error|timeout|error"}[5m]))

# ok-but-no-accept fallthrough
sum(rate(xrootd_openverify_rucio_exhausted_total[5m]))

# cmsd openverify succeeded after that fallthrough
sum(rate(xrootd_openverify_rucio_exhausted_recovered_total[5m]))

# recovery fraction (cmsd saved the open)
sum(rate(xrootd_openverify_rucio_exhausted_recovered_total[5m]))
/
clamp_min(sum(rate(xrootd_openverify_rucio_exhausted_total[5m])), 1e-9)

# Bound check (expect ≤ 1 when Rucio is always on). Include static fallback accepts
# (source=xrootd) — those often follow empty soft-fail and are not errors.
sum(rate(xrootd_openverify_location_source_total{source=~"cmsd|xrootd"}[5m]))
/
clamp_min(
  sum(rate(xrootd_openverify_rucio_lookups_total{result=~"empty|auth_error|timeout|error"}[5m]))
  + sum(rate(xrootd_openverify_rucio_exhausted_total[5m]))
, 1e-9)

# Mean locate RTT by source (Rucio list_replicas vs cmsd OFS open)
sum by (source) (rate(xrootd_openverify_locate_rtt_seconds_sum[5m]))
/
clamp_min(sum by (source) (rate(xrootd_openverify_locate_rtt_seconds_count[5m])), 1e-9)
```

AAA request volume (independent of OpenVerify) comes from **xrdmon**:
`xrdmon_redir_total{opcode}` — see the **AAA baseline** row on the CMS ops
dashboard.

### Accept attempt (retry depth)

When enforce mode retries candidates, record which attempt finally accepted a
verified / positive-cache redirect. **Rucio and cmsd are counted separately**
(`source` label). Enforce walks **all** Rucio PFNs; cmsd is still capped at 3.
Quarantine skips and failed verifies advance the attempt counter within that
source; client `tried=` skips on the Rucio path do not.

| Metric | Labels | Meaning |
|--------|--------|---------|
| `accepted_total` | `source=rucio\|cmsd`, `attempt=…` | rucio: verify succeeded on Nth ordered replica (`5+` overflow); cmsd: Nth redirect candidate |
| `retry_exhausted_total` | (instance) | Enforce only: cmsd max attempts with no verify success; last redirect returned best-effort |

```promql
# Frequency over a window (bar chart), split by source
sum by (source, attempt) (increase(xrootd_openverify_accepted_total[6h]))

# Share accepted on first try (all sources)
sum(rate(xrootd_openverify_accepted_total{attempt="1"}[5m]))
/
clamp_min(sum(rate(xrootd_openverify_accepted_total[5m])), 1e-9)
```

### Redirect traffic and “bad redirects saved”

| Metric | Labels | Meaning |
|--------|--------|---------|
| `redirects_handled_total` | (instance) | Every `SFS_REDIRECT` seen |
| `redirects_avoided_total` | `reason=quarantine\|negative_cache\|host_busy` | Target skipped via `tried=` before client follow |

`queue_timeout` / `queue_full` do **not** add the site to `tried=` and do not
touch EWMA / negative cache; the plugin requeues once, then passes through the
current redirect. `host_busy` **does** add the host to `tried=` (this site is
saturating its probe cap) but still does not affect EWMA.

FIFO wait defaults to **twice** `XRD_OPENVERIFY_VERIFY_TIMEOUT` (30s when the
probe timeout is 15s). Override with `XRD_OPENVERIFY_QUEUE_TIMEOUT_MS`. Per-host
inflight cap defaults to 50% of `XRD_OPENVERIFY_MAX_INFLIGHT` (override
`XRD_OPENVERIFY_MAX_INFLIGHT_PER_HOST`).

Avoidance rate ≈  
`rate(redirects_avoided_total) / rate(redirects_handled_total)`.

### Time penalty (redirect handling delay)

Histogram of wall time from receiving `SFS_REDIRECT` until accept/retry
decision (cache hit, verify, or avoid) — the OpenVerify-added latency for that
hop (cmsd stalls are returned to the client and are not part of this timer).
On the miss path this total includes FIFO queue wait + `open_verify` RTT.

| Series | Labels |
|--------|--------|
| `redirect_delay_seconds_bucket` | `outcome`, `le` |
| `redirect_delay_seconds_sum` | `outcome` |
| `redirect_delay_seconds_count` | `outcome` |

`outcome` ∈ `cache_hit_positive` | `cache_hit_negative` | `verify_success` |
`verify_failure` | `avoided` | `queue_timeout` | `queue_full` | `host_busy` |
`passthrough`
(static `xrootd.redirect` fallback such as transit; no verify).

FIFO rejects (`queue_timeout` / `queue_full`) never ran `open_verify` — they are
**not** counted in `runs_total` or `verify_failures_total`. `host_busy` is also
not a verify failure; it is a per-site inflight-cap skip (`tried=`). Do not read
`outcome=verify_failure` delay as including capacity waits.

Buckets (seconds): 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
7.5, 10, 15, 30, +Inf.

### Queue wait vs verify RTT (miss-path split)

Leaders only (followers coalesce on the in-flight key and are not timed here).

| Series | Labels | Meaning |
|--------|--------|---------|
| `queue_wait_seconds_*` | `result=admitted\|timeout` | Time waiting for a FIFO verify slot |
| `verify_rtt_seconds_*` | `result=success\|failure` | Wall time inside `open_verify` after admission |

`queue_full` immediate rejects do not record a queue-wait sample. Same bucket
bounds as `redirect_delay_seconds`.

```promql
# Mean queue wait (admitted leaders)
sum(rate(xrootd_openverify_queue_wait_seconds_sum{result="admitted"}[5m]))
/
clamp_min(sum(rate(xrootd_openverify_queue_wait_seconds_count{result="admitted"}[5m])), 1e-9)

# Mean verify RTT (successful opens)
sum(rate(xrootd_openverify_verify_rtt_seconds_sum{result="success"}[5m]))
/
clamp_min(sum(rate(xrootd_openverify_verify_rtt_seconds_count{result="success"}[5m])), 1e-9)
```

### Site status / scores

Exported from `OpenVerifyHostReliability` on each metrics flush:

| Metric | Type | Meaning |
|--------|------|---------|
| `site_ewma_health` | gauge | EWMA “badness” (0 = good, higher = worse) |
| `site_healthy` | gauge | `1` if not quarantined, else `0` |
| `site_verify_successes_total` | counter | Per-site verify successes |
| `site_verify_failures_total` | counter | Per-site verify failures |
| `failsafe_active` | gauge | `1` if the mass-quarantine circuit breaker is open (site skip disabled) |
| `failsafe_trips_total` | counter | Times the circuit breaker opened |
| `failsafe_recent_sites` | gauge | Unique sites that entered quarantine in the fail-safe window |
| `failsafe_max_sites` | gauge | Configured trip threshold (`0` disables) |

Labels: `host`, `port` (`none` if no port), optional `xrootd_instance`.
Fail-safe series have only the optional instance label.

Quarantine/recovery rates are env-tunable (`XRD_OPENVERIFY_EWMA_ALPHA_FAIL` /
`XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS`, thresholds, `XRD_OPENVERIFY_PROBE_COOLDOWN`);
see `OpenVerifyHostReliability.hh`. If `XRD_OPENVERIFY_FAILSAFE_MAX_SITES` unique
sites enter quarantine within `XRD_OPENVERIFY_FAILSAFE_WINDOW` seconds (defaults
8 / 300s; `0` sites disables), OpenVerify trips a circuit breaker: currently
quarantined sites are released, new quarantines are blocked, and `AvoidSite`
returns false until the hold expires.

---

## Example PromQL

### Developer

```promql
# Positive cache hit ratio (exclude hit_negative — known-bad)
sum(rate(xrootd_openverify_cache_lookups_total{result="hit_positive"}[5m]))
/
sum(rate(xrootd_openverify_cache_lookups_total[5m]))

# Single-flight followers per leader
sum(rate(xrootd_openverify_singleflight_requests_total{role="follower"}[5m]))
/
clamp_min(sum(rate(xrootd_openverify_singleflight_requests_total{role="leader"}[5m])), 1e-9)

# p95 redirect penalty
histogram_quantile(0.95,
  sum by (le) (rate(xrootd_openverify_redirect_delay_seconds_bucket[5m])))
```

### Operator / CMS redirector

```promql
# Redirects handled (proxy for redirector open load through OV)
sum(rate(xrootd_openverify_redirects_handled_total[5m]))

# Bad redirects saved
sum by (reason) (rate(xrootd_openverify_redirects_avoided_total[5m]))

# Unhealthy sites
count(xrootd_openverify_site_healthy == 0) or vector(0)

# Quarantine fail-safe (1 = OpenVerify stopped skipping sites)
xrootd_openverify_failsafe_active
xrootd_openverify_failsafe_recent_sites
increase(xrootd_openverify_failsafe_trips_total[1h])

# Worst site scores
topk(10, xrootd_openverify_site_ewma_health)

# Top sites by verify TIMEOUT (operation_expired / socket_timeout)
topk(15, sum by (host) (
  rate(xrootd_openverify_verify_failures_total{
    reason=~"operation_expired|socket_timeout"}[5m])))

# Top sites by ANY verify failure, split by reason
topk(15, sum by (host, reason) (
  rate(xrootd_openverify_verify_failures_total[5m])))

# cmsd stall rate (lookup delay; not attributed to a site)
sum(rate(xrootd_openverify_cmsd_stalls_total[5m]))
sum(rate(xrootd_openverify_cmsd_stall_seconds_total[5m]))

# Per-site inflight cap (host holding 50% of MAX_INFLIGHT)
topk(15, sum by (host) (rate(xrootd_openverify_host_busy_total[5m])))
```

### Observe mode

`XRD_OPENVERIFY_OBSERVE=1` still records metrics (including delay). Quarantine /
negative-cache avoidance counters only increment when enforcement applies
`tried=` (observe does not skip via quarantine the same way for client path;
quarantine avoid is skipped entirely in observe).

In observe:
- `accepted_total` is only `attempt=1`; `retry_exhausted_total` is not incremented
- `redirects_avoided_total` stays 0 (neg-cache hits use delay outcome
  `cache_hit_negative` but are not counted as avoided)
- `site_healthy` / EWMA still update from verify outcomes, but quarantine does
  not change the client redirect path — treat “Unhealthy sites” as a forecast
  signal, not “bad redirects saved”
- Fail-safe still trips from those forecast quarantines (`failsafe_active`);
  clients are already not skipped in observe
- Miss-path delay outcomes include `queue_timeout` / `queue_full` / `host_busy`
  when the FIFO or per-host cap rejects before verify
