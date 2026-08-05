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
| [`docs/grafana/openverify-cms-ops.json`](grafana/openverify-cms-ops.json) | CMS redirector ops: traffic, capacity, site×error; Enforce row for avoidance/attempts |
| [`docs/grafana/xrdmon-cms-ops.json`](grafana/xrdmon-cms-ops.json) | AAA baseline from xrdmon-collector (r-stream, destinations, link/cmsm) |

**CMS ops variables** (top of dashboard):

| Variable | Use |
|----------|-----|
| `xrootd_instance` | Which redirector daemon(s) |
| `Site` | Multi-select `host` from `verify_failures_total` |
| `Error reason` | Multi-select `reason` (scoped to selected sites) |

Drill-down panels:

- **Sites → error types** — pick site(s), see stacked rates by `reason`
- **Error types → sites** — pick reason(s), see stacked rates by `host`
- **Verify failures: site × error** — table of counts over the time range (filterable/sortable)

New series appear after deploying a build that includes latency / avoid / site
export, and after at least one redirect has been handled (site gauges appear
once a host has a verify outcome recorded).

## Always-present series

- `xrootd_openverify_cache_lookups_total` (`miss` | `hit_positive` | `hit_negative`)
- `xrootd_openverify_runs_total` (`success` | `failure`)
- `xrootd_openverify_queue_admissions_total` (`admitted` | `queue_full` | `queue_timeout`)
- `xrootd_openverify_singleflight_requests_total` (`leader` | `follower`)
- `xrootd_openverify_redirects_handled_total`
- `xrootd_openverify_redirects_avoided_total` (`quarantine` | `negative_cache`)
- `xrootd_openverify_redirect_delay_seconds` (histogram by `outcome`; total hop = queue + RTT on miss)
- `xrootd_openverify_queue_wait_seconds` (histogram by `result` = `admitted` | `timeout`)
- `xrootd_openverify_verify_rtt_seconds` (histogram by `result` = `success` | `failure`)
- `xrootd_openverify_cmsd_stalls_total` / `cmsd_stall_seconds_total`
- `xrootd_openverify_cmsd_stall_seconds` (histogram of individual stall durations)
- `xrootd_openverify_accepted_total` (`source` = `rucio` \| `cmsd`, `attempt` = `1`|`2`|`3`)
- `xrootd_openverify_retry_exhausted_total`
- `xrootd_openverify_rucio_lookups_total` (`result` = `ok` \| `empty` \| `auth_error` \| `timeout` \| `error`)
- `xrootd_openverify_rucio_candidates_total`
- `xrootd_openverify_location_source_total` (`source` = `rucio` \| `cmsd`)

**Appear after first event:**

- `xrootd_openverify_verify_failures_total` — first verify failure (**includes per-site timeouts**)
- `xrootd_openverify_site_*` — first per-site verify success/failure

Optional label **`xrootd_instance`** when `XRD_OPENVERIFY_METRICS_INSTANCE` is set.

Use **`rate()`** / **`increase()`** on counters; gauges (`site_ewma_health`,
`site_healthy`) are instantaneous.

---

## Metric reference

### Cache / verify / queue / single-flight

Same meanings as before:

| Metric | Labels | Meaning |
|--------|--------|---------|
| `cache_lookups_total` | `result` | Cache consult on redirect |
| `runs_total` | `result` | Actual `open_verify` after miss |
| `queue_admissions_total` | `result` | Inflight queue gate |
| `singleflight_requests_total` | `role` | Leader runs verify; follower waits |
| `verify_failures_total` | `host`,`port`,`reason` | Failed verifies by target |

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
to cmsd. See the **Rucio-first locate** row on
[`openverify-cms-ops.json`](grafana/openverify-cms-ops.json).

| Metric | Labels | Meaning |
|--------|--------|---------|
| `rucio_lookups_total` | `result=ok\|empty\|auth_error\|timeout\|error` | `list_replicas` outcome |
| `rucio_candidates_total` | (instance) | PFN candidates from successful lookups |
| `location_source_total` | `source=rucio\|cmsd` | Accepted open’s location source |

```promql
# Share of accepts from Rucio
sum(rate(xrootd_openverify_location_source_total{source="rucio"}[5m]))
/
clamp_min(sum(rate(xrootd_openverify_location_source_total[5m])), 1e-9)

# Soft-fail rate (fallback to cmsd)
sum(rate(xrootd_openverify_rucio_lookups_total{result=~"empty|auth_error|timeout|error"}[5m]))
```

### Accept attempt (retry depth)

When enforce mode retries across candidates (up to 3), record which attempt
finally accepted a verified / positive-cache redirect. **Rucio and cmsd are
counted separately** (`source` label). Quarantine skips and failed verifies
advance the attempt counter within that source; client `tried=` skips on the
Rucio path do not.

| Metric | Labels | Meaning |
|--------|--------|---------|
| `accepted_total` | `source=rucio\|cmsd`, `attempt=1\|2\|3` | Open accepted on the Nth candidate of that source |
| `retry_exhausted_total` | (instance) | Enforce only: max attempts with no verify success; last redirect returned best-effort |

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
| `redirects_avoided_total` | `reason=quarantine\|negative_cache` | Target skipped via `tried=` before client follow |

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
`verify_failure` | `avoided` | `queue_timeout` | `queue_full`.

FIFO rejects (`queue_timeout` / `queue_full`) never ran `open_verify` — they are
**not** counted in `runs_total` or `verify_failures_total`. Do not read
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

Labels: `host`, `port` (`none` if no port), optional `xrootd_instance`.

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
- Miss-path delay outcomes include `queue_timeout` / `queue_full` when the FIFO
  rejects before verify
