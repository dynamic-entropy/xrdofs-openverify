# OpenVerify Prometheus metrics

Metrics are **counters** written in Prometheus text exposition format (e.g. via
`XRD_OPENVERIFY_METRICS_PATH` and the node_exporter `textfile_collector`).

Environment variables are summarized in `include/OpenVerifyMetrics.hh`.

## Why you might only see two metric names

Prometheus ingests **time series**, not just `# TYPE` lines. You will always see
samples for:

- `xrootd_openverify_cache_lookups_total` (three `result` label values)
- `open_verify_calls_total` (single total counter)
- `xrootd_openverify_verify_runs_total` (two `result` label values)

**`xrootd_openverify_verify_failures_total` appears only after at least one failed
verify** (cache miss + `open_verify` returned false). Until then there are no
samples, so many UIs will not list that metric. This is expected.

## Exported metrics

All are `counter` type. Use **`rate()`** or **`increase()`** in queries; they
handle process restarts (counter resets) correctly.

Optional label **`xrootd_instance`** is present when
`XRD_OPENVERIFY_METRICS_INSTANCE` is set to a non-empty value.

### `xrootd_openverify_cache_lookups_total`

**Labels:** `result` ∈ `miss` | `hit_positive` | `hit_negative`  
**Meaning:** How often, on an `SFS_REDIRECT` open path, the in-memory OpenVerify
cache was consulted:

| `result`        | Meaning |
|----------------|---------|
| `miss`         | No valid cache entry; enforcement mode will run `open_verify` (observe mode also runs it on miss). |
| `hit_positive` | Cached successful verify for this (path, host, port). |
| `hit_negative` | Cached failed verify (short TTL); enforcement may drive replica retry via `tried=`. |

These are **lookup outcomes**, not bytes or client counts.

### `xrootd_openverify_verify_runs_total`

**Labels:** `result` ∈ `success` | `failure`  
**Meaning:** Runs of `open_verify` after a **cache miss** only (not on cache
hits). One miss can yield at most one success or one failure increment per
redirect handled in that open path.

- **`success`:** XrdCl open/stat/read check passed.
- **`failure`:** Verify failed (see `verify_failures_total` for breakdown).

### `open_verify_calls_total`

**Labels:** none (or optional `xrootd_instance` when configured)  
**Meaning:** Total number of actual `open_verify()` executions. In single-flight
paths this increments only for the leader call; followers do not increment it.

### `xrootd_openverify_verify_failures_total`

**Labels:** `host`, `port` (`port="none"` if redirect had no port), `reason`
(stable snake_case string from internal / XrdCl classification), plus optional
`xrootd_instance`.

**Meaning:** Sub-count of **`verify_runs_total{result="failure"}`**, split by
redirect target and failure reason. Sum over all label combinations of this
metric should match the failure counter (same process lifetime).

**Note:** No samples until the first failure (see above).

### Observe mode (`XRD_OPENVERIFY_OBSERVE=1`)

The **same metrics** are updated. Behavior differences (no cache writes, no
plugin `tried=`, no internal retry) do not change metric names or labels; only
traffic patterns change.

---

## Example PromQL

Adjust label matchers (`xrootd_instance`, job, etc.) to your scrape config.

### Cache lookup rate (per second)

```promql
sum by (result, xrootd_instance) (
  rate(xrootd_openverify_cache_lookups_total[5m])
)
```

### Verify run rate after cache misses

```promql
sum by (result, xrootd_instance) (
  rate(xrootd_openverify_verify_runs_total[5m])
)
```

### Share of cache hits among lookups (instant ratio, 5m window)

```promql
sum(rate(xrootd_openverify_cache_lookups_total{result=~"hit_.*"}[5m]))
/
sum(rate(xrootd_openverify_cache_lookups_total[5m]))
```

### Verify failure rate

```promql
sum(rate(xrootd_openverify_verify_runs_total{result="failure"}[5m]))
```

### Failure rate by reason (after first failures exist)

```promql
sum by (reason, host) (
  rate(xrootd_openverify_verify_failures_total[5m])
)
```

### Failure reasons as fraction of all verify runs

```promql
sum by (reason) (rate(xrootd_openverify_verify_failures_total[5m]))
/
sum(rate(xrootd_openverify_verify_runs_total[5m]))
```

### Grafana tip

Use **`rate(...[$__rate_interval])`** or a fixed range like **`[5m]`** on
panels so counters are displayed as rates; raw counter values climb forever and
reset on restart.
