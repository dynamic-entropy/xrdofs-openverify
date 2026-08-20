# XrdOfsOpenVerify

An XRootD `XrdSfsFileSystem` plugin that wraps the native filesystem and
intercepts file open decisions to verify the file's integrity.

## Build

```bash
cd build
cmake ..
make
```

## Installation

```bash
sudo cmake --install build
```

## RPM packaging

Both packages share one version (`xrdofs-openverify.spec` / `xrdmon-collector.spec`):

```bash
# Local build (needs rpmdevtools, cmake toolchain, golang, xrootd-server-devel, …)
./build-all-rpms.sh

# Normal release: build in podman, publish to the yum repo, puppet lab nodes
./scripts/publish-rpms-to-yum.sh
```

RPMs land under `~/rpmbuild/RPMS`. Lab canary/cluster hosts install from the yum repo via puppet.

## XRootD configuration

Add the plugin in your server config:
```
xrootd.fslib ++ libXrdOfsOpenVerify.so
```

Optional environment variables (see `include/OpenVerifyMetrics.hh` for the full set):

| Variable | Effect |
|----------|--------|
| `XRD_OPENVERIFY_OBSERVE=1` | Metrics + verify on miss; no `tried=` / retry; cmsd redirect unchanged |
| `XRD_OPENVERIFY_DIRECT_SERVER=1` | After a successful verify on the **cmsd** path (or positive cache with a recorded data server), rewrite the client redirect to that final data-server host:port. Unsafe for EOS when the recorded server is an FST (missing MGM-signed opaque). Not applied to Rucio-first redirects. |
| `XRD_OPENVERIFY_RUCIO=1` | Enable Rucio-first locate: query CMS Rucio for replicas before cmsd; redirect to the site gateway from the PFN; fall back to cmsd on empty/auth/timeout/all candidates failed |
| `XRD_OPENVERIFY_RUCIO_URL` | Rucio REST base URL (default `https://cms-rucio.cern.ch`) |
| `XRD_OPENVERIFY_RUCIO_AUTH_URL` | Rucio auth base URL (default `https://cms-rucio-auth.cern.ch`) |
| `XRD_OPENVERIFY_RUCIO_ACCOUNT` | Rucio account (required when Rucio lookup is enabled) |
| `XRD_OPENVERIFY_RUCIO_TIMEOUT` | HTTP timeout seconds for Rucio auth/list (default `10`) |
| `XRD_OPENVERIFY_VERIFY_TIMEOUT` | Outbound XrdCl Open/Stat/VectorRead probe timeout in seconds (default `15`). FIFO wait defaults to twice this |
| `XRD_OPENVERIFY_RUCIO_SELECT` | Rucio PFN try-order: `random` (default), `priority` (Rucio priority), or `geoip` (reserved; currently same as random). Next PFNs are tried only after the current one fails verify |
| `XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX` | Comma-separated LFN prefixes that skip Rucio `list_replicas` and fall through to cmsd. CMS user files are not registered in Rucio: `/store/user` |
| `XRD_OPENVERIFY_RUCIO_CACHE_TTL` | `list_replicas` LRU TTL in seconds (default `60`; `0` disables). Key is `(lfn, scheme)`; replica set is reused across cmsd-stall retries |
| `XRD_OPENVERIFY_RUCIO_CACHE_SIZE` | Max LRU entries (default `8192`; `0` disables) |
| `XRD_OPENVERIFY_RUCIO_POOL_SIZE` | Long-lived libcurl easy handles for Rucio HTTPS. Default matches `XRD_OPENVERIFY_MAX_INFLIGHT` (`32`); max `256`. Reuses TCP+TLS to `cms-rucio` / `cms-rucio-auth` instead of a new handshake per lookup |
| `XRD_OPENVERIFY_EWMA_ALPHA_FAIL` | Failure blend into site badness score (default `0.05`; smaller = slower quarantine) |
| `XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS` | Success decay of site badness score (default `0.10`; larger = faster recovery) |
| `XRD_OPENVERIFY_MIN_ATTEMPTS` | Verify samples before a site can enter or leave quarantine (default `20`) |
| `XRD_OPENVERIFY_QUARANTINE_THRESHOLD` | Enter quarantine when EWMA is at/above this (default `0.6`) |
| `XRD_OPENVERIFY_RECOVER_THRESHOLD` | Leave quarantine when EWMA is at/below this (default `0.4`; clamped to quarantine) |
| `XRD_OPENVERIFY_PROBE_COOLDOWN` | Seconds between probes of a quarantined site (default `60`) |
| `XRD_OPENVERIFY_FAILSAFE_MAX_SITES` | Unique sites entering quarantine in the fail-safe window that trip the circuit breaker (default `8`; `0` disables). While tripped, OpenVerify stops skipping sites for one window |
| `XRD_OPENVERIFY_FAILSAFE_WINDOW` | Fail-safe detection window and hold time in seconds (default `300`) |
| `X509_USER_PROXY` | X.509 proxy used for Rucio `x509_proxy` auth (same default credentials path as verify) |

Rucio scheme selection follows the client wire protocol: `http`/`https` → Rucio protocol `davs` (Rucio does not know `http`), otherwise `root`. `list_replicas` always sends the normalized Rucio scheme. Successful and empty lists are cached in a TTL LRU keyed by `(lfn, scheme)` (`XRD_OPENVERIFY_RUCIO_CACHE_TTL` / `_SIZE`) so cmsd-stall client retries do not re-hit the REST API; try-order is re-applied on every cache hit. Auth and `list_replicas` share a pool of long-lived libcurl easy handles (`XRD_OPENVERIFY_RUCIO_POOL_SIZE`) with a connection/DNS/TLS-session cache, so cache misses reuse keep-alive HTTPS instead of `curl_easy_init`/`cleanup` per call. Candidate try-order is pluggable (`OpenVerifyRucioSelector`); only the first chosen PFN is verified unless it fails, then the next, and so on. Client `tried=` is honoured when walking Rucio PFNs. In enforce mode every Rucio PFN is tried (no 3-cap); cmsd fallback remains capped at 3. Failed Rucio gateway candidates are accumulated into `tried=` for the cmsd fallback. **Tape replicas are dropped** before try-order (PFN `type=TAPE` or RSE name ending in `_Tape`) so OpenVerify never verify-opens or redirects to tape — Disk and Tape often share a gateway host with different PFN paths. LFNs matching `XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX` skip `list_replicas` entirely and go straight to cmsd.

OpenVerify probes and redirects using the **catalog PFN path** (including any site prefix such as `/dcache/uscmsdisk/store/...`), not the client LFN. Both dialects redirect with a full URL (`SFS_REDIRECT` with port `-1`) so the client opens the PFN path instead of the original LFN. Because Rucio reports WebDAV replicas under its `davs` protocol id, and `dav`/`davs` are client-side input aliases that no HTTP client will follow in a `Location:` header, HTTP redirect URLs are translated to their wire scheme first (`davs://` → `https://`, `dav://` → `http://`).

**Static xrootd.redirect fallback:** when the wrapped OFS returns a redirect to `cms-xrd-transit.cern.ch` (CMS global `xrootd.redirect … ? /store` ENOENT rule), OpenVerify passes it through without verify, quarantine, or cache. That is a **successful** client redirect (`source=xrootd` / `fallback=transit`), not a verify error or retry exhaustion.

## Grepping xrootd.log

Failures, empty Rucio lists, exhaust, stalls, and skips are one greppable record each on the daemon log (`zgrep` rotated `xrootd.log-*.gz`):

```bash
# Files with an empty Rucio replica list (no PFNs; cmsd fallback, not exhaust)
grep 'openverify rucio_empty' /var/log/xrootd/fed/xrootd.log

# LFNs skipped by XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX (no Rucio REST call)
grep 'openverify rucio_skipped' /var/log/xrootd/fed/xrootd.log

# Rucio returned PFNs but none were accepted: LFN + catalog sites + per-host error
grep 'openverify rucio_exhausted' /var/log/xrootd/fed/xrootd.log
#   path=/store/... rucio=[host1:1094,host2:1094] errors=host1:1094=operation_expired,host2:1094=negative_cache
#   client_tried= / ov_tried= are log-only; cgi sent downstream is still tried=

# Site already in the client's tried= CGI (not an OpenVerify retry)
grep 'openverify skip client_tried' /var/log/xrootd/fed/xrootd.log

# cmsd retry: log splits origin; opaque still has one tried=
grep 'openverify cmsd retry' /var/log/xrootd/fed/xrootd.log

# Probe timeouts (Open / Stat / VectorRead of first+last byte)
grep 'reason=operation_expired' /var/log/xrootd/fed/xrootd.log
#   openverify_fail source=rucio host=... reason=operation_expired path=/store/... stage=open
#   openverify_probe reason=operation_expired stage=open url=root://...

# cmsd locate stall (client wait; includes path)
grep 'openverify cmsd stall' /var/log/xrootd/fed/xrootd.log
#   path=/store/... sec=5

# cmsd locate returned an error instead of a redirect
grep 'openverify cmsd_error' /var/log/xrootd/fed/xrootd.log

# cmsd retry budget spent with no accepted site (enforce mode)
grep 'openverify cmsd_exhausted' /var/log/xrootd/fed/xrootd.log
```

`errors=` on the exhaust line uses the same reason vocabulary as Prometheus (`operation_expired`, `not_found`, …) plus skip tags `tried`, `quarantine`, `host_busy`, `negative_cache`. Summary lines also print `client_tried=` (CGI the client sent) and `ov_tried=` (hosts OpenVerify added this open); downstream opaque is still a single merged `tried=`. Other Rucio lookup failures (auth/timeout/error) are `openverify rucio_lookup result=… path=…`. Prefix-skipped LFNs are `openverify rucio_skipped`. Successful accepts are `openverify succeeded` (and `openverify: verifying` marks the start of a probe).

## Metrics (Prometheus)

Counters and example queries are documented in
[docs/prometheus.md](docs/prometheus.md). Set `XRD_OPENVERIFY_METRICS_PATH` (and
optionally `XRD_OPENVERIFY_METRICS_INSTANCE`) for textfile export; see
`include/OpenVerifyMetrics.hh` for environment variables.