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

```bash
# Local build (needs rpmdevtools, cmake toolchain, xrootd-server-devel, …)
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
| `XRD_OPENVERIFY_OBSERVE=1` | Metrics + verify on miss; no Rucio lookup (even with `XRD_OPENVERIFY_RUCIO=1`); no `tried=` / retry; cmsd redirect unchanged |
| `XRD_OPENVERIFY_DIRECT_SERVER=1` | After a successful verify on the **cmsd** path (or positive cache with a recorded data server), rewrite the client redirect to that final data-server host:port. Unsafe for EOS when the recorded server is an FST (missing MGM-signed opaque). Not applied to Rucio-first redirects. |
| `XRD_OPENVERIFY_RUCIO=1` | Enable Rucio-first locate: query CMS Rucio for replicas before cmsd; redirect to the site gateway from the PFN; fall back to cmsd on empty/auth/timeout/all candidates failed |
| `XRD_OPENVERIFY_RUCIO_URL` | Rucio REST base URL (default `https://cms-rucio.cern.ch`) |
| `XRD_OPENVERIFY_RUCIO_AUTH_URL` | Rucio auth base URL (default `https://cms-rucio-auth.cern.ch`) |
| `XRD_OPENVERIFY_RUCIO_ACCOUNT` | Rucio account (required when Rucio lookup is enabled) |
| `XRD_OPENVERIFY_RUCIO_TIMEOUT` | HTTP timeout seconds for Rucio auth/list (default `10`) |
| `XRD_OPENVERIFY_VERIFY_TIMEOUT` | Outbound XrdCl Open/Stat/VectorRead probe timeout in seconds (default `15`). FIFO wait defaults to twice this |
| `XRD_OPENVERIFY_RUCIO_SELECT` | Rucio PFN try-order: `rucio` (default; the order Rucio returns for `sort=geoip`), `random`, `priority` (Rucio priority), or `geoip` (reserved for local geo ranking; currently same as `rucio`). Next PFNs are tried only after the current one fails verify |
| `XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX` | Comma-separated LFN prefixes that skip Rucio `list_replicas` and fall through to **cmsd with verify still on**. Examples: `/store/user` (not in Rucio), `/tmp` (local SAM/test files). Does **not** stop OpenVerify probes. |
| `XRD_OPENVERIFY_SKIP_PREFIX` | Comma-separated LFN prefixes that skip Rucio **and** the verify probe. One cmsd locate; the redirect is passed to the client (same idea as transit). Matching is the same path-component rule as ignore-prefix. Put `/store/test/xrootd` here — see [SAM AAA](#sam-aaa-storetestxrootd) below. |
| `XRD_OPENVERIFY_RUCIO_CACHE_TTL` | `list_replicas` LRU TTL in seconds (default `60`; `0` disables). Key is `(lfn, scheme)`; replica set is reused across cmsd-stall retries |
| `XRD_OPENVERIFY_RUCIO_CACHE_SIZE` | Max LRU entries (default `8192`; `0` disables) |
| `XRD_OPENVERIFY_RUCIO_POOL_MIN` | Warm libcurl easy handles for Rucio HTTPS (default `1`; raise via puppet under load) |
| `XRD_OPENVERIFY_RUCIO_POOL_MAX` | Pool cap (default `500`). Grows when all handles are busy; shrinks idle extras after 15s. Wait only at max |
| `XRD_OPENVERIFY_RUCIO_POOL_SIZE` | Optional alias for `POOL_MIN` |
| `XRD_OPENVERIFY_EWMA_ALPHA_FAIL` | Failure blend into site badness score (default `0.05`; smaller = slower quarantine) |
| `XRD_OPENVERIFY_EWMA_ALPHA_SUCCESS` | Success decay of site badness score (default `0.10`; larger = faster recovery) |
| `XRD_OPENVERIFY_MIN_ATTEMPTS` | Verify samples before a site can enter or leave quarantine (default `20`) |
| `XRD_OPENVERIFY_QUARANTINE_THRESHOLD` | Enter quarantine when EWMA is at/above this (default `0.6`) |
| `XRD_OPENVERIFY_RECOVER_THRESHOLD` | Leave quarantine when EWMA is at/below this (default `0.4`; clamped to quarantine) |
| `XRD_OPENVERIFY_PROBE_COOLDOWN` | Seconds between probes of a quarantined site (default `60`) |
| `XRD_OPENVERIFY_FAILSAFE_MAX_SITES` | Unique sites entering quarantine in the fail-safe window that trip the circuit breaker (default `8`; `0` disables). While tripped, OpenVerify stops skipping sites for one window |
| `XRD_OPENVERIFY_FAILSAFE_WINDOW` | Fail-safe detection window and hold time in seconds (default `300`) |
| `X509_USER_PROXY` | X.509 proxy used for Rucio `x509_proxy` auth (same default credentials path as verify) |

Rucio scheme selection follows the client wire protocol: `http`/`https` → Rucio protocol `davs` (Rucio does not know `http`), otherwise `root`. `list_replicas` always sends the normalized Rucio scheme. Successful and empty lists are cached in a TTL LRU keyed by `(lfn, scheme)` (`XRD_OPENVERIFY_RUCIO_CACHE_TTL` / `_SIZE`) so cmsd-stall client retries do not re-hit the REST API; try-order is re-applied on every cache hit. Auth and `list_replicas` share an elastic pool of long-lived libcurl easy handles (`XRD_OPENVERIFY_RUCIO_POOL_MIN`/`_MAX`, default 1–500; set `POOL_MIN` in puppet if a host needs a warm floor) with a DNS/TLS-session cache; idle TCP keep-alives older than 15s are not reused (`CURLOPT_MAXAGE_CONN` — the warm min still keeps the *handles*), and idle extra handles shrink back toward min. Candidate try-order is pluggable (`OpenVerifyRucioSelector`); only the first chosen PFN is verified unless it fails, then the next, and so on. Client `tried=` is honoured when walking Rucio PFNs. In enforce mode every Rucio PFN is tried (no 3-cap); cmsd fallback remains capped at 3. Failed Rucio gateway candidates are accumulated into `tried=` for the cmsd fallback. **Tape replicas are dropped** before try-order (PFN `type=TAPE` or RSE name ending in `_Tape`) so OpenVerify never verify-opens or redirects to tape — Disk and Tape often share a gateway host with different PFN paths. LFNs matching `XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX` skip `list_replicas` entirely and go straight to cmsd **with verify still on**. LFNs matching `XRD_OPENVERIFY_SKIP_PREFIX` skip Rucio **and** verify: cmsd locates once and the client follows the hop.

OpenVerify sanitizes the **inbound** open path once to a CMS LFN (substring from the first `/store/`), stripping site prefixes such as `/eos/cms/` or `/dcache/uscmsdisk/`. That way a client that retries the federation with a PFN after load-balancer fallback ([xrootd#2394](https://github.com/xrootd/xrootd/issues/2394)) still hits Rucio/`cmsd` with `/store/...` instead of `http=400`. Rucio `list_replicas` and the wrapped cmsd `open` use that LFN. **Outbound** verify and client redirects keep the catalog PFN path (site prefix) that Rucio returned — or whatever path cmsd redirects with. Both dialects redirect with a full URL (`SFS_REDIRECT` with port `-1`). Because Rucio reports WebDAV replicas under its `davs` protocol id, and `dav`/`davs` are client-side input aliases that no HTTP client will follow in a `Location:` header, HTTP redirect URLs are translated to their wire scheme first (`davs://` → `https://`, `dav://` → `http://`).

**Static xrootd.redirect fallback:** when the wrapped OFS returns a redirect to `cms-xrd-transit.cern.ch` (CMS global `xrootd.redirect … ? /store` ENOENT rule), OpenVerify passes it through without verify, quarantine, or cache. That is a **successful** client redirect (`source=xrootd` / `fallback=transit`), not a verify error or retry exhaustion.

## SAM AAA `/store/test/xrootd`

CMS SAM/ETF AAA tests open this namespace **themselves**. OpenVerify does not invent the path. Typical LFN:

```
/store/test/xrootd/<CMS_SITE>/store/mc/SAM/...
```

ETF `org.cms.SE-XRootD-9federation` and WN `CE-cms-xrootd-access` hardcode `root://cms-xrd-global.cern.ch//store/test/xrootd/` + sitename + SAM LFN. Site-direct `SE-XRootD-4crt-read` never appears on global.

The prefix is a **cmsd/TFC pin**, not a Rucio DID ([XRootDTFCchanges](https://twiki.cern.ch/twiki/bin/view/CMSPublic/XRootDTFCchanges)). The SAM files exist at tens of RSEs; without a unique namespace, cmsd could send the client anywhere. Each **site** TFC maps `/store/test/xrootd/$SITENAME/store/(.*)` to the same PFN as `/store/$1`. Global has `all.export /` and **no** per-site rewrite. Subscription bubbles site → regional → global, so `xrdfs cms-xrd-global01 locate //store/test/xrootd/T2_US_Wisconsin/...` correctly returns **US regionals** (e.g. `xrootd.unl.edu`, `cmsxrootd2.fnal.gov`), not Wisconsin.

Vanilla AAA (no OpenVerify): cmsd redirects the **client** to the regional; the client walks to the site; site TFC strips the prefix. OpenVerify instead verify-opens the regional hop **from the global host**.

Two knobs, different strength:

| Env | Rucio REST | Verify probe | Client redirect |
|-----|------------|--------------|-----------------|
| `XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX=/store/test/xrootd` | skipped | **still runs** on cmsd hops | after up to 3 probes |
| `XRD_OPENVERIFY_SKIP_PREFIX=/store/test/xrootd` | skipped | **skipped** | cmsd hop unchanged (client follows AAA) |

Ignore-prefix alone does **not** stop hammering. Put `/store/test/xrootd` on `SKIP_PREFIX`. Do not unwrap the pin and Rucio-lookup the inner `/store/mc/SAM/...` DID — that would test the catalog, not cmsd export + site TFC.

### Why the caches do not absorb this traffic

1. **Inbound LFN is the wrapper.** `CmsLfnFromPath` takes the first `/store/`, so the path stays `/store/test/xrootd/<SITE>/store/mc/SAM/...`. The real DID is the inner `/store/mc/SAM/...`. Rucio `list_replicas` on the wrapper is empty or meaningless; each site wrapper is a distinct LFN.

2. **Rucio list cache is `(lfn, scheme)`** on that inbound wrapped path. Every `/store/test/xrootd/<SITE>/...` is a separate empty entry. `rucio_empty` is also logged on cache **hits**. ETF hits every CMS site in parallel, so the LRU fills with unique keys instead of coalescing.

3. **Verify cache is `(host:port, path)`** with ~15s negative / 120s positive TTL. The path includes the site wrapper, so Wisconsin vs Nebraska vs CIEMAT are different keys for the same file. **Same-key repeats are cached:** one `(xrootd.unl.edu:1094, /store/test/xrootd/T2_US_Wisconsin/...)` is probed on miss, then negative for ~15s; 5Hz client retries of that exact key are `negative_cache` / single-flight, not 5 XrdCl opens per second. A 5Hz line at a regional (or on the `/store/test/xrootd` prefix) is **fan-out**: ETF opens every `<SITE>` wrapper in parallel; each wrapper is a different path and usually locates the **same** regional first. N site keys × ~1 probe per 15s is several Hz at UNL/FNAL. `rucio_empty` is also logged on list-cache hits, so that log rate is not REST QPS.

4. **Quarantine runs before verify cache.** `AvoidSite` in the cmsd loop never consults the verify cache (`openverify skip quarantine`). A hot regional can be skipped on EWMA and still re-probed after cooldown.

5. **`tried=` dialect mismatch.** OpenVerify injects `host:port`; clients often send `+NNhostname`. cmsd frequently returns the **same regional** again (`ov_tried=unl,unl,unl`), so the 3-cap does not walk the tree.

6. **Empty Rucio does not stop cmsd.** cmsd still locates the **export prefix**. UNL/FNAL advertise `/store/test/xrootd/...` even when the file is not at that regional.

### Structural hammering from the global redirector

Monitoring “source site = `cms-xrd-global-test.cern.ch`” (or prod global) for `/store/test/xrootd/T2_US_Wisconsin` is **OpenVerify’s outbound XrdCl probes**, not ETF. The SAM client opened global; the plugin then opened the regional from CERN.

Typical enforce flow without `SKIP_PREFIX`:

1. Client opens the wrapped LFN on global.
2. Rucio ignore/empty — cmsd still runs.
3. cmsd locates a regional (UNL/FNAL for a US-site pin).
4. OpenVerify **from CERN** opens `root://xrootd.unl.edu:1094//store/test/xrootd/T2_US_Wisconsin/store/mc/SAM/...` with the **redirector** host proxy/cert, not the SAM client’s VOMS/GSI.
5. UNL TFC does not map Wisconsin’s prefix → `permission_denied` / `operation_expired`.
6. Enforce retries up to 3 cmsd hops (often the same regional). The client retries after 5s stalls. ETF does this for **every** CMS site’s wrapper at once.

What is wrong in the strategy for this namespace:

- Verify treats a **locate hop** (regional redirector) as a file server.
- The probe uses redirector credentials, so site authz/TFC never sees the real client.
- Rucio ignore/empty only skips REST; cmsd verify still runs.
- Enforce `tried=` + 3-cap **multiplies** probes; same regional repeats.
- Each site wrapper is a new cache key, so caches cannot collapse the fan-out.

`SKIP_PREFIX` restores vanilla AAA for this namespace: one cmsd open, pass the redirect, let the **client** walk regional → site, let **site TFC** strip the pin.

Logs: `openverify skip_prefix reason=/store/test/xrootd host=… path=…`. Metrics: `location_source=skip`, `skip_prefix_total{reason=…}`.

## Grepping xrootd.log

Failures, empty Rucio lists, exhaust, stalls, and skips are one greppable record each on the daemon log (`zgrep` rotated `xrootd.log-*.gz`):

```bash
# Files with an empty Rucio replica list (no PFNs; cmsd fallback, not exhaust)
grep 'openverify rucio_empty' /var/log/xrootd/fed/xrootd.log

# LFNs skipped by XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX (no Rucio REST call; cmsd still verified)
grep 'openverify rucio_skipped' /var/log/xrootd/fed/xrootd.log
#   result=skipped reason=/store/user path=/store/user/...

# LFNs skipped by XRD_OPENVERIFY_SKIP_PREFIX (no Rucio, no verify; cmsd redirect passed through)
grep 'openverify skip_prefix' /var/log/xrootd/fed/xrootd.log
#   reason=/store/test/xrootd host=xrootd.unl.edu:1094 path=/store/test/xrootd/T2_US_Wisconsin/...

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

`errors=` on the exhaust line uses the same reason vocabulary as Prometheus (`operation_expired`, `not_found`, …) plus skip tags `tried`, `quarantine`, `host_busy`, `negative_cache`. Summary lines also print `client_tried=` (CGI the client sent) and `ov_tried=` (hosts OpenVerify added this open); downstream opaque is still a single merged `tried=`. Other Rucio lookup failures (auth/timeout/error) are `openverify rucio_lookup result=… path=…`. Prefix-skipped LFNs are `openverify rucio_skipped` (`reason=` is the matched ignore prefix) or `openverify skip_prefix` (matched `XRD_OPENVERIFY_SKIP_PREFIX`; no probe). Successful accepts are `openverify succeeded` (and `openverify: verifying` marks the start of a probe).

## Metrics (Prometheus)

Counters and example queries are documented in
[docs/prometheus.md](docs/prometheus.md). Set `XRD_OPENVERIFY_METRICS_PATH` (and
optionally `XRD_OPENVERIFY_METRICS_INSTANCE`) for textfile export; see
`include/OpenVerifyMetrics.hh` for environment variables.