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
| `XRD_OPENVERIFY_RUCIO_SELECT` | Rucio PFN try-order: `random` (default), `priority` (Rucio priority), or `geoip` (reserved; currently same as random). Next PFNs are tried only after the current one fails verify |
| `X509_USER_PROXY` | X.509 proxy used for Rucio `x509_proxy` auth (same default credentials path as verify) |

Rucio scheme selection follows the client wire protocol: `http`/`https` → Rucio protocol `davs` (Rucio does not know `http`), otherwise `root`. `list_replicas` always sends the normalized Rucio scheme. Candidate try-order is pluggable (`OpenVerifyRucioSelector`); only the first chosen PFN is verified unless it fails, then the next, and so on. Client `tried=` is honoured when walking Rucio PFNs. In enforce mode every Rucio PFN is tried (no 3-cap); cmsd fallback remains capped at 3. Failed Rucio gateway candidates are accumulated into `tried=` for the cmsd fallback. **Tape replicas are dropped** before try-order (PFN `type=TAPE` or RSE name ending in `_Tape`) so OpenVerify never verify-opens or redirects to tape — Disk and Tape often share a gateway host with different PFN paths.

OpenVerify probes and redirects using the **catalog PFN path** (including any site prefix such as `/dcache/uscmsdisk/store/...`), not the client LFN. Both dialects redirect with a full URL (`SFS_REDIRECT` with port `-1`) so the client opens the PFN path instead of the original LFN. Because Rucio reports WebDAV replicas under its `davs` protocol id, and `dav`/`davs` are client-side input aliases that no HTTP client will follow in a `Location:` header, HTTP redirect URLs are translated to their wire scheme first (`davs://` → `https://`, `dav://` → `http://`).

**Static xrootd.redirect fallback:** when the wrapped OFS returns a redirect to `cms-xrd-transit.cern.ch` (CMS global `xrootd.redirect … ? /store` ENOENT rule), OpenVerify passes it through without verify, quarantine, or cache. That is a **successful** client redirect (`source=xrootd` / `fallback=transit`), not a verify error or retry exhaustion.

## Grepping xrootd.log

Failures, empty Rucio lists, exhaust, and skips are one greppable record each on the daemon log (`zgrep` rotated `xrootd.log-*.gz`):

```bash
# Files with an empty Rucio replica list (no PFNs; cmsd fallback, not exhaust)
grep 'openverify rucio_empty' /var/log/xrootd/fed/xrootd.log

# Rucio returned PFNs but none were accepted: LFN + catalog sites + per-host error
grep 'openverify rucio_exhausted' /var/log/xrootd/fed/xrootd.log
#   path=/store/... rucio=[host1:1094,host2:1094] errors=host1:1094=operation_expired,host2:1094=negative_cache

# Probe timeouts (Open / Stat / VectorRead of first+last byte)
grep 'reason=operation_expired' /var/log/xrootd/fed/xrootd.log
#   openverify_fail source=rucio host=... reason=operation_expired path=/store/... stage=open
#   openverify_probe reason=operation_expired stage=open url=root://...
```

`errors=` on the exhaust line uses the same reason vocabulary as Prometheus (`operation_expired`, `not_found`, …) plus skip tags `tried`, `quarantine`, `host_busy`, `negative_cache`. Other Rucio lookup failures (auth/timeout/error) are `openverify rucio_lookup result=… path=…`.

## Metrics (Prometheus)

Counters and example queries are documented in
[docs/prometheus.md](docs/prometheus.md). Set `XRD_OPENVERIFY_METRICS_PATH` (and
optionally `XRD_OPENVERIFY_METRICS_INSTANCE`) for textfile export; see
`include/OpenVerifyMetrics.hh` for environment variables.