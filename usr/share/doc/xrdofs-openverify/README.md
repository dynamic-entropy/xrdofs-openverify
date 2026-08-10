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

Install build dependencies (Fedora/RHEL family):

```bash
sudo dnf install -y rpm-build rpmlint cmake gcc-c++ make xrootd-server-devel libcurl-devel nlohmann-json-devel
```

Build RPMs from the current git checkout:

```bash
./build-rpm.sh
```

This creates source and binary RPMs under `~/rpmbuild/SRPMS` and `~/rpmbuild/RPMS`.

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
| `XRD_OPENVERIFY_FAILURE_LOG` | Absolute path for a dedicated live-verify failure log (see below). Unset/empty disables it |
| `X509_USER_PROXY` | X.509 proxy used for Rucio `x509_proxy` auth (same default credentials path as verify) |

Rucio scheme selection follows the client wire protocol: `http`/`https` → `davs`, otherwise `root`. Candidate try-order is pluggable (`OpenVerifyRucioSelector`); only the first chosen PFN is verified unless it fails, then the next, and so on. Client `tried=` is honoured when walking Rucio PFNs. In enforce mode every Rucio PFN is tried (no 3-cap); cmsd fallback remains capped at 3. Failed Rucio gateway candidates are accumulated into `tried=` for the cmsd fallback.

## Failure log (campaign file)

Set `XRD_OPENVERIFY_FAILURE_LOG` to an absolute path writable by the `xrootd` user to get one structured line per **live** `open_verify` failure (single-flight leader only). Existing daemon WARN lines and Prometheus `verify_failures_total` counters are unchanged (duplicated into this file, not moved).

Recommended path (instance-scoped, matching `xrootd@fed` / `xrootd@local`):

```
XRD_OPENVERIFY_FAILURE_LOG=/var/log/xrootd/fed/openverify-failures.log
```

If bind/open fails at plugin init, OpenVerify warns in the main log and continues without the campaign file.

**Recorded:** live probe failures on the Rucio-first and cmsd paths (including empty-file failures).

**Not recorded:** negative-cache hits, quarantine skips, queue full/timeout, Rucio lookup/auth soft-fails.

Example line (timestamp/prefix added by `XrdSysLogger`):

```
openverify_failure source=rucio attempt=2 host=cms-xrd.example.edu port=1094 path=/store/data/file.root pfn=root://cms-xrd.example.edu:1094//store/data/file.root protocol=root stage=open reason=socket_timeout status_code=103 err_no=0 detail="[ERROR] Socket timeout"
```

Fields:

| Field | Meaning |
|-------|---------|
| `source` | `rucio` or `cmsd` |
| `attempt` | 1-based ordered candidate index for that source path |
| `host` / `port` | Original gateway / cmsd next-hop (not the final data server) |
| `path` | LFN / request path |
| `pfn` | Rucio replica PFN as returned by catalog; for cmsd, synthesized `root://host:port//path` or `https://host:port/path` (no opaque/token) |
| `protocol` | `root` or `http` |
| `stage` | `key`, `credential_setup`, `open`, `stat`, `empty_file`, or `vector_read` |
| `reason` | Stable classified reason (same vocabulary as Prometheus) |
| `status_code` / `err_no` | XrdCl `Status::code` / `errNo` |
| `detail` | Low-level `Status::ToString()` (no URL, opaque, token, or cert paths) |

Filter failed Rucio verifications with e.g. `grep 'source=rucio'`, then group by `reason` / `stage` / `host`. Rotate with system logrotate (`create` as `xrootd:xrootd`); the plugin uses `Bind(..., lfh=0)` (no midnight rotate / fifo).

## Metrics (Prometheus)

Counters and example queries are documented in
[docs/prometheus.md](docs/prometheus.md). Set `XRD_OPENVERIFY_METRICS_PATH` (and
optionally `XRD_OPENVERIFY_METRICS_INSTANCE`) for textfile export; see
`include/OpenVerifyMetrics.hh` for environment variables.