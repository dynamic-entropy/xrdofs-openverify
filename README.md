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
sudo dnf install -y rpm-build rpmlint cmake gcc-c++ make xrootd-server-devel
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
| `XRD_OPENVERIFY_DIRECT_SERVER=1` | After a successful verify (or positive cache with a recorded data server), rewrite the client redirect to that final data-server host:port instead of the cmsd next hop |
## Metrics (Prometheus)

Counters and example queries are documented in
[docs/prometheus.md](docs/prometheus.md). Set `XRD_OPENVERIFY_METRICS_PATH` (and
optionally `XRD_OPENVERIFY_METRICS_INSTANCE`) for textfile export; see
`include/OpenVerifyMetrics.hh` for environment variables.