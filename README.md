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

## XRootD configuration

Add the plugin in your server config:
```
xrootd.fslib ++ libXrdOfsOpenVerify.so
```

## Metrics (Prometheus)

Counters and example queries are documented in
[docs/prometheus.md](docs/prometheus.md). Set `XRD_OPENVERIFY_METRICS_PATH` (and
optionally `XRD_OPENVERIFY_METRICS_INSTANCE`) for textfile export; see
`include/OpenVerifyMetrics.hh` for environment variables.