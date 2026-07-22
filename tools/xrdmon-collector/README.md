# xrdmon-collector

Minimal Go UDP collector for CMS AAA redirectors. Lives in this repo under
`tools/xrdmon-collector` (not a separate project). Listens for:

1. **r-stream** (`xrootd.monitor … dest redir`) — per-redirect events
2. **`xrd.report` XML** — `link.*` (no byte counters) and `cmsm.*`

Writes a Prometheus textfile for `node_exporter`’s textfile collector — same
directory as OpenVerify on the canary:

`/var/lib/node_exporter/textfile_collector/xrdmon.prom`

Does **not** parse user maps, login stats, or transfer/byte streams.

## Install on cms-xrd-global-test (from GitHub Release)

After a `xrdmon-v*` tag is published on
[dynamic-entropy/xrdofs-openverify](https://github.com/dynamic-entropy/xrdofs-openverify/releases):

```bash
# as root on the canary
curl -fsSL -o /tmp/install-xrdmon.sh \
  https://raw.githubusercontent.com/dynamic-entropy/xrdofs-openverify/master/tools/xrdmon-collector/contrib/install-from-release.sh
# or copy contrib/ from a checkout, then:
sudo bash tools/xrdmon-collector/contrib/install-from-release.sh   # latest
# sudo bash …/install-from-release.sh 0.1.0                      # pin version
```

That installs `/usr/local/bin/xrdmon-collector`, enables
`xrdmon-collector.service`, and writes:

`/var/lib/node_exporter/textfile_collector/xrdmon.prom`

Manual download (EL x86_64):

```bash
VER=0.1.0   # release without the xrdmon-v prefix
curl -fsSLO "https://github.com/dynamic-entropy/xrdofs-openverify/releases/download/xrdmon-v${VER}/xrdmon-collector-${VER}-linux-amd64.tar.gz"
tar -xzf "xrdmon-collector-${VER}-linux-amd64.tar.gz"
sudo install -m 0755 "xrdmon-collector-${VER}-linux-amd64" /usr/local/bin/xrdmon-collector
sudo install -m 0644 contrib/xrdmon-collector.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now xrdmon-collector
```

## Publish a release (maintainers)

CI: `.github/workflows/xrdmon-collector-release.yml`

```bash
# after merging collector changes to master:
git tag xrdmon-v0.1.0
git push origin xrdmon-v0.1.0
```

Builds linux/amd64 + linux/arm64 tarballs (+ sha256) and attaches them to the
GitHub Release for that tag. `workflow_dispatch` builds artifacts without
publishing.

## Build locally

```bash
cd tools/xrdmon-collector
go test ./...
go build -ldflags="-X main.version=dev" -o xrdmon-collector .
./xrdmon-collector -version
```

## Run (foreground)

```bash
./xrdmon-collector \
  -listen :9930 \
  -out /var/lib/node_exporter/textfile_collector/xrdmon.prom \
  -instance cms-xrd-global-test \
  -write-interval 15s
```

Flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `-listen` | `:9930` | UDP bind (redir + report on same port) |
| `-out` | `/var/lib/node_exporter/textfile_collector/xrdmon.prom` | Atomic textfile path |
| `-instance` | _(empty)_ | Optional `xrootd_instance` label |
| `-write-interval` | `15s` | Flush period |
| `-dest-labels` | `true` | Per `host`/`port` redirect counters |
| `-version` | | Print build version |

## XRootD / cmsd config (local only)

Point both daemons at the collector — **no** UCSD / EU collector:

```text
# xrootd@fed
xrootd.monitor all window 5s ident 5m dest redir 127.0.0.1:9930
xrd.report 127.0.0.1:9930 every 30s all sync

# cmsd@fed (manager)
xrd.report 127.0.0.1:9930 every 30s all sync
cms.repstats all
```

## Metrics (v1)

**r-stream**

- `xrdmon_redir_total{opcode,source}` — `source` is `cmsd` or `local`
- `xrdmon_redir_dest_total{host,port}` — optional via `-dest-labels`

**summary**

- `xrdmon_link_num|maxn` (gauges), `xrdmon_link_tot|tmo|stall|ctime_seconds` (counters)
- `xrdmon_xrootd_rdr_total`
- `xrdmon_cmsm_sel_total{access=total\|read\|write}`
- `xrdmon_cmsm_frq_total{kind=…}` — lookup/redir fast vs slow, etc.
- `xrdmon_cmsm_node_ref_total{node,…}`, `xrdmon_cmsm_node_active{node,…}`

**collector health**

- `xrdmon_packets_total{result=ok\|ignored\|parse_error}`

`link.in` / `link.out` are intentionally omitted.
