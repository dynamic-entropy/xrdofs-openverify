# xrdmon-collector

Minimal Go UDP collector for CMS AAA redirectors. Lives in this repo under
`tools/xrdmon-collector`. Listens for:

1. **r-stream** (`xrootd.monitor … dest redir`) — per-redirect events
2. **`xrd.report` XML** — `link.*` (no byte counters) and `cmsm.*`

Writes Prometheus textfile:

`/var/lib/node_exporter/textfile_collector/xrdmon.prom`

## Deploy (RPM → yum Pages → Puppet)

Preferred path (same as OpenVerify):

```bash
# from xrdofs-openverify checkout (builds plugin + collector RPMs)
./scripts/publish-rpms-to-yum.sh
```

That builds both packages in the amd64 builder container, copies
`xrdofs-openverify*.rpm` and `xrdmon-collector*.rpm` into `~/dev/yum/el10/x86_64/`,
runs `createrepo_c`, and pushes GitHub Pages.

On **cms-xrd-global-test** hiera:

```yaml
xrootd_xrdmon_enable: true
```

Puppet installs `xrdmon-collector`, enables the systemd unit, and (via the fed
cfg template) points `xrd.report` + `redir` monitor at `127.0.0.1:9930` with
`cms.repstats all`.

## Build RPM only

```bash
# inside the builder container, or on an EL10+golang host:
./build-all-rpms.sh          # openverify + collector
# or:
./build-rpm.sh && ./build-xrdmon-rpm.sh
```

## Local Go build / test

```bash
cd tools/xrdmon-collector
go test ./...
go build -ldflags="-X main.version=dev" -o xrdmon-collector .
./xrdmon-collector -version
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-listen` | `:9930` | UDP bind (redir + report) |
| `-out` | `/var/lib/node_exporter/textfile_collector/xrdmon.prom` | Textfile path |
| `-instance` | _(empty)_ | Optional `xrootd_instance` label |
| `-write-interval` | `15s` | Flush period |
| `-dest-labels` | `true` | Per `host`/`port` redirect counters |
| `-version` | | Print build version |

## Metrics (v1)

- `xrdmon_redir_total{opcode,source}` / `xrdmon_redir_dest_total{host,port}`
- `xrdmon_link_*` (no byte counters), `xrdmon_xrootd_rdr_total`
- `xrdmon_cmsm_sel_total`, `xrdmon_cmsm_frq_total`, `xrdmon_cmsm_node_*`
- `xrdmon_packets_total{result=…}`

Optional GitHub Release workflow (`.github/workflows/xrdmon-collector-release.yml`)
still builds tarball assets; production canary install is via the yum RPM.
