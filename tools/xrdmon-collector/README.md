# xrdmon-collector

UDP collector for CMS AAA redirectors → Prometheus textfile.

## What it exports (baseline board)

| Goal | Series |
|------|--------|
| Demand | `xrdmon_redir_total{opcode}` (locate, openr, …) |
| Destinations | `xrdmon_redir_dest_total{host}`, `xrdmon_redir_dest_hosts` (parses classic `host:path` and full `root://host…` / `https://host…` payloads; a naive `:` split would mis-label URLs as `host="root"`) |
| Platform (xrootd) | `xrdmon_link_num\|maxn\|tot` (**xrootd only**, not cmsd; often absent on AAA redirectors) |
| cmsd peer health | `xrdmon_cmsm_node_active{node,…}` |
| Collector health | `xrdmon_packets_total{result}` |

**Removed / not exported:** cmsd vs local `source`, cmsm sel/FRQ/refs, cmsd link sockets, bytes, `xrootd.rdr` (redundant with r-stream).

## Not available from xrdmon (need other sources)

| Goal | Source |
|------|--------|
| Unique LFNs, hops/open | probes / richer correlation |
| Client open success, TTFB, failure taxonomy, retries | synthetic probes / job metrics |
| Post-redirect site failures | client-side |
| CPU / FD | node_exporter (Grafana 1860) |
| Auth / TLS | later (`lgn.*`) or logs |

## Grafana

Panels live on the OpenVerify CMS ops board:

[`docs/grafana/openverify-cms-ops.json`](../../docs/grafana/openverify-cms-ops.json)
— top row **AAA baseline** (client redirects by type/destination, cmsd peers, collector health).

## Deploy

Same release path as OpenVerify (one version, both RPMs):

```bash
./scripts/publish-rpms-to-yum.sh
```

On the canary (after yum metadata refresh / puppet):

```bash
dnf reinstall -y xrdmon-collector && systemctl restart xrdmon-collector
```

Default textfile: `/var/lib/node_exporter/textfile_collector/xrdmon.prom` (mode 0644).
The systemd unit is shipped by the RPM (no separate install script).
