package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics holds collector state for Prometheus textfile export.
type Metrics struct {
	mu sync.Mutex

	instance string

	// r-stream
	redirByOpSrc map[string]uint64 // key: opcode|source
	redirByDest  map[string]uint64 // key: host|port
	trackDest    bool

	packetsOK     atomic.Uint64
	packetsIgnore atomic.Uint64
	parseErrors   atomic.Uint64

	// last summary snapshot per src (xrootd/cmsd endpoint)
	summary map[string]*SummarySnapshot
}

type SummarySnapshot struct {
	PGM  string
	Ins  string
	Site string

	LinkNum   int64
	LinkMaxN  int64
	LinkTot   int64
	LinkTmo   int64
	LinkStall int64
	LinkCTime int64

	XrootdRdr int64

	CmsmRole string
	SelT     int64
	SelR     int64
	SelW     int64

	FrqAdd  int64
	FrqAddD int64
	FrqRsp  int64
	FrqRspM int64
	FrqLF   int64
	FrqLS   int64
	FrqRF   int64
	FrqRS   int64
	HasFrq  bool

	Nodes []CmsmNode
}

type CmsmNode struct {
	Host string
	Role string
	Run  string
	RefR int64
	RefW int64
}

func NewMetrics(instance string, trackDest bool) *Metrics {
	return &Metrics{
		instance:     instance,
		redirByOpSrc: make(map[string]uint64),
		redirByDest:  make(map[string]uint64),
		trackDest:    trackDest,
		summary:      make(map[string]*SummarySnapshot),
	}
}

func (m *Metrics) IncPacketOK()     { m.packetsOK.Add(1) }
func (m *Metrics) IncPacketIgnore() { m.packetsIgnore.Add(1) }
func (m *Metrics) IncParseError()   { m.parseErrors.Add(1) }

func (m *Metrics) AddRedirect(opcode, source, host string, port uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := opcode + "|" + source
	m.redirByOpSrc[k]++
	if m.trackDest && host != "" {
		dk := host + "|" + fmt.Sprintf("%d", port)
		m.redirByDest[dk]++
	}
}

func (m *Metrics) SetSummary(src string, snap *SummarySnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.summary[src] = snap
}

func esc(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func (m *Metrics) labels(extra map[string]string) string {
	parts := make([]string, 0, 1+len(extra))
	if m.instance != "" {
		parts = append(parts, fmt.Sprintf(`xrootd_instance="%s"`, esc(m.instance)))
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, esc(extra[k])))
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (m *Metrics) WriteFile(path string) error {
	body := m.BuildExposition()
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".xrdmon-*.prom")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (m *Metrics) BuildExposition() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	w("# HELP xrdmon_packets_total UDP packets processed by the collector.")
	w("# TYPE xrdmon_packets_total counter")
	w(fmt.Sprintf("xrdmon_packets_total%s %d", m.labels(map[string]string{"result": "ok"}), m.packetsOK.Load()))
	w(fmt.Sprintf("xrdmon_packets_total%s %d", m.labels(map[string]string{"result": "ignored"}), m.packetsIgnore.Load()))
	w(fmt.Sprintf("xrdmon_packets_total%s %d", m.labels(map[string]string{"result": "parse_error"}), m.parseErrors.Load()))

	w("# HELP xrdmon_redir_total Redirect events from the r-stream.")
	w("# TYPE xrdmon_redir_total counter")
	opKeys := make([]string, 0, len(m.redirByOpSrc))
	for k := range m.redirByOpSrc {
		opKeys = append(opKeys, k)
	}
	sort.Strings(opKeys)
	for _, k := range opKeys {
		parts := strings.SplitN(k, "|", 2)
		opcode, source := parts[0], parts[1]
		w(fmt.Sprintf("xrdmon_redir_total%s %d",
			m.labels(map[string]string{"opcode": opcode, "source": source}),
			m.redirByOpSrc[k]))
	}

	if m.trackDest {
		w("# HELP xrdmon_redir_dest_total Redirect events by destination host:port.")
		w("# TYPE xrdmon_redir_dest_total counter")
		dKeys := make([]string, 0, len(m.redirByDest))
		for k := range m.redirByDest {
			dKeys = append(dKeys, k)
		}
		sort.Strings(dKeys)
		for _, k := range dKeys {
			parts := strings.SplitN(k, "|", 2)
			host, port := parts[0], parts[1]
			w(fmt.Sprintf("xrdmon_redir_dest_total%s %d",
				m.labels(map[string]string{"host": host, "port": port}),
				m.redirByDest[k]))
		}
	}

	srcs := make([]string, 0, len(m.summary))
	for s := range m.summary {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	if len(srcs) > 0 {
		w("# HELP xrdmon_link_num Current connections (xrd.report link.num).")
		w("# TYPE xrdmon_link_num gauge")
		w("# HELP xrdmon_link_maxn Max simultaneous connections (link.maxn).")
		w("# TYPE xrdmon_link_maxn gauge")
		w("# HELP xrdmon_link_tot Connections since start (link.tot).")
		w("# TYPE xrdmon_link_tot counter")
		w("# HELP xrdmon_link_tmo Read request timeouts (link.tmo).")
		w("# TYPE xrdmon_link_tmo counter")
		w("# HELP xrdmon_link_stall Partial-data stalls (link.stall).")
		w("# TYPE xrdmon_link_stall counter")
		w("# HELP xrdmon_link_ctime_seconds Cumulative connect seconds (link.ctime).")
		w("# TYPE xrdmon_link_ctime_seconds counter")
		w("# HELP xrdmon_xrootd_rdr_total Protocol-level redirects (xrootd.rdr).")
		w("# TYPE xrdmon_xrootd_rdr_total counter")

		for _, src := range srcs {
			snap := m.summary[src]
			base := map[string]string{"src": src, "pgm": snap.PGM, "ins": snap.Ins}
			if snap.Site != "" {
				base["site"] = snap.Site
			}
			w(fmt.Sprintf("xrdmon_link_num%s %d", m.labels(base), snap.LinkNum))
			w(fmt.Sprintf("xrdmon_link_maxn%s %d", m.labels(base), snap.LinkMaxN))
			w(fmt.Sprintf("xrdmon_link_tot%s %d", m.labels(base), snap.LinkTot))
			w(fmt.Sprintf("xrdmon_link_tmo%s %d", m.labels(base), snap.LinkTmo))
			w(fmt.Sprintf("xrdmon_link_stall%s %d", m.labels(base), snap.LinkStall))
			w(fmt.Sprintf("xrdmon_link_ctime_seconds%s %d", m.labels(base), snap.LinkCTime))
			if snap.XrootdRdr > 0 || snap.PGM == "xrootd" {
				w(fmt.Sprintf("xrdmon_xrootd_rdr_total%s %d", m.labels(base), snap.XrootdRdr))
			}
		}

		w("# HELP xrdmon_cmsm_sel_total cmsd node selections (cmsm.sel).")
		w("# TYPE xrdmon_cmsm_sel_total counter")
		w("# HELP xrdmon_cmsm_frq_total cmsd fast-response queue counters.")
		w("# TYPE xrdmon_cmsm_frq_total counter")
		w("# HELP xrdmon_cmsm_node_ref_total Per-subscribed-node selection refs.")
		w("# TYPE xrdmon_cmsm_node_ref_total counter")
		w("# HELP xrdmon_cmsm_node_active Whether node run status includes active (a).")
		w("# TYPE xrdmon_cmsm_node_active gauge")

		for _, src := range srcs {
			snap := m.summary[src]
			if snap.CmsmRole == "" && snap.SelT == 0 && len(snap.Nodes) == 0 {
				continue
			}
			base := map[string]string{"src": src, "pgm": snap.PGM, "ins": snap.Ins, "role": snap.CmsmRole}
			if snap.Site != "" {
				base["site"] = snap.Site
			}
			w(fmt.Sprintf("xrdmon_cmsm_sel_total%s %d",
				m.labels(withKV(base, "access", "total")), snap.SelT))
			w(fmt.Sprintf("xrdmon_cmsm_sel_total%s %d",
				m.labels(withKV(base, "access", "read")), snap.SelR))
			w(fmt.Sprintf("xrdmon_cmsm_sel_total%s %d",
				m.labels(withKV(base, "access", "write")), snap.SelW))

			if snap.HasFrq {
				for _, p := range []struct {
					k string
					v int64
				}{
					{"add", snap.FrqAdd},
					{"add_dup", snap.FrqAddD},
					{"rsp", snap.FrqRsp},
					{"rsp_multi", snap.FrqRspM},
					{"lookup_fast", snap.FrqLF},
					{"lookup_slow", snap.FrqLS},
					{"redir_fast", snap.FrqRF},
					{"redir_slow", snap.FrqRS},
				} {
					w(fmt.Sprintf("xrdmon_cmsm_frq_total%s %d",
						m.labels(withKV(base, "kind", p.k)), p.v))
				}
			}

			for _, n := range snap.Nodes {
				nb := withKV(base, "node", n.Host)
				nb = withKV(nb, "node_role", n.Role)
				nb = withKV(nb, "run", n.Run)
				w(fmt.Sprintf("xrdmon_cmsm_node_ref_total%s %d",
					m.labels(withKV(nb, "access", "read")), n.RefR))
				w(fmt.Sprintf("xrdmon_cmsm_node_ref_total%s %d",
					m.labels(withKV(nb, "access", "write")), n.RefW))
				active := 0
				if strings.Contains(n.Run, "a") {
					active = 1
				}
				w(fmt.Sprintf("xrdmon_cmsm_node_active%s %d", m.labels(nb), active))
			}
		}
	}

	return b.String()
}

func withKV(base map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(base)+1)
	for kk, vv := range base {
		out[kk] = vv
	}
	out[k] = v
	return out
}
