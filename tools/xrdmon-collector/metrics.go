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
// Scoped to the AAA baseline board: demand (opcode rates, destinations),
// blame (redirects per host), light platform (xrootd links + cmsd node liveness).
type Metrics struct {
	mu sync.Mutex

	instance string

	redirByOpcode map[string]uint64 // opcode
	redirByDest   map[string]uint64 // host (port ignored for cardinality)
	trackDest     bool

	packetsOK     atomic.Uint64
	packetsIgnore atomic.Uint64
	parseErrors   atomic.Uint64

	// last summary snapshot per src (xrootd/cmsd endpoint)
	summary map[string]*SummarySnapshot
}

// SummarySnapshot keeps only fields used on the baseline board.
type SummarySnapshot struct {
	PGM  string
	Ins  string
	Site string

	// xrootd client-facing links only (cmsd peer sockets are not exported)
	LinkNum  int64
	LinkMaxN int64
	LinkTot  int64

	Nodes []CmsmNode
}

type CmsmNode struct {
	Host string
	Role string
	Run  string
}

func NewMetrics(instance string, trackDest bool) *Metrics {
	return &Metrics{
		instance:      instance,
		redirByOpcode: make(map[string]uint64),
		redirByDest:   make(map[string]uint64),
		trackDest:     trackDest,
		summary:       make(map[string]*SummarySnapshot),
	}
}

func (m *Metrics) IncPacketOK()     { m.packetsOK.Add(1) }
func (m *Metrics) IncPacketIgnore() { m.packetsIgnore.Add(1) }
func (m *Metrics) IncParseError()   { m.parseErrors.Add(1) }

func (m *Metrics) AddRedirect(opcode, source, host string, port uint16) {
	_ = source // retained in parser for future; not exported (cmsd vs local confuses ops)
	_ = port
	m.mu.Lock()
	defer m.mu.Unlock()
	m.redirByOpcode[opcode]++
	if m.trackDest && host != "" {
		m.redirByDest[host]++
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

	// node_exporter runs as a non-root user and must be able to read the textfile.
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}

func (m *Metrics) BuildExposition() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	// Collector health (minimal)
	w("# HELP xrdmon_packets_total UDP packets processed by the collector.")
	w("# TYPE xrdmon_packets_total counter")
	w(fmt.Sprintf("xrdmon_packets_total%s %d", m.labels(map[string]string{"result": "ok"}), m.packetsOK.Load()))
	w(fmt.Sprintf("xrdmon_packets_total%s %d", m.labels(map[string]string{"result": "ignored"}), m.packetsIgnore.Load()))
	w(fmt.Sprintf("xrdmon_packets_total%s %d", m.labels(map[string]string{"result": "parse_error"}), m.parseErrors.Load()))

	// Demand: locate / open / other redirect rates
	w("# HELP xrdmon_redir_total Redirect events from the r-stream by opcode.")
	w("# TYPE xrdmon_redir_total counter")
	opKeys := make([]string, 0, len(m.redirByOpcode))
	for k := range m.redirByOpcode {
		opKeys = append(opKeys, k)
	}
	sort.Strings(opKeys)
	for _, opcode := range opKeys {
		w(fmt.Sprintf("xrdmon_redir_total%s %d",
			m.labels(map[string]string{"opcode": opcode}),
			m.redirByOpcode[opcode]))
	}

	// Blame / demand: redirects per destination host + unique host cardinality
	if m.trackDest {
		w("# HELP xrdmon_redir_dest_total Redirect events by destination host.")
		w("# TYPE xrdmon_redir_dest_total counter")
		dKeys := make([]string, 0, len(m.redirByDest))
		for k := range m.redirByDest {
			dKeys = append(dKeys, k)
		}
		sort.Strings(dKeys)
		for _, host := range dKeys {
			w(fmt.Sprintf("xrdmon_redir_dest_total%s %d",
				m.labels(map[string]string{"host": host}),
				m.redirByDest[host]))
		}
		w("# HELP xrdmon_redir_dest_hosts Distinct redirect destination hosts seen since process start.")
		w("# TYPE xrdmon_redir_dest_hosts gauge")
		w(fmt.Sprintf("xrdmon_redir_dest_hosts%s %d", m.labels(nil), len(m.redirByDest)))
	}

	srcs := make([]string, 0, len(m.summary))
	for s := range m.summary {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	wroteLinkHelp := false
	wroteNodeHelp := false
	for _, src := range srcs {
		snap := m.summary[src]
		base := map[string]string{"src": src, "pgm": snap.PGM, "ins": snap.Ins}
		if snap.Site != "" {
			base["site"] = snap.Site
		}

		// Platform: client-facing connections on xrootd only (not cmsd peer sockets).
		if snap.PGM == "xrootd" {
			if !wroteLinkHelp {
				w("# HELP xrdmon_link_num Current client connections (xrd.report link.num, xrootd).")
				w("# TYPE xrdmon_link_num gauge")
				w("# HELP xrdmon_link_maxn Max simultaneous client connections (link.maxn).")
				w("# TYPE xrdmon_link_maxn gauge")
				w("# HELP xrdmon_link_tot Client connections since start (link.tot).")
				w("# TYPE xrdmon_link_tot counter")
				wroteLinkHelp = true
			}
			w(fmt.Sprintf("xrdmon_link_num%s %d", m.labels(base), snap.LinkNum))
			w(fmt.Sprintf("xrdmon_link_maxn%s %d", m.labels(base), snap.LinkMaxN))
			w(fmt.Sprintf("xrdmon_link_tot%s %d", m.labels(base), snap.LinkTot))
		}

		// Platform: cmsd subscribed-node liveness
		if len(snap.Nodes) > 0 {
			if !wroteNodeHelp {
				w("# HELP xrdmon_cmsm_node_active Whether cmsd peer run status includes active (a).")
				w("# TYPE xrdmon_cmsm_node_active gauge")
				wroteNodeHelp = true
			}
			for _, n := range snap.Nodes {
				nb := withKV(base, "node", n.Host)
				nb = withKV(nb, "node_role", n.Role)
				nb = withKV(nb, "run", n.Run)
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
