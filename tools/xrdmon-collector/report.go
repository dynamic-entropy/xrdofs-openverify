package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// statistics envelope + nested stats blocks from xrd.report XML.
type reportRoot struct {
	XMLName xml.Name `xml:"statistics"`
	TOD     string   `xml:"tod,attr"`
	Ver     string   `xml:"ver,attr"`
	Src     string   `xml:"src,attr"`
	TOS     string   `xml:"tos,attr"`
	PGM     string   `xml:"pgm,attr"`
	Ins     string   `xml:"ins,attr"`
	PID     string   `xml:"pid,attr"`
	Site    string   `xml:"site,attr"`
	Stats   []statBlock `xml:"stats"`
}

type statBlock struct {
	ID string `xml:"id,attr"`
	// link
	Num   string `xml:"num"`
	MaxN  string `xml:"maxn"`
	Tot   string `xml:"tot"`
	In    string `xml:"in"`
	Out   string `xml:"out"`
	CTime string `xml:"ctime"`
	Tmo   string `xml:"tmo"`
	Stall string `xml:"stall"`
	Sfps  string `xml:"sfps"`
	// xrootd
	Rdr string `xml:"rdr"`
	// cmsm
	Role string     `xml:"role"`
	Sel  *cmsmSel   `xml:"sel"`
	Node *cmsmNodes `xml:"node"`
	Frq  *cmsmFrq   `xml:"frq"`
}

type cmsmSel struct {
	T string `xml:"t"`
	R string `xml:"r"`
	W string `xml:"w"`
}

type cmsmNodes struct {
	// Number of nodes is the character data of <node>N ... but nested stats
	// make this awkward; we collect nested <stats id="i">.
	Stats []cmsmNodeStat `xml:"stats"`
}

type cmsmNodeStat struct {
	ID   string   `xml:"id,attr"`
	Host string   `xml:"host"`
	Role string   `xml:"role"`
	Run  string   `xml:"run"`
	Ref  *cmsmRef `xml:"ref"`
}

type cmsmRef struct {
	R string `xml:"r"`
	W string `xml:"w"`
}

type cmsmFrq struct {
	Add *cmsmFrqAdd `xml:"add"`
	Rsp *cmsmFrqRsp `xml:"rsp"`
	LF  string      `xml:"lf"`
	LS  string      `xml:"ls"`
	RF  string      `xml:"rf"`
	RS  string      `xml:"rs"`
}

type cmsmFrqAdd struct {
	// Character data is add count; nested <d> is duplicates.
	D     string `xml:"d"`
	Value string `xml:",chardata"`
}

type cmsmFrqRsp struct {
	M     string `xml:"m"`
	Value string `xml:",chardata"`
}

func atoi64(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// chardata may include nested noise; take first integer token
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// ParseReportXML parses an xrd.report XML datagram into metrics.
func ParseReportXML(buf []byte, m *Metrics) error {
	dec := xml.NewDecoder(strings.NewReader(string(buf)))
	var root reportRoot
	if err := dec.Decode(&root); err != nil && err != io.EOF {
		return fmt.Errorf("xml decode: %w", err)
	}
	if root.Src == "" {
		return fmt.Errorf("statistics missing src attribute")
	}

	snap := &SummarySnapshot{
		PGM:  root.PGM,
		Ins:  root.Ins,
		Site: root.Site,
	}

	for _, st := range root.Stats {
		switch st.ID {
		case "link":
			snap.LinkNum = atoi64(st.Num)
			snap.LinkMaxN = atoi64(st.MaxN)
			snap.LinkTot = atoi64(st.Tot)
			snap.LinkTmo = atoi64(st.Tmo)
			snap.LinkStall = atoi64(st.Stall)
			snap.LinkCTime = atoi64(st.CTime)
		case "xrootd":
			snap.XrootdRdr = atoi64(st.Rdr)
		case "cmsm":
			snap.CmsmRole = st.Role
			if st.Sel != nil {
				snap.SelT = atoi64(st.Sel.T)
				snap.SelR = atoi64(st.Sel.R)
				snap.SelW = atoi64(st.Sel.W)
			}
			if st.Frq != nil {
				snap.HasFrq = true
				if st.Frq.Add != nil {
					snap.FrqAdd = atoi64(st.Frq.Add.Value)
					snap.FrqAddD = atoi64(st.Frq.Add.D)
				}
				if st.Frq.Rsp != nil {
					snap.FrqRsp = atoi64(st.Frq.Rsp.Value)
					snap.FrqRspM = atoi64(st.Frq.Rsp.M)
				}
				snap.FrqLF = atoi64(st.Frq.LF)
				snap.FrqLS = atoi64(st.Frq.LS)
				snap.FrqRF = atoi64(st.Frq.RF)
				snap.FrqRS = atoi64(st.Frq.RS)
			}
			if st.Node != nil {
				for _, ns := range st.Node.Stats {
					n := CmsmNode{
						Host: ns.Host,
						Role: ns.Role,
						Run:  ns.Run,
					}
					if ns.Ref != nil {
						n.RefR = atoi64(ns.Ref.R)
						n.RefW = atoi64(ns.Ref.W)
					}
					snap.Nodes = append(snap.Nodes, n)
				}
			}
		}
	}

	m.SetSummary(root.Src, snap)
	return nil
}
