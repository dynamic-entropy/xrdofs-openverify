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
	XMLName xml.Name    `xml:"statistics"`
	Src     string      `xml:"src,attr"`
	PGM     string      `xml:"pgm,attr"`
	Ins     string      `xml:"ins,attr"`
	Site    string      `xml:"site,attr"`
	Stats   []statBlock `xml:"stats"`
}

type statBlock struct {
	ID string `xml:"id,attr"`
	// link (xrootd client conns)
	Num  string `xml:"num"`
	MaxN string `xml:"maxn"`
	Tot  string `xml:"tot"`
	// cmsm nodes only
	Node *cmsmNodes `xml:"node"`
}

type cmsmNodes struct {
	Stats []cmsmNodeStat `xml:"stats"`
}

type cmsmNodeStat struct {
	ID   string `xml:"id,attr"`
	Host string `xml:"host"`
	Role string `xml:"role"`
	Run  string `xml:"run"`
}

func atoi64(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
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
		case "cmsm":
			if st.Node != nil {
				for _, ns := range st.Node.Stats {
					snap.Nodes = append(snap.Nodes, CmsmNode{
						Host: ns.Host,
						Role: ns.Role,
						Run:  ns.Run,
					})
				}
			}
		}
	}

	m.SetSummary(root.Src, snap)
	return nil
}
