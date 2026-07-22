package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

func buildRedirPacket(entries [][]byte) []byte {
	body := make([]byte, 0, 16+128)
	sid := make([]byte, 8)
	sid[0] = monRedSID
	body = append(body, sid...)
	for _, e := range entries {
		body = append(body, e...)
	}
	pkt := make([]byte, 8+len(body))
	pkt[0] = monMapRedr
	pkt[1] = 1
	binary.BigEndian.PutUint16(pkt[2:4], uint16(8+len(body)))
	binary.BigEndian.PutUint32(pkt[4:8], 1700000000)
	copy(pkt[8:], body)
	return pkt
}

func redirEntry(typ byte, host, path string, port uint16) []byte {
	s := host + ":" + path
	n := len(s) + 1
	slots := n / 8
	if n%8 != 0 {
		slots++
	}
	buf := make([]byte, (slots+1)*8)
	buf[0] = typ
	buf[1] = byte(slots)
	binary.BigEndian.PutUint16(buf[2:4], port)
	binary.BigEndian.PutUint32(buf[4:8], 0x12345678)
	copy(buf[8:], s)
	return buf
}

func TestParseRedirPacket(t *testing.T) {
	win := make([]byte, 8)
	e1 := redirEntry(monRedir|0x05, "disk.example.edu", "/store/data/file.root", 1094)
	e2 := redirEntry(monRedLoc|0x02, "other.site.edu", "/store/foo", 1094)
	pkt := buildRedirPacket([][]byte{win, e1, e2, win})

	m := NewMetrics("test", true)
	if err := ParseRedirPacket(pkt, m); err != nil {
		t.Fatalf("parse: %v", err)
	}

	exp := m.BuildExposition()
	if !strings.Contains(exp, `opcode="openr"`) {
		t.Fatalf("missing openr in:\n%s", exp)
	}
	if !strings.Contains(exp, `opcode="locate"`) {
		t.Fatalf("missing locate in:\n%s", exp)
	}
	if strings.Contains(exp, `source=`) {
		t.Fatalf("source label must not be exported:\n%s", exp)
	}
	if !strings.Contains(exp, `host="disk.example.edu"`) {
		t.Fatalf("missing dest host in:\n%s", exp)
	}
	if !strings.Contains(exp, `xrdmon_redir_dest_hosts`) {
		t.Fatalf("missing dest_hosts gauge:\n%s", exp)
	}
}

func TestParseReportXMLXrootdLinks(t *testing.T) {
	xml := `<?xml version="1.0"?>
<statistics tod="1" ver="5.7" src="cms-xrd-global01.cern.ch:1094" tos="0" pgm="xrootd" ins="fed" pid="1" site="T2_CH_CERN">
  <stats id="link"><num>12</num><maxn>40</maxn><tot>1000</tot><in>9</in><out>8</out>
    <ctime>500</ctime><tmo>3</tmo><stall>1</stall><sfps>0</sfps></stats>
  <stats id="xrootd"><rdr>42</rdr></stats>
</statistics>`

	m := NewMetrics("test", false)
	if err := ParseReportXML([]byte(xml), m); err != nil {
		t.Fatalf("parse: %v", err)
	}
	exp := m.BuildExposition()
	if !strings.Contains(exp, `xrdmon_link_num{`) || !strings.Contains(exp, `} 12`) {
		t.Fatalf("link_num missing:\n%s", exp)
	}
	if strings.Contains(exp, "xrdmon_xrootd_rdr_total") {
		t.Fatalf("xrootd.rdr must not be exported:\n%s", exp)
	}
	if strings.Contains(exp, "xrdmon_link_tmo") {
		t.Fatalf("link_tmo must not be exported:\n%s", exp)
	}
}

func TestParseCmsmReportNodesOnly(t *testing.T) {
	xml := `<statistics tod="1" ver="5.7" src="cms-xrd-global01.cern.ch:1098" tos="0" pgm="cmsd" ins="fed" pid="2" site="T2_CH_CERN">
  <stats id="cmsm"><role>M</role>
    <sel><t>10</t><r>8</r><w>2</w></sel>
    <node>1
      <stats id="0"><host>srv1.cern.ch</host><role>S</role><run>aw</run>
        <ref><r>5</r><w>1</w></ref></stats>
    </node>
    <frq><add>9<d>1</d></add><rsp>8<m>0</m></rsp>
      <lf>7</lf><ls>2</ls><rf>6</rf><rs>1</rs></frq>
  </stats>
</statistics>`

	m := NewMetrics("", true)
	if err := ParseReportXML([]byte(xml), m); err != nil {
		t.Fatalf("parse: %v", err)
	}
	exp := m.BuildExposition()
	if !strings.Contains(exp, `node="srv1.cern.ch"`) || !strings.Contains(exp, `xrdmon_cmsm_node_active`) {
		t.Fatalf("node active missing:\n%s", exp)
	}
	for _, ban := range []string{
		`xrdmon_cmsm_sel_total`,
		`xrdmon_cmsm_frq_total`,
		`xrdmon_cmsm_node_ref_total`,
		`xrdmon_link_num`, // cmsd links must not export
	} {
		if strings.Contains(exp, ban) {
			t.Fatalf("must not export %q in:\n%s", ban, exp)
		}
	}
}
