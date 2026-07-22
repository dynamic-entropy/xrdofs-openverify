package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	monMapRedr = 'r'

	monRedSID  = 0xf0
	monRedTime = 0x00
	monRedir   = 0x80
	monRedLoc  = 0x90
)

var opcodeNames = map[byte]string{
	0x01: "chmod",
	0x02: "locate",
	0x03: "opendir",
	0x04: "openc",
	0x05: "openr",
	0x06: "openw",
	0x07: "mkdir",
	0x08: "mv",
	0x09: "prep",
	0x0a: "query",
	0x0b: "rm",
	0x0c: "rmdir",
	0x0d: "stat",
	0x0e: "trunc",
}

func opcodeName(op byte) string {
	if n, ok := opcodeNames[op]; ok {
		return n
	}
	return fmt.Sprintf("op_0x%02x", op)
}

// ParseRedirPacket parses an XRootD r-stream datagram and records redirects.
func ParseRedirPacket(buf []byte, m *Metrics) error {
	if len(buf) < 8 {
		return fmt.Errorf("packet too short for header: %d", len(buf))
	}
	code := buf[0]
	if code != monMapRedr {
		return fmt.Errorf("not an r-stream packet: code=%q", code)
	}
	plen := int(binary.BigEndian.Uint16(buf[2:4]))
	if plen < 16 || plen > len(buf) {
		// Some stacks deliver larger UDP buffers; accept len(buf) if plen looks truncated.
		if plen < 16 || plen > 65535 {
			return fmt.Errorf("bad plen=%d buflen=%d", plen, len(buf))
		}
		if plen > len(buf) {
			plen = len(buf)
		}
	}

	// After header: 8-byte server id word (first byte REDSID).
	if plen < 16 {
		return fmt.Errorf("packet missing server id word")
	}
	off := 16 // start of info[]
	for off+8 <= plen {
		typ := buf[off]
		hi := typ & 0xf0

		switch {
		case typ == monRedTime:
			// Window mark: exactly 8 bytes.
			off += 8
		case typ == monRedSID:
			// Unexpected SID inside info[]; skip 8.
			off += 8
		case hi == monRedir || hi == monRedLoc:
			dent := int(buf[off+1])
			words := dent + 1
			need := words * 8
			if off+need > plen {
				return fmt.Errorf("redirect entry truncated: off=%d need=%d plen=%d", off, need, plen)
			}
			port := binary.BigEndian.Uint16(buf[off+2 : off+4])
			// dictid at off+4..off+8 ignored
			payload := buf[off+8 : off+need]
			host, _ := splitHostPath(payload)
			source := "cmsd"
			if hi == monRedLoc {
				source = "local"
			}
			op := typ & 0x0f
			m.AddRedirect(opcodeName(op), source, host, port)
			off += need
		default:
			// Unknown 8-byte slot; skip to avoid wedging the walker.
			off += 8
		}
	}
	return nil
}

func splitHostPath(b []byte) (host, path string) {
	// Null-terminated "host:path" (host may be empty → local pfn).
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	s := string(b[:n])
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

func isProbablyXMLReport(buf []byte) bool {
	for _, c := range buf {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return c == '<' || c == '{'
	}
	return false
}
