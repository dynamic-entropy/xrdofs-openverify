package main

import (
	"bytes"
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
	// Null-terminated destination. Classic r-stream form is "host:path"
	// (host may be empty → local pfn). OpenVerify / some stacks put a full
	// URL ("root://host:port/path"); a naive first-':' split then yields
	// host="root", which pollutes destination metrics.
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	s := string(b[:n])
	if s == "" {
		return "", ""
	}

	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		if at := strings.IndexByte(rest, '@'); at >= 0 {
			rest = rest[at+1:]
		}
		hostport := rest
		path = ""
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			hostport = rest[:slash]
			path = rest[slash:]
		}
		return hostnameFromHostPort(hostport), path
	}

	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// hostnameFromHostPort returns the host from "host", "host:port", or "[ipv6]:port".
func hostnameFromHostPort(hostport string) string {
	if hostport == "" {
		return ""
	}
	if hostport[0] == '[' {
		if end := strings.IndexByte(hostport, ']'); end >= 0 {
			return hostport[1:end]
		}
		return hostport
	}
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		// Only strip when the suffix looks like a port (all digits).
		port := hostport[i+1:]
		if port != "" && isAllDigits(port) {
			return hostport[:i]
		}
	}
	return hostport
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isProbablyXMLReport(buf []byte) bool {
	// Only accept real xrd.report envelopes. A bare '<' match is too loose:
	// stray/truncated UDP payloads (e.g. starting with "<100") were logged as
	// xml decode errors and dropped without counting as ignored.
	i := 0
	for i < len(buf) {
		c := buf[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		break
	}
	if i >= len(buf) {
		return false
	}
	s := buf[i:]
	if s[0] == '{' {
		return false // JSON reports not supported
	}
	if bytes.HasPrefix(s, []byte("<?xml")) || bytes.HasPrefix(s, []byte("<statistics")) {
		return true
	}
	return false
}
