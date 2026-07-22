package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Set via -ldflags "-X main.version=..." at release build time.
var version = "dev"

func main() {
	listen := flag.String("listen", ":9930", "UDP listen address for xrootd.monitor redir + xrd.report")
	out := flag.String("out", "/var/lib/node_exporter/textfile_collector/xrdmon.prom",
		"Prometheus textfile path (atomically rewritten)")
	instance := flag.String("instance", "", "Optional xrootd_instance label")
	interval := flag.Duration("write-interval", 15*time.Second, "How often to rewrite the textfile")
	trackDest := flag.Bool("dest-labels", true, "Export per-destination redirect counters (host/port labels)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	m := NewMetrics(*instance, *trackDest)

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("resolve listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(8 * 1024 * 1024)

	log.Printf("xrdmon-collector listening on %s → %s (interval %s)", conn.LocalAddr(), *out, *interval)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("udp read: %v", err)
				continue
			}
			handlePacket(buf[:n], m)
		}
	}()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	write := func() {
		if err := m.WriteFile(*out); err != nil {
			log.Printf("write %s: %v", *out, err)
		}
	}
	write()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			write()
		case sig := <-sigc:
			log.Printf("signal %v, flushing and exit", sig)
			write()
			return
		}
	}
}

func handlePacket(buf []byte, m *Metrics) {
	if len(buf) == 0 {
		return
	}
	if isProbablyXMLReport(buf) {
		if err := ParseReportXML(buf, m); err != nil {
			m.IncParseError()
			log.Printf("report parse: %v", err)
			return
		}
		m.IncPacketOK()
		return
	}
	if buf[0] == monMapRedr {
		if err := ParseRedirPacket(buf, m); err != nil {
			m.IncParseError()
			log.Printf("redir parse: %v", err)
			return
		}
		m.IncPacketOK()
		return
	}
	m.IncPacketIgnore()
}
