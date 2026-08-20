Name:           xrdofs-openverify
Version:        0.5.3
Release:        1%{?dist}
Summary:        OpenVerify OFS plugin for XRootD

License:        MIT
URL:            https://github.com/dynamic-entropy/xrdofs-openverify
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  xrootd-server-devel >= 6.0.0
BuildRequires:  libcurl-devel
BuildRequires:  nlohmann-json-devel

Requires:       xrootd-server%{?_isa} >= 6.0.0
Requires:       libcurl%{?_isa}

%description
XrdOfsOpenVerify is an XRootD OFS plugin that wraps the native filesystem
and verifies file integrity decisions during open operations.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake
%cmake_build

%check
%ctest --output-on-failure

%install
%cmake_install

%files
%doc README.md docs/prometheus.md
%{_libdir}/libXrdOfsOpenVerify.so

%changelog
* Thu Aug 20 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.5.3-1
- Default Rucio curl pool min to 1 (grow under load; raise warm floor via puppet).
- Clarify MAXAGE_CONN vs warm handles; Grafana Locate path cache stats cleanup.

* Thu Aug 20 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.5.2-1
- Instrument Rucio curl pool: TCP/handle reuse (CURLINFO_NUM_CONNECTS), size gauges, grow/shrink.
- Add Grafana "Rucio curl pool" panels on openverify-cms-ops.

* Thu Aug 20 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.5.1-1
- Sanitize inbound open paths to CMS LFN once (strip site PFN prefixes) before Rucio/cmsd.
- Keeps catalog/cmsd PFN paths on outbound verify and client redirects (xrootd#2394 bounce fix).

* Thu Aug 20 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.5.0-1
- Elastic Rucio libcurl pool (min 50 / max 500): grow under load, shrink idle extras after 15s.
- Drop idle keep-alives after 15s; per-handle connection cache (no CURLSH CONNECT share).
- Disable Expect: 100-continue on list_replicas POST.
- Drop cmsd locate-RTT metric (stalls start a new client open; the per-call mean was not useful).

* Thu Aug 20 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.12-1
- Drop cmsd stall-duration histogram; keep stall event/sum counters (stall seconds are config, not latency).

* Thu Aug 20 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.11-1
- Reuse Rucio HTTPS via a libcurl easy-handle pool (XRD_OPENVERIFY_RUCIO_POOL_SIZE; default MAX_INFLIGHT).
- Split exhaust/retry logs into client_tried= vs ov_tried=.

* Wed Aug 19 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.10-1
- TTL LRU for Rucio list_replicas (lfn, scheme → PFN list) so cmsd-stall retries skip REST.

* Wed Aug 19 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.9-1
- Skip Rucio lookups for LFN prefixes (XRD_OPENVERIFY_RUCIO_IGNORE_PREFIX; CMS /store/user).

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.8-1
- Fix fail-safe Prometheus samples (missing braces) so node_exporter accepts the textfile again.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.7-1
- Raise default XRD_OPENVERIFY_VERIFY_TIMEOUT from 5s to 15s.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.6-1
- Mass-quarantine fail-safe: stop skipping sites if N unique sites enter quarantine in window T.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.5-1
- Env-tunable EWMA quarantine (alpha, thresholds, probe cooldown).
- Grafana site-health panel fixed to 0–1 with quarantine threshold lines.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.4-1
- Drop per-open FileWrapper/Connect/Disc INFO noise from the daemon log.
- Greppable cmsd stall/error/exhaust lines include path=; do not log client opaque.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.3-1
- Greppable daemon lines: rucio_empty, rucio_exhausted (path + rucio=[] + errors=), openverify_fail reason=.
- Drop XRD_OPENVERIFY_FAILURE_LOG campaign file; grep xrootd.log instead.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.2-1
- Log result= and path= on rucio lookup soft-fail (empty replica list is greppable).

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.1-1
- Log LFN on rucio-candidates-exhausted (path= next to rucio=[...]).

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.0-1
- Queue wait defaults to twice the verify timeout; requeue queue_timeout/queue_full without tried=.
- Cap per-host inflight at 50% of MAX_INFLIGHT; host_busy skips via tried= and is labeled in metrics.

* Tue Aug 11 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.3.0-1
- Fix memory leak: own wrapped OFS file with std::unique_ptr (RAII).

* Tue Aug 11 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.9-1
- Pass through cms-xrd-transit static xrootd.redirect without verify.
- Label accepts as source=xrootd / fallback=transit (not cmsd).

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.8-1
- Skip tape RSEs in Rucio-first locate (type=TAPE / RSE *_Tape).
- Normalize Rucio schemes: wire http/https → davs (never send http to Rucio).

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.7-1
- Lockstep release with xrdmon-collector (systemd enable after reinstall).

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.6-1
- Do not forward client opaque (xrd.gsiusrpxy/tried=) onto outbound verify URLs.

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.5-1
- Rucio verify and accepted redirects use the catalog PFN path (site prefix).
- Root clients get a full-URL redirect (SFS port -1); HTTP keeps host:port.
- Label verify_failures_total with source=rucio|cmsd for Grafana breakdowns.
- Failure log records probe URL/path actually used by XrdCl Open/Stat.

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.4-1
- Write failure campaign log via private append FILE (not XrdSysLogger::Bind).
- Keep normal daemon/plugin traffic on the main xrootd log only.

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.3-1
- Add optional XRD_OPENVERIFY_FAILURE_LOG campaign file for live verify failures.
- Record source, attempt, host/port, LFN, PFN, protocol, stage, reason, and status.

* Wed Aug 05 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.2-1
- Enforce walks all Rucio PFNs (cmsd remains capped at 3).
- Pluggable Rucio try-order selector (default random; priority/geoip hooks).
- Split Grafana success/accept-rate panels by source (rucio vs cmsd).

* Wed Aug 05 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.1-1
- Split accepted_total attempt counters by source (rucio vs cmsd).
- Honour client tried= when walking Rucio PFN candidates.

* Tue Aug 04 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.0-1
- Add feature-flagged Rucio-first replica lookup with cmsd fallback.
- Redirect to site gateway from Rucio PFNs; match scheme to client protocol.
- Add Rucio/location-source Prometheus metrics.

* Fri May 08 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.1.0-1
- Initial RPM packaging for the OpenVerify plugin.
