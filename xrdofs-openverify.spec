Name:           xrdofs-openverify
Version:        0.4.0
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
