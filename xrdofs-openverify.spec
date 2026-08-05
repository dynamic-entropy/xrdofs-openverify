Name:           xrdofs-openverify
Version:        0.2.1
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
* Wed Aug 05 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.1-1
- Split accepted_total attempt counters by source (rucio vs cmsd).
- Honour client tried= when walking Rucio PFN candidates.

* Tue Aug 04 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.0-1
- Add feature-flagged Rucio-first replica lookup with cmsd fallback.
- Redirect to site gateway from Rucio PFNs; match scheme to client protocol.
- Add Rucio/location-source Prometheus metrics.

* Fri May 08 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.1.0-1
- Initial RPM packaging for the OpenVerify plugin.
