Name:           xrdofs-openverify
Version:        0.1.0
Release:        1%{?dist}
Summary:        OpenVerify OFS plugin for XRootD

License:        MIT
URL:            https://github.com/dynamic-entropy/xrdofs-openverify
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  xrootd-server-devel >= 5.9.1

Requires:       xrootd-server%{?_isa} >= 5.9.1

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
* Fri May 08 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.1.0-1
- Initial RPM packaging for the OpenVerify plugin.
