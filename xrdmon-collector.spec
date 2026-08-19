Name:           xrdmon-collector
Version:        0.4.9
Release:        1%{?dist}
Summary:        XRootD AAA redirect monitor → Prometheus textfile

License:        MIT
URL:            https://github.com/dynamic-entropy/xrdofs-openverify
# Same git archive as the OpenVerify plugin build (repo root tarball).
Source0:        xrdofs-openverify-%{version}.tar.gz

BuildRequires:  golang
BuildRequires:  systemd-rpm-macros

Requires:       systemd

# Static Go binary: no usable DWARF/debugsource → empty debugsourcefiles.list.
%global debug_package %{nil}

%description
UDP collector for XRootD r-stream redirects and xrd.report summary stats
(link.*, cmsm.*). Writes Prometheus textfile metrics for node_exporter,
intended for CMS AAA redirectors (local-only monitoring).

%prep
%autosetup -n xrdofs-openverify-%{version}

%build
cd tools/xrdmon-collector
GO111MODULE=on CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=%{version}-%{release}" \
  -o xrdmon-collector .

%install
install -D -m 0755 tools/xrdmon-collector/xrdmon-collector \
  %{buildroot}%{_bindir}/xrdmon-collector

# Always point ExecStart at %{_bindir} (do not trust a stale unit path in git).
install -d %{buildroot}%{_unitdir}
cat > %{buildroot}%{_unitdir}/xrdmon-collector.service <<EOF
[Unit]
Description=XRootD AAA monitor collector (r-stream + xrd.report → Prometheus textfile)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%{_bindir}/xrdmon-collector \\
  -listen :9930 \\
  -out /var/lib/node_exporter/textfile_collector/xrdmon.prom \\
  -instance %%H \\
  -write-interval 15s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

%post
%systemd_post xrdmon-collector.service
# dnf reinstall runs %%preun as a full erase (disables the unit). Re-enable/start
# on every install/upgrade so the collector does not stay dead after package ops.
systemctl enable xrdmon-collector.service >/dev/null 2>&1 || :
systemctl start xrdmon-collector.service >/dev/null 2>&1 || :

%preun
%systemd_preun xrdmon-collector.service

%postun
%systemd_postun_with_restart xrdmon-collector.service

%files
%doc tools/xrdmon-collector/README.md
%{_bindir}/xrdmon-collector
%{_unitdir}/xrdmon-collector.service

%changelog
* Wed Aug 19 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.9-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.8-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.7-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.6-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.5-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.4-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.3-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.2-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.1-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 18 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.4.0-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 11 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.3.0-1
- Lockstep release with xrdofs-openverify.

* Tue Aug 11 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.9-1
- Lockstep release with xrdofs-openverify.

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.8-1
- Lockstep release with xrdofs-openverify.

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.7-1
- Re-enable and start the unit after install/reinstall (%%preun disables it).

* Mon Aug 10 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.2.6-1
- Parse full root/https redirect URLs for dest host labels (avoid host="root").

* Wed Jul 22 2026 OpenVerify maintainers <xrootd-dev@cern.ch> - 0.1.0-1
- Initial RPM packaging for xrdmon-collector.
