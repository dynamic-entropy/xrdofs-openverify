ARG XROOTD_VERSION=6.0.1
FROM --platform=linux/amd64 xrootd-devel:${XROOTD_VERSION}

# Collector RPM needs golang + systemd macros; install here so rebuilding
# openverify-builder (publish-rpms-to-yum.sh) is enough without rebuilding
# the xrootd-devel base image.
RUN dnf install -y golang systemd-rpm-macros libcurl-devel nlohmann-json-devel && dnf clean all

WORKDIR /src

# Mount the repo at /src and rpmbuild output at /root/rpmbuild when running:
#   podman run --rm \
#     --security-opt label=disable \
#     -v ~/rpmbuild:/root/rpmbuild \
#     -v <repo>:/src:ro \
#     openverify-builder

CMD ["bash", "build-all-rpms.sh"]
