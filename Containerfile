ARG XROOTD_VERSION=6.0.1
FROM --platform=linux/amd64 xrootd-devel:${XROOTD_VERSION}

RUN dnf install -y libcurl-devel nlohmann-json-devel && dnf clean all

WORKDIR /src

# Mount the repo at /src and rpmbuild output at /root/rpmbuild when running:
#   podman run --rm \
#     --security-opt label=disable \
#     -v ~/rpmbuild:/root/rpmbuild \
#     -v <repo>:/src:ro \
#     openverify-builder

CMD ["bash", "build-all-rpms.sh"]
