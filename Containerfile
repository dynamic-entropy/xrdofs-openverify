ARG XROOTD_VERSION=6.0.1
FROM --platform=linux/amd64 xrootd-devel:${XROOTD_VERSION}

WORKDIR /src

# Mount the repo at /src and rpmbuild output at /root/rpmbuild when running:
#   podman run --rm \
#     -v ~/rpmbuild:/root/rpmbuild:Z \
#     -v <repo>:/src:ro,Z \
#     openverify-builder

CMD ["bash", "build-rpm.sh"]
