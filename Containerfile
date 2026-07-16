ARG XROOTD_VERSION=6.0.1
FROM --platform=linux/amd64 xrootd-devel:${XROOTD_VERSION}

WORKDIR /src

# Mount the repo at /src and rpmbuild output at /root/rpmbuild when running:
#   podman run --rm \
#     --security-opt label=disable \
#     -v ~/rpmbuild:/root/rpmbuild \
#     -v <repo>:/src:ro \
#     openverify-builder

CMD ["bash", "build-rpm.sh"]
