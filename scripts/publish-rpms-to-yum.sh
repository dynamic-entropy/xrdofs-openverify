#!/usr/bin/env bash
# publish-rpms-to-yum.sh
#
# End-to-end publish for both RPMs (same version):
#   xrdofs-openverify + xrdmon-collector
#
#   1. Build RPMs inside the podman container (build-all-rpms.sh)
#   2. Copy binary RPMs into the local yum repo checkout
#   3. Regenerate repodata with createrepo_c
#   4. Commit and push the yum repo to GitHub (Pages serves it as the DNF repo).
#      Same version as HEAD → amend + push --force-with-lease; version bump → new commit.
#   5. Trigger puppet agent runs on lab cluster nodes
#
# Usage:
#   ./scripts/publish-rpms-to-yum.sh [--skip-build] [--skip-push] [--skip-puppet]
#
# Prerequisites: podman, createrepo_c, git, ssh (key auth to cluster nodes)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YUM_REPO="${YUM_REPO:-${HOME}/dev/yum}"
RPMBUILD_DIR="${RPMBUILD_DIR:-${HOME}/rpmbuild}"
OS_VER="${OS_VER:-el10}"
ARCH="${ARCH:-x86_64}"

BUILDER_IMAGE="${BUILDER_IMAGE:-openverify-builder}"
XROOTD_VERSION="${XROOTD_VERSION:-6.0.1}"

SSH_USER="${SSH_USER:-root}"
SSH_PROXY="${SSH_PROXY:-}"

# Lab cluster nodes (profile::xrootd::cluster). Canary uses the same yum repo
# via puppet separately (cms-xrd-global-test).
NODES=(
    xrdmetaman.cern.ch
    xrdman-1.cern.ch
    xrdman-2.cern.ch
    xrdsrv-1.cern.ch
    xrdsrv-2.cern.ch
    xrdsrv-3.cern.ch
    xrdsrv-4.cern.ch
)

SKIP_BUILD=0
SKIP_PUSH=0
SKIP_PUPPET=0
for arg in "$@"; do
    case "$arg" in
        --skip-build)   SKIP_BUILD=1 ;;
        --skip-push)    SKIP_PUSH=1 ;;
        --skip-puppet)  SKIP_PUPPET=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

VERSION="$(rpmspec -q --srpm --qf '%{VERSION}-%{RELEASE}\n' \
    "${REPO_ROOT}/xrdofs-openverify.spec" | head -1)"
MON_VERSION="$(rpmspec -q --srpm --qf '%{VERSION}-%{RELEASE}\n' \
    "${REPO_ROOT}/xrdmon-collector.spec" | head -1)"
if [[ "${MON_VERSION}" != "${VERSION}" ]]; then
    echo "ERROR: xrdmon-collector.spec (${MON_VERSION}) must match xrdofs-openverify.spec (${VERSION})" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1 – Build RPMs in the container
# ---------------------------------------------------------------------------
if [[ $SKIP_BUILD -eq 0 ]]; then
    echo "==> Building container image ${BUILDER_IMAGE} ..."
    podman build \
        --build-arg XROOTD_VERSION="${XROOTD_VERSION}" \
        -t "${BUILDER_IMAGE}" \
        -f "${REPO_ROOT}/Containerfile" \
        "${REPO_ROOT}"

    echo "==> Running RPM build inside container (openverify + xrdmon-collector ${VERSION}) ..."
    mkdir -p "${RPMBUILD_DIR}"
    podman run --rm \
        --security-opt label=disable \
        -v "${RPMBUILD_DIR}:/root/rpmbuild" \
        -v "${REPO_ROOT}:/src:ro" \
        "${BUILDER_IMAGE}"
else
    echo "==> Skipping container build (--skip-build)"
fi

# ---------------------------------------------------------------------------
# Step 2 – Copy binary RPMs into the local yum repo checkout
# ---------------------------------------------------------------------------
RPM_SRC="${RPMBUILD_DIR}/RPMS/${ARCH}"
RPM_DST="${YUM_REPO}/${OS_VER}/${ARCH}"

if [[ ! -d "${RPM_SRC}" ]]; then
    echo "ERROR: RPM output dir not found: ${RPM_SRC}" >&2
    exit 1
fi
if [[ ! -d "${RPM_DST}" ]]; then
    echo "ERROR: yum repo target dir not found: ${RPM_DST}" >&2
    exit 1
fi

OV_RPM="$(ls -t "${RPM_SRC}"/xrdofs-openverify-[0-9]*.rpm 2>/dev/null | head -1 || true)"
MON_RPM="$(ls -t "${RPM_SRC}"/xrdmon-collector-[0-9]*.rpm 2>/dev/null | head -1 || true)"
if [[ -z "${OV_RPM}" || -z "${MON_RPM}" ]]; then
    echo "ERROR: need both RPMs in ${RPM_SRC}" >&2
    echo "  xrdofs-openverify: ${OV_RPM:-MISSING}" >&2
    echo "  xrdmon-collector:  ${MON_RPM:-MISSING}" >&2
    exit 1
fi

echo "==> Copying RPMs to ${RPM_DST} ..."
cp -v "${OV_RPM}" "${MON_RPM}" "${RPM_DST}/"

# ---------------------------------------------------------------------------
# Step 3 – Regenerate repodata
# ---------------------------------------------------------------------------
echo "==> Regenerating repodata in ${RPM_DST} ..."
createrepo_c --update "${RPM_DST}"

# ---------------------------------------------------------------------------
# Step 4 – Commit and push yum repo
# ---------------------------------------------------------------------------
# Same NVR as HEAD → amend (republish/rebuild). Version bump → new commit.
if [[ $SKIP_PUSH -eq 0 ]]; then
    COMMIT_MSG="Update xrdofs-openverify and xrdmon-collector ${VERSION}"
    HEAD_MSG="$(git -C "${YUM_REPO}" log -1 --pretty=%s 2>/dev/null || true)"

    echo "==> Staging yum repo (xrdofs-openverify + xrdmon-collector ${VERSION}) ..."
    git -C "${YUM_REPO}" add "${OS_VER}/"

    if [[ -z "$(git -C "${YUM_REPO}" status --porcelain)" ]]; then
        echo "==> No yum repo changes to commit; skipping commit/push."
    elif [[ "${HEAD_MSG}" == "${COMMIT_MSG}" ]]; then
        echo "==> Same version as HEAD (${VERSION}); amending previous commit ..."
        git -C "${YUM_REPO}" commit --amend --no-edit
        git -C "${YUM_REPO}" push --force-with-lease
        echo "==> yum repo force-pushed (amended); GitHub Pages will serve the updated metadata shortly."
    else
        echo "==> Version changed (HEAD: ${HEAD_MSG:-none}); creating new commit ..."
        git -C "${YUM_REPO}" commit -m "${COMMIT_MSG}"
        git -C "${YUM_REPO}" push
        echo "==> yum repo pushed; GitHub Pages will serve the updated metadata shortly."
    fi
else
    echo "==> Skipping git push (--skip-push)"
fi

# ---------------------------------------------------------------------------
# Step 5 – Run puppet agent on lab cluster nodes
# ---------------------------------------------------------------------------
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no)
if [[ -n "${SSH_PROXY}" ]]; then
    SSH_OPTS+=(-J "${SSH_PROXY}")
fi

if [[ $SKIP_PUPPET -eq 0 && $SKIP_PUSH -eq 0 ]]; then
    echo "==> Triggering puppet agent runs on cluster nodes ..."
    sleep 10

    for node in "${NODES[@]}"; do
        echo "  -> ${node}"
        ssh "${SSH_OPTS[@]}" "${SSH_USER}@${node}" \
            'dnf clean metadata --disablerepo="*" --enablerepo="xrdofs-openverify" \
             && puppet agent --onetime --no-daemonize --verbose 2>&1 | tail -20' &
    done

    echo "==> Waiting for all puppet runs to finish ..."
    wait
    echo "==> All puppet runs complete."
elif [[ $SKIP_PUPPET -eq 1 ]]; then
    echo "==> Skipping puppet runs (--skip-puppet)"
else
    echo "==> Skipping puppet runs because push was skipped"
fi

echo ""
echo "Done. Published xrdofs-openverify + xrdmon-collector ${VERSION}."
echo "Canary: puppet on cms-xrd-global-test (or dnf reinstall both packages there)."
