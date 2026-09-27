#!/usr/bin/env bash
# publish-rpms-to-yum.sh
#
# End-to-end publish for the xrdofs-openverify RPM:
#
#   1. Build RPMs inside the podman container (build-all-rpms.sh)
#   2. Copy binary RPMs into the local yum repo checkout
#   3. Regenerate repodata with createrepo_c
#   4. Commit and push the yum repo to GitHub (Pages serves it as the DNF repo).
#      Same version as HEAD → amend + push --force-with-lease; version bump → new commit.
#
# Usage:
#   ./scripts/publish-rpms-to-yum.sh [--skip-build] [--skip-push]
#
# Prerequisites: podman, createrepo_c, git

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YUM_REPO="${YUM_REPO:-${HOME}/dev/yum}"
RPMBUILD_DIR="${RPMBUILD_DIR:-${HOME}/rpmbuild}"
OS_VER="${OS_VER:-el10}"
ARCH="${ARCH:-x86_64}"

BUILDER_IMAGE="${BUILDER_IMAGE:-openverify-builder}"
XROOTD_VERSION="${XROOTD_VERSION:-6.0.1}"

SKIP_BUILD=0
SKIP_PUSH=0
for arg in "$@"; do
    case "$arg" in
        --skip-build)   SKIP_BUILD=1 ;;
        --skip-push)    SKIP_PUSH=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

VERSION="$(rpmspec -q --srpm --qf '%{VERSION}-%{RELEASE}\n' \
    "${REPO_ROOT}/xrdofs-openverify.spec" | head -1)"

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

    echo "==> Running RPM build inside container (xrdofs-openverify ${VERSION}) ..."
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
if [[ -z "${OV_RPM}" ]]; then
    echo "ERROR: xrdofs-openverify RPM not found in ${RPM_SRC}" >&2
    exit 1
fi

echo "==> Copying RPM to ${RPM_DST} ..."
cp -v "${OV_RPM}" "${RPM_DST}/"

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
    COMMIT_MSG="Update xrdofs-openverify ${VERSION}"
    HEAD_MSG="$(git -C "${YUM_REPO}" log -1 --pretty=%s 2>/dev/null || true)"

    echo "==> Staging yum repo (xrdofs-openverify ${VERSION}) ..."
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

echo ""
echo "Done. Published xrdofs-openverify ${VERSION}."
echo "Canary: puppet on cms-xrd-global-test (or dnf reinstall the package there)."
