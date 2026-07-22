#!/usr/bin/env bash
# publish-rpms-to-yum.sh
#
# End-to-end deploy script:
#   1. Build RPMs inside the podman container (OpenVerify + xrdmon-collector)
#   2. Copy the new binary RPMs into the local yum repo checkout
#   3. Regenerate repodata with createrepo_c
#   4. Commit and push the yum repo to GitHub (Pages serves it as the DNF repo)
#   5. Trigger puppet agent runs on every cluster node so they pick up the new
#      package without waiting for the next scheduled run
#
# Usage:
#   ./scripts/publish-rpms-to-yum.sh [--skip-build] [--skip-push] [--skip-puppet]
#
# Options:
#   --skip-build    Reuse whatever RPMs are already in ~/rpmbuild (e.g. you
#                   already ran the container build manually)
#   --skip-push     Stop after updating repodata; don't commit/push yum repo
#   --skip-puppet   Stop after pushing yum repo; don't SSH to nodes
#
# Prerequisites on this machine:
#   podman, createrepo_c, git, ssh (key auth to cluster nodes)
#
# The cluster nodes are derived from the puppet site manifest; edit NODES below
# if your hostnames differ.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config – adjust if your paths or image names differ
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YUM_REPO="${YUM_REPO:-${HOME}/dev/yum}"
RPMBUILD_DIR="${RPMBUILD_DIR:-${HOME}/rpmbuild}"
OS_VER="${OS_VER:-el10}"
ARCH="${ARCH:-x86_64}"

BUILDER_IMAGE="${BUILDER_IMAGE:-openverify-builder}"
XROOTD_VERSION="${XROOTD_VERSION:-6.0.1}"

# SSH user for cluster nodes (key auth as root, matching deploy.sh).
SSH_USER="${SSH_USER:-root}"

# Optional jump/proxy host.  If set, all ssh calls will use -J "$SSH_PROXY".
SSH_PROXY="${SSH_PROXY:-}"

# All nodes that run profile::xrootd::cluster (derived from site.pp / cluster.pp)
NODES=(
    xrdmetaman.cern.ch
    xrdman-1.cern.ch
    xrdman-2.cern.ch
    xrdsrv-1.cern.ch
    xrdsrv-2.cern.ch
    xrdsrv-3.cern.ch
    xrdsrv-4.cern.ch
)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
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

    echo "==> Running RPM build inside container ..."
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

echo "==> Copying RPMs from ${RPM_SRC} to ${RPM_DST} ..."
# OpenVerify plugin + AAA monitor collector (skip unrelated leftovers in rpmbuild)
find "${RPM_SRC}" \( -name 'xrdofs-openverify*.rpm' -o -name 'xrdmon-collector*.rpm' \) \
  -exec cp -v {} "${RPM_DST}/" \;

# ---------------------------------------------------------------------------
# Step 3 – Regenerate repodata
# ---------------------------------------------------------------------------
echo "==> Regenerating repodata in ${RPM_DST} ..."
createrepo_c --update "${RPM_DST}"

# ---------------------------------------------------------------------------
# Step 4 – Commit and push yum repo
# ---------------------------------------------------------------------------
if [[ $SKIP_PUSH -eq 0 ]]; then
    VERSION="$(rpmspec -q --srpm --qf '%{VERSION}-%{RELEASE}\n' \
        "${REPO_ROOT}/xrdofs-openverify.spec" | head -1)"
    XRD_MON_VER="$(rpmspec -q --srpm --qf '%{VERSION}-%{RELEASE}\n' \
        "${REPO_ROOT}/xrdmon-collector.spec" | head -1)"

    echo "==> Committing yum repo (openverify ${VERSION}, xrdmon-collector ${XRD_MON_VER}) ..."
    git -C "${YUM_REPO}" add "${OS_VER}/"
    git -C "${YUM_REPO}" commit -m "Update xrdofs-openverify ${VERSION}; xrdmon-collector ${XRD_MON_VER}"
    git -C "${YUM_REPO}" push

    echo "==> yum repo pushed; GitHub Pages will serve the updated metadata shortly."
else
    echo "==> Skipping git push (--skip-push)"
fi

# ---------------------------------------------------------------------------
# Step 5 – Run puppet agent on every cluster node
# ---------------------------------------------------------------------------
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no)
if [[ -n "${SSH_PROXY}" ]]; then
    SSH_OPTS+=(-J "${SSH_PROXY}")
fi

if [[ $SKIP_PUPPET -eq 0 && $SKIP_PUSH -eq 0 ]]; then
    echo "==> Triggering puppet agent runs on cluster nodes ..."
    # Wait briefly for GitHub Pages to propagate before the first node fetches.
    sleep 10

    for node in "${NODES[@]}"; do
        echo "  -> ${node}"
        # --no-daemonize + --onetime: run once, stay in foreground so errors are visible.
        # We clear the DNF cache first so puppet picks up the freshly-published
        # repodata even though the package version string hasn't changed.
        # Already root: no sudo needed.
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
echo "Done."
