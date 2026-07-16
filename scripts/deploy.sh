#!/usr/bin/env bash
# deploy.sh
#
# Build the xrdofs-openverify RPM in the podman container, then copy it
# directly to each cluster node and reinstall it there.  No yum repo or
# GitHub Pages involved.
#
# Usage:
#   ./scripts/deploy.sh [--skip-build] [NODE...]
#
# Options:
#   --skip-build    Skip the container image build + RPM build and reuse
#                   whatever RPM is already in ~/rpmbuild.  Useful when you
#                   only want to redeploy the last build to a different set
#                   of nodes.
#
# Examples:
#   ./scripts/deploy.sh                          # build + deploy to all nodes
#   ./scripts/deploy.sh --skip-build             # redeploy last build to all nodes
#   ./scripts/deploy.sh xrdsrv-1.cern.ch         # build + deploy to one node only
#   ./scripts/deploy.sh --skip-build xrdsrv-1.cern.ch xrdsrv-2.cern.ch
#
# SSH / jump host:
#   If the cluster nodes are only reachable via a bastion, set SSH_PROXY:
#     SSH_PROXY=lxplus.cern.ch ./scripts/deploy.sh
#   Or add a Host block in ~/.ssh/config and leave SSH_PROXY unset.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RPMBUILD_DIR="${RPMBUILD_DIR:-${HOME}/rpmbuild}"
ARCH="${ARCH:-x86_64}"

BUILDER_IMAGE="${BUILDER_IMAGE:-openverify-builder}"
XROOTD_VERSION="${XROOTD_VERSION:-6.0.1}"

# SSH user for cluster nodes.
SSH_USER="${SSH_USER:-root}"

# Optional jump/proxy host.  If set, all ssh/scp calls will use -J "$SSH_PROXY".
# Alternatively configure ProxyJump in ~/.ssh/config.
SSH_PROXY="${SSH_PROXY:-}"

# All nodes that run profile::xrootd::cluster.  Pass node names as arguments
# to target a subset.
ALL_NODES=(
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
TARGET_NODES=()

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=1 ;;
        --*)          echo "Unknown option: $arg" >&2; exit 1 ;;
        *)            TARGET_NODES+=("$arg") ;;
    esac
done

if [[ ${#TARGET_NODES[@]} -eq 0 ]]; then
    NODES=("${ALL_NODES[@]}")
else
    NODES=("${TARGET_NODES[@]}")
fi

# Build common SSH/SCP option arrays.
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no)
SCP_OPTS=(-q -o BatchMode=yes -o StrictHostKeyChecking=no)
if [[ -n "${SSH_PROXY}" ]]; then
    SSH_OPTS+=(-J "${SSH_PROXY}")
    SCP_OPTS+=(-J "${SSH_PROXY}")
fi

# ---------------------------------------------------------------------------
# Step 1 – Build RPMs in the container
# ---------------------------------------------------------------------------
if [[ $SKIP_BUILD -eq 0 ]]; then
    echo "==> Building container image ${BUILDER_IMAGE} ..."
    podman build \
        --build-arg XROOTD_VERSION="${XROOTD_VERSION}" \
        --platform linux/amd64 \
        -t "${BUILDER_IMAGE}" \
        -f "${REPO_ROOT}/Containerfile" \
        "${REPO_ROOT}"

    echo "==> Running RPM build inside container ..."
    mkdir -p "${RPMBUILD_DIR}"
    podman run --rm \
        --security-opt label=disable \
        --platform linux/amd64 \
        -v "${RPMBUILD_DIR}:/root/rpmbuild" \
        -v "${REPO_ROOT}:/src:ro" \
        "${BUILDER_IMAGE}"
else
    echo "==> Skipping build (--skip-build)"
fi

# ---------------------------------------------------------------------------
# Locate the main (non-debug, non-src) RPM we just built
# ---------------------------------------------------------------------------
RPM_SRC="${RPMBUILD_DIR}/RPMS/${ARCH}"

if [[ ! -d "${RPM_SRC}" ]]; then
    echo "ERROR: RPM output dir not found: ${RPM_SRC}" >&2
    exit 1
fi

# Pick the most recently built xrdofs-openverify RPM (excludes debuginfo/debugsource)
RPM_PATH="$(ls -t "${RPM_SRC}"/xrdofs-openverify-[0-9]*.rpm 2>/dev/null | head -1)"
if [[ -z "${RPM_PATH}" ]]; then
    echo "ERROR: No xrdofs-openverify RPM found in ${RPM_SRC}" >&2
    exit 1
fi
RPM_FILE="$(basename "${RPM_PATH}")"
echo "==> Using RPM: ${RPM_FILE}"

# ---------------------------------------------------------------------------
# Step 2 – Copy RPM to each node and reinstall in parallel
# ---------------------------------------------------------------------------
echo "==> Deploying to ${#NODES[@]} node(s): ${NODES[*]}"

deploy_to_node() {
    local node="$1"
    local remote_path="/tmp/${RPM_FILE}"

    echo "  [${node}] copying RPM ..."
    if ! scp "${SCP_OPTS[@]}" "${RPM_PATH}" "${SSH_USER}@${node}:${remote_path}"; then
        echo "  [${node}] ERROR: scp failed" >&2
        return 1
    fi

    echo "  [${node}] clearing DNF cache and reinstalling ..."
    if ! ssh "${SSH_OPTS[@]}" "${SSH_USER}@${node}" "
        dnf clean metadata --disablerepo='*' --enablerepo='xrdofs-openverify' 2>/dev/null || true
        dnf reinstall -y '${remote_path}'
        rm -f '${remote_path}'
    "; then
        echo "  [${node}] ERROR: dnf reinstall failed" >&2
        return 1
    fi

    echo "  [${node}] restarting cmsd@cluster and xrootd@cluster ..."
    if ! ssh "${SSH_OPTS[@]}" "${SSH_USER}@${node}" "
        mkdir -p /run/xrootd
        systemctl restart cmsd@cluster
        systemctl restart xrootd@cluster
        systemctl is-active --quiet cmsd@cluster
        systemctl is-active --quiet xrootd@cluster
    "; then
        echo "  [${node}] ERROR: service restart failed (use xrootd@cluster / cmsd@cluster, not xrootd.service)" >&2
        return 1
    fi

    echo "  [${node}] done."
}

export -f deploy_to_node
export RPM_PATH RPM_FILE SSH_USER
export SSH_OPTS SCP_OPTS

# Launch all deployments in parallel, tracking PIDs and node names together.
declare -A pids
for node in "${NODES[@]}"; do
    deploy_to_node "${node}" &
    pids[$!]="${node}"
done

echo "==> Waiting for all deployments to finish ..."
failed=()
for pid in "${!pids[@]}"; do
    node="${pids[$pid]}"
    if ! wait "${pid}"; then
        failed+=("${node}")
    fi
done

echo ""
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "ERROR: deployment failed on: ${failed[*]}" >&2
    exit 1
fi

echo "Done. Deployed ${RPM_FILE} to: ${NODES[*]}"
