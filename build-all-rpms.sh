#!/usr/bin/env bash
# Build OpenVerify + xrdmon-collector RPMs from one shared Source0 tarball.
# Used as Containerfile CMD and by ./scripts/publish-rpms-to-yum.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${REPO_ROOT}"

OV_SPEC="xrdofs-openverify.spec"
MON_SPEC="xrdmon-collector.spec"

for f in "${OV_SPEC}" "${MON_SPEC}"; do
  if [[ ! -f "${f}" ]]; then
    echo "Missing ${f}" >&2
    exit 1
  fi
done

OV_VERSION="$(rpmspec -q --srpm --qf '%{VERSION}\n' "${OV_SPEC}" | head -1)"
OV_NAME="$(rpmspec -q --srpm --qf '%{NAME}\n' "${OV_SPEC}" | head -1)"
MON_VERSION="$(rpmspec -q --srpm --qf '%{VERSION}\n' "${MON_SPEC}" | head -1)"

if [[ "${MON_VERSION}" != "${OV_VERSION}" ]]; then
  echo "ERROR: ${MON_SPEC} version (${MON_VERSION}) must match ${OV_SPEC} (${OV_VERSION})" >&2
  exit 1
fi

rpmdev-setuptree
SOURCE_TGZ="$(rpm -E '%{_sourcedir}')/${OV_NAME}-${OV_VERSION}.tar.gz"
SPEC_DIR="$(rpm -E '%{_specdir}')"

echo "==> Creating ${OV_NAME}-${OV_VERSION}.tar.gz from git HEAD ..."
git archive --format=tar.gz --prefix="${OV_NAME}-${OV_VERSION}/" \
  -o "${SOURCE_TGZ}" HEAD

cp "${OV_SPEC}" "${MON_SPEC}" "${SPEC_DIR}/"

echo "==> Building ${OV_SPEC} ..."
rpmbuild -ba "${SPEC_DIR}/${OV_SPEC}"

echo "==> Building ${MON_SPEC} ..."
rpmbuild -ba "${SPEC_DIR}/${MON_SPEC}"

echo "Built RPMs under $(rpm -E '%{_rpmdir}')"
