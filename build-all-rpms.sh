#!/usr/bin/env bash
# Build the OpenVerify RPM from a Source0 tarball of git HEAD.
# Used as Containerfile CMD and by ./scripts/publish-rpms-to-yum.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${REPO_ROOT}"

OV_SPEC="xrdofs-openverify.spec"

if [[ ! -f "${OV_SPEC}" ]]; then
  echo "Missing ${OV_SPEC}" >&2
  exit 1
fi

OV_VERSION="$(rpmspec -q --srpm --qf '%{VERSION}\n' "${OV_SPEC}" | head -1)"
OV_NAME="$(rpmspec -q --srpm --qf '%{NAME}\n' "${OV_SPEC}" | head -1)"

rpmdev-setuptree
SOURCE_TGZ="$(rpm -E '%{_sourcedir}')/${OV_NAME}-${OV_VERSION}.tar.gz"
SPEC_DIR="$(rpm -E '%{_specdir}')"

echo "==> Creating ${OV_NAME}-${OV_VERSION}.tar.gz from git HEAD ..."
git archive --format=tar.gz --prefix="${OV_NAME}-${OV_VERSION}/" \
  -o "${SOURCE_TGZ}" HEAD

cp "${OV_SPEC}" "${SPEC_DIR}/"

echo "==> Building ${OV_SPEC} ..."
rpmbuild -ba "${SPEC_DIR}/${OV_SPEC}"

echo "Built RPMs under $(rpm -E '%{_rpmdir}')"
