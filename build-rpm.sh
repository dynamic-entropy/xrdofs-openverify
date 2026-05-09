#!/usr/bin/env bash
set -euo pipefail

SPEC_FILE="xrdofs-openverify.spec"

if [[ ! -f "${SPEC_FILE}" ]]; then
  echo "Missing ${SPEC_FILE}" >&2
  exit 1
fi

VERSION="${1:-$(rpmspec -q --srpm --qf '%{VERSION}\n' "${SPEC_FILE}")}"
NAME="$(rpmspec -q --srpm --qf '%{NAME}\n' "${SPEC_FILE}")"

rpmdev-setuptree

git archive --format=tar.gz --prefix="${NAME}-${VERSION}/" \
  -o "$(rpm -E '%{_sourcedir}')/${NAME}-${VERSION}.tar.gz" HEAD
cp "${SPEC_FILE}" "$(rpm -E '%{_specdir}')/"

rpmbuild -ba "$(rpm -E '%{_specdir}')/${SPEC_FILE}"

echo "Built RPMs:"
echo "  $(rpm -E '%{_rpmdir}')"
echo "  $(rpm -E '%{_srcrpmdir}')"
