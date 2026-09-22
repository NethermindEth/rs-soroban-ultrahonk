#!/usr/bin/env bash
# Compare every circuit's freshly built verification key against the committed
# known-good digests in circuits/ARTIFACT_HASHES.txt (OpenZeppelin audit N-06).
#
# The circuit build outputs under circuits/<name>/target/ are gitignored, so this
# manifest is the repository's only record of what the reviewed artifacts were.
# Only the `vk` is hashed: it commits to the circuit's selector and permutation
# polynomials, so an unchanged VK implies unchanged ACIR for a fixed bb version,
# while the proof and public-input files can legitimately vary with prover inputs.
#
# Usage:
#   circuits/scripts/check_artifact_hashes.sh           # verify; non-zero on drift
#   circuits/scripts/check_artifact_hashes.sh --update  # rewrite the manifest
#
# Run after circuits/scripts/build_all.sh. Regenerate the manifest only when a
# circuit, the vendored Poseidon2 source, or the pinned toolchain is changed on
# purpose; every entry change is a change to an on-chain verification key.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MANIFEST="circuits/ARTIFACT_HASHES.txt"
cd "${REPO_ROOT}"

circuit_vks() {
  local dir
  for dir in circuits/*/; do
    dir="${dir%/}"
    [[ "$(basename "${dir}")" == "vendor" ]] && continue
    [[ -f "${dir}/Nargo.toml" ]] || continue
    echo "${dir}/target/vk"
  done | sort
}

if [[ "${1:-}" == "--update" ]]; then
  : > "${MANIFEST}"
  while read -r vk; do
    [[ -f "${vk}" ]] || { echo "missing ${vk}; build the circuits first" >&2; exit 1; }
    sha256sum "${vk}" >> "${MANIFEST}"
  done < <(circuit_vks)
  echo "wrote ${MANIFEST}:"; cat "${MANIFEST}"
  exit 0
fi

[[ -f "${MANIFEST}" ]] || { echo "${MANIFEST} not found" >&2; exit 1; }

# Every circuit must have an entry, so a new circuit cannot slip in unpinned.
missing=0
while read -r vk; do
  if ! grep -q " ${vk}\$" "${MANIFEST}"; then
    echo "no manifest entry for ${vk}; run $0 --update after reviewing the new key" >&2
    missing=1
  fi
done < <(circuit_vks)
[[ "${missing}" -eq 0 ]] || exit 1

# --strict: a malformed line is an error, not a skip.
sha256sum --check --strict "${MANIFEST}"
echo "• circuit verification keys match ${MANIFEST}"
