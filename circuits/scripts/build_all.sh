#!/usr/bin/env bash
set -euo pipefail

NOIR_VERSION="1.0.0-beta.9"
BB_VERSION="v0.87.0"

# Known-good SHA-256 digests for the Barretenberg release archives of ${BB_VERSION},
# keyed by asset name. The download is fail-closed: an asset with no entry here and
# no BB_SHA256 override is not extracted.
#
# The two darwin entries were each downloaded and hashed locally, and match the
# digest GitHub publishes for that asset; they can be re-checked against the release
# API at any time. GitHub publishes no digest for the linux asset, so its entry is
# the hash of the archive this project was built against, corroborated by the release
# record's byte size (8772757) and by the extracted binary reporting 0.87.0. That
# entry detects the asset changing under a fixed tag, which is what this check is
# for; it is not an upstream attestation.
#
# To re-derive:
#   curl -sfL https://api.github.com/repos/AztecProtocol/aztec-packages/releases/tags/${BB_VERSION} \
#     | jq -r '.assets[] | select(.name|startswith("barretenberg")) | "\(.name) \(.digest)"'
declare -A BB_SHA256_DEFAULT=(
  ["barretenberg-amd64-linux.tar.gz"]="829b714287085ff4562ba2c64f9c8128463650d833bdd1db5d5a33471dcd67cb"
  ["barretenberg-arm64-darwin.tar.gz"]="29007919d4badea047f660f55bcbc38acd6e88f07722cc63f84baec816be1751"
  ["barretenberg-amd64-darwin.tar.gz"]="a996534031c898b65123197979284aa92bd377c1ebc13318a82476a82f9cc781"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"

export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

# Resolve the binaries that will actually be used for every circuit, honouring the
# NARGO/BB overrides, and export them so build_circuit cannot select anything else.
# Asserting against `command -v` alone would be bypassable: a machine can carry the
# expected versions on PATH and still build with an overridden binary.
resolve_toolchain() {
  NARGO_BIN="${NARGO:-$(command -v nargo || true)}"
  BB_BIN="${BB:-$(command -v bb || true)}"
  if [[ -z "${NARGO_BIN}" || -z "${BB_BIN}" ]]; then
    echo "missing nargo or bb (set NARGO/BB or put them on PATH)" >&2; exit 1
  fi
  export NARGO_BIN BB_BIN
}

assert_versions() {
  local nv bv
  nv="$("${NARGO_BIN}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+)?' | head -n1 || true)"
  bv="$("${BB_BIN}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  if [[ "${nv}" != "${NOIR_VERSION}" ]]; then
    echo "nargo version mismatch at '${NARGO_BIN}': found '${nv}', require '${NOIR_VERSION}'" >&2; exit 1
  fi
  if [[ "${bv}" != "${BB_VERSION#v}" ]]; then
    echo "bb version mismatch at '${BB_BIN}': found '${bv}', require '${BB_VERSION#v}'" >&2; exit 1
  fi
  echo "• toolchain verified: nargo ${nv} (${NARGO_BIN}), bb ${bv} (${BB_BIN})"
}

install_nargo() {
  if command -v nargo >/dev/null 2>&1; then return; fi

  echo "• installing nargo ${NOIR_VERSION}"
  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | \
    NOIR_VERSION="${NOIR_VERSION}" bash
  export PATH="$HOME/.nargo/bin:$PATH"
  [ -n "${GITHUB_PATH:-}" ] && echo "$HOME/.nargo/bin" >> "$GITHUB_PATH"
  noirup -v "${NOIR_VERSION}"
}

install_bb() {
  if command -v bb >/dev/null 2>&1; then return; fi

  echo "• installing bb ${BB_VERSION}"
  mkdir -p "$HOME/.bb/bin"

  uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
  uname_m=$(uname -m)
  case "${uname_s}_${uname_m}" in
    linux_x86_64)  file="barretenberg-amd64-linux.tar.gz" ;;
    darwin_arm64)  file="barretenberg-arm64-darwin.tar.gz" ;;
    darwin_x86_64) file="barretenberg-amd64-darwin.tar.gz" ;;
    *)             echo "unsupported platform"; exit 1 ;;
  esac

  url="https://github.com/AztecProtocol/aztec-packages/releases/download/${BB_VERSION}/${file}"
  curl -L "$url" -o /tmp/bb.tar.gz
  # Verify the download before extracting, and fail closed. A warn-and-continue
  # check documents the supply-chain gap rather than closing it.
  expected="${BB_SHA256:-${BB_SHA256_DEFAULT[$file]:-}}"
  if [[ -z "${expected}" ]]; then
    echo "no known-good SHA-256 for ${file}; set BB_SHA256 or add it to BB_SHA256_DEFAULT" >&2
    exit 1
  fi
  echo "${expected}  /tmp/bb.tar.gz" | sha256sum -c - || {
    echo "bb tarball checksum mismatch for ${file}" >&2; exit 1; }
  tar -xzf /tmp/bb.tar.gz -C "$HOME/.bb/bin"
  chmod +x "$HOME/.bb/bin/bb"
  export PATH="$HOME/.bb/bin:$PATH"
  [ -n "${GITHUB_PATH:-}" ] && echo "$HOME/.bb/bin" >> "$GITHUB_PATH"
}

run_tornado_public_inputs_generation() {
  local manifest_path="${REPO_ROOT}/contracts/tornado_classic/contracts/Cargo.toml"
  if [[ ! -f "${manifest_path}" ]]; then
    echo "skip tornado public input generation (missing ${manifest_path})"
    return
  fi

  echo "[tornado] generating Prover.toml inputs (seed=${TORNADO_SEED:-1})"
  (
    cd "${REPO_ROOT}"
    TORNADO_GENERATE=1 TORNADO_SEED="${TORNADO_SEED:-1}" \
      cargo run \
      --example populate_publics \
      --manifest-path contracts/tornado_classic/contracts/Cargo.toml \
      --features std
  )
}

build_circuit() {
  local name="$1"
  local dir="${ROOT}/${name}"
  local nargo_bin bb_bin project_name json gz

  [[ -f "${dir}/Nargo.toml" ]] || {
    echo "skip ${name} (no Nargo.toml)"
    return
  }

  echo "=== Building ${name} ==="
  pushd "${dir}" >/dev/null

  if [[ "${name}" == "tornado" && "${GENERATE_PROVER:-1}" != "0" ]]; then
    run_tornado_public_inputs_generation
  fi

  # Use the binaries resolved and version-asserted by resolve_toolchain /
  # assert_versions. Do not re-resolve here: that is what allowed an overridden
  # binary to pass the assertion and then build the artifacts.
  nargo_bin="${NARGO_BIN}"
  bb_bin="${BB_BIN}"

  if [[ ! -f Prover.toml ]]; then
    "${nargo_bin}" check --overwrite
  fi

  "${nargo_bin}" compile
  "${nargo_bin}" execute

  project_name=$(grep -E '^name\s*=\s*"' Nargo.toml | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
  json="target/${project_name}.json"
  gz="target/${project_name}.gz"

  if [[ ! -f "${json}" || ! -f "${gz}" ]]; then
    echo "missing ACIR (${json}) or witness (${gz})"
    popd >/dev/null
    exit 1
  fi

  "${bb_bin}" prove \
    --scheme ultra_honk \
    --oracle_hash keccak \
    --bytecode_path "${json}" \
    --witness_path "${gz}" \
    --output_path target \
    --output_format bytes_and_fields

  "${bb_bin}" write_vk \
    --scheme ultra_honk \
    --oracle_hash keccak \
    --bytecode_path "${json}" \
    --output_path target \
    --output_format bytes_and_fields

  if [[ "${name}" == "tornado" && "${GENERATE_PROVER:-1}" != "0" ]]; then
    echo "=== Generating E2E artifacts for tornado ==="
    (
      cd "${REPO_ROOT}"
      TORNADO_EMPTY_TREE=1 cargo run \
        --example populate_publics \
        --manifest-path contracts/tornado_classic/contracts/Cargo.toml \
        --features std
    )
    "${nargo_bin}" execute
    "${bb_bin}" prove \
      --scheme ultra_honk \
      --oracle_hash keccak \
      --bytecode_path "${json}" \
      --witness_path "${gz}" \
      --output_path target/e2e \
      --output_format bytes_and_fields
  fi

  if [[ -d target/vk_fields.json && -f target/vk_fields.json/vk_fields.json ]]; then
    mv target/vk_fields.json/vk_fields.json target/vk_fields.json.tmp
    rmdir target/vk_fields.json
    mv target/vk_fields.json.tmp target/vk_fields.json
  fi

  if [[ -d target/vk && -f target/vk/vk ]]; then
    mv target/vk/vk target/vk.tmp
    rmdir target/vk
    mv target/vk.tmp target/vk
  fi

  popd >/dev/null
}

install_nargo
install_bb
resolve_toolchain
assert_versions

if [[ "$#" -gt 0 ]]; then
  TARGETS=("$@")
else
  TARGETS=()
  while IFS= read -r line; do
    TARGETS+=("$line")
  done < <(
    find "$ROOT" -mindepth 1 -maxdepth 1 -type d \
        ! -name scripts \
        -exec sh -c '[ -f "$1/Nargo.toml" ] && basename "$1"' _ {} \;
    )
fi

for name in "${TARGETS[@]}"; do
  build_circuit "$name"
done