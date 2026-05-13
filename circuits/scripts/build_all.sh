#!/usr/bin/env bash
set -euo pipefail

NOIR_VERSION="1.0.0-beta.9"
BB_VERSION="v0.87.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"

export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

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

  nargo_bin="${NARGO:-$(command -v nargo || true)}"
  bb_bin="${BB:-$(command -v bb || true)}"
  if [[ -z "${nargo_bin}" || -z "${bb_bin}" ]]; then
    echo "missing nargo or bb in PATH"
    popd >/dev/null
    exit 1
  fi

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