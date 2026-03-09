#!/usr/bin/env bash
set -euo pipefail

NOIR_VERSION="1.0.0-beta.18"

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.bb/bin:$PATH"

install_nargo() {
  if ! command -v nargo >/dev/null 2>&1; then
    echo "• installing nargo $NOIR_VERSION"
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | \
      NOIR_VERSION="$NOIR_VERSION" bash
    export PATH="$HOME/.nargo/bin:$PATH"
    [ -n "${GITHUB_PATH:-}" ] && echo "$HOME/.nargo/bin" >> "$GITHUB_PATH"

    noirup -v "$NOIR_VERSION"
  fi
}

install_bb() {
  if command -v bb >/dev/null 2>&1; then return; fi

  echo "• installing bb (compatible with nargo $NOIR_VERSION)"
  curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
  export PATH="$HOME/.bb:$PATH"
  [ -n "${GITHUB_PATH:-}" ] && echo "$HOME/.bb" >> "$GITHUB_PATH"

  bbup -nv "$NOIR_VERSION"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

install_nargo
install_bb

for dir in tests/* ; do
  [ -d "$dir" ] || continue
  [ -f "$dir/Nargo.toml" ] || continue

  name=$(basename "$dir")
  echo "► building $name"
  pushd "$dir" >/dev/null

  [ -f Prover.toml ] || nargo check --overwrite
  nargo execute

  json="target/${name}.json"
  gz="target/${name}.gz"

  bb write_vk -b "$json" -o target \
    --verifier_target evm-no-zk

  bb prove -b "$json" -w "$gz" -o target \
    --verifier_target evm-no-zk

  # Flatten nested directories that bb may create
  if [[ -d target/vk && -f target/vk/vk ]]; then
    mv target/vk/vk target/vk.tmp
    rmdir target/vk
    mv target/vk.tmp target/vk
  fi

  popd >/dev/null
done
