# Ultrahonk Verifier — task runner
# Install `just` (https://github.com/casey/just) then run `just` for help.

set dotenv-load := true
set shell := ["bash", "-cu"]

# =============================================================================
# General
# =============================================================================

# Show available commands (default)
default:
    @just --list

# Check dependencies, install Node packages, add Rust target
setup:
    ./scripts/setup.sh

# Clean up: stop container and remove generated contract IDs
clean:
    ./scripts/stop_stellar.sh 2>/dev/null || true
    rm -f .contract_id .identity_contract_id
    @echo "Cleaned up localnet state"

# =============================================================================
# Network
# =============================================================================

# Start the Stellar localnet container (pass extra args to `stellar container start`)
start *args="":
    ./scripts/start_stellar.sh {{args}}

# Stop the Stellar localnet container
stop:
    ./scripts/stop_stellar.sh

# Generate and fund the source account
fund:
    ./scripts/fund_account.sh

# =============================================================================
# Circuits
# =============================================================================

# Build circuits (proof, vk, public_inputs). Builds all circuits by default;
# pass one or more names to build only those (e.g. `just build-circuits simple_circuit identity`).
build-circuits *names="":
    bash ./circuits/scripts/build_all.sh {{names}}

# =============================================================================
# Contracts — General
# =============================================================================

# Build the Soroban contract WASM (pass extra args to `stellar contract build`)
build-contract *args="":
    stellar contract build {{args}}

# =============================================================================
# Tornado / Default Verifier Contract
# =============================================================================

# Deploy the default (Tornado) verifier contract (builds circuits, builds contract, deploys with retry logic)
deploy:
    ./scripts/deploy.sh

# Verify proof on-chain and generate performance report.
# If no contract_id is provided, reads from .contract_id file.
verify contract_id="":
    ./scripts/verify.sh {{contract_id}}

# Run the full localnet E2E pipeline (start → fund → deploy → verify)
e2e:
    ./scripts/run_localnet_e2e.sh

# Run the full testnet E2E pipeline (fund → deploy → verify)
testnet:
    ./scripts/run_testnet_e2e.sh

# =============================================================================
# Identity Contract
# =============================================================================

# Build only the Identity contract WASM
build-identity-contract:
    cargo build --release --target wasm32v1-none --package identity

# Deploy the Identity contract with the identity circuit's VK
deploy-identity:
    #!/usr/bin/env bash
    set -euo pipefail
    source ./scripts/config.sh
    CIRCUIT_DIR="$ROOT_DIR/circuits/identity"
    CONTRACT_WASM="$ROOT_DIR/target/wasm32v1-none/release/identity.wasm"
    just build-circuits identity
    stellar contract build
    ./scripts/fund_account.sh
    CONTRACT_ID=$(stellar contract deploy \
      --wasm "$CONTRACT_WASM" \
      --source "$STELLAR_SOURCE_ACCOUNT" \
      --network "$STELLAR_NETWORK_NAME" \
      -- \
      --vk_bytes-file-path "$CIRCUIT_DIR/target/vk")
    echo "$CONTRACT_ID" > "$ROOT_DIR/.identity_contract_id"
    echo "Identity contract deployed: $CONTRACT_ID"

# Verify an identity proof on-chain.
# If no contract_id is provided, reads from .identity_contract_id file.
verify-identity contract_id="":
    #!/usr/bin/env bash
    set -euo pipefail
    source ./scripts/config.sh
    CIRCUIT_DIR="$ROOT_DIR/circuits/identity"
    if [ -z "{{contract_id}}" ]; then
      CONTRACT_ID=$(cat "$ROOT_DIR/.identity_contract_id")
    else
      CONTRACT_ID="{{contract_id}}"
    fi
    stellar contract invoke \
      --id "$CONTRACT_ID" \
      --source "$STELLAR_SOURCE_ACCOUNT" \
      --network "$STELLAR_NETWORK_NAME" \
      --send yes \
      -- \
      prove_identity \
      --public_inputs-file-path "$CIRCUIT_DIR/target/public_inputs" \
      --proof_bytes-file-path "$CIRCUIT_DIR/target/proof"

# Run the full Identity E2E pipeline (build circuit → build contract → deploy → prove)
identity-e2e network="local":
    ./scripts/run_identity_e2e.sh {{network}}
