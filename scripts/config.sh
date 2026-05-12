#!/usr/bin/env bash
set -e

# Load local overrides if they exist
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$ROOT_DIR/.env" ]; then
  # Use set -a to export all variables from .env
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

# Network Configuration
export STELLAR_NETWORK_NAME="${STELLAR_NETWORK_NAME:-local}"
export STELLAR_RPC_URL="${STELLAR_RPC_URL:-http://localhost:8000/soroban/rpc}"
export STELLAR_NETWORK_PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Standalone Network ; February 2017}"

# Deployment & Health Configuration
if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  # CI environment: 5-minute window for robustness
  export STELLAR_DEPLOY_RETRIES="${STELLAR_DEPLOY_RETRIES:-90}"
  export STELLAR_DEPLOY_RETRY_INTERVAL="${STELLAR_DEPLOY_RETRY_INTERVAL:-10}"
  export STELLAR_HEALTH_RETRIES="${STELLAR_HEALTH_RETRIES:-150}"
  export STELLAR_HEALTH_RETRY_INTERVAL="${STELLAR_HEALTH_RETRY_INTERVAL:-2}"
else
  # Local environment: 2-minute window for friendbot to initialize
  export STELLAR_DEPLOY_RETRIES="${STELLAR_DEPLOY_RETRIES:-24}"
  export STELLAR_DEPLOY_RETRY_INTERVAL="${STELLAR_DEPLOY_RETRY_INTERVAL:-10}"
  export STELLAR_HEALTH_RETRIES="${STELLAR_HEALTH_RETRIES:-120}"
  export STELLAR_HEALTH_RETRY_INTERVAL="${STELLAR_HEALTH_RETRY_INTERVAL:-1}"
fi

# Account Configuration
export STELLAR_SOURCE_ACCOUNT="${STELLAR_SOURCE_ACCOUNT:-alice}"

# Container Configuration
export STELLAR_CONTAINER_NAME="${STELLAR_CONTAINER_NAME:-stellar-local}"

# Paths
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CONTRACT_WASM="$ROOT_DIR/target/wasm32v1-none/release/rs_soroban_ultrahonk.wasm"
export CONTRACT_ID_FILE="$ROOT_DIR/.contract_id"
export DATASET_DIR="$ROOT_DIR/contracts/rs-soroban-ultrahonk/tests/simple_circuit/target"
export BUILD_CIRCUITS_SCRIPT="$ROOT_DIR/contracts/rs-soroban-ultrahonk/tests/build_circuits.sh"

# Colors for output
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export BLUE='\033[0;34m'
export NC='\033[0m'
