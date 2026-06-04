#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Identity E2E — End-to-end flow for the Identity contract
# =============================================================================
# This script demonstrates the full flow of proving identity on-chain:
#
#   1. Build the Noir circuit (generate proof, vk, public inputs)
#   2. Build the Soroban identity contract
#   3. Deploy the contract with the verification key
#   4. Call prove_identity() with the proof and public inputs
#
# Usage:
#   ./scripts/run_identity_e2e.sh [network]
#
#   network: local (default) | testnet
#
# Example:
#   ./scripts/run_identity_e2e.sh
#   ./scripts/run_identity_e2e.sh testnet
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${SCRIPT_DIR}/config.sh"

# Override network if provided
if [[ "${1:-}" == "testnet" ]]; then
  export STELLAR_NETWORK_NAME="testnet"
  export STELLAR_RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
  export STELLAR_NETWORK_PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
fi

# Start localnet automatically if needed
if [[ "${STELLAR_NETWORK_NAME}" == "local" ]]; then
  if ! curl -sf "${STELLAR_RPC_URL}" >/dev/null 2>&1; then
    echo -e "${BLUE}Localnet not running, starting it...${NC}"
    "${SCRIPT_DIR}/start_stellar.sh"
  fi
fi

CIRCUIT_NAME="identity"
CIRCUIT_DIR="${ROOT_DIR}/circuits/${CIRCUIT_NAME}"
TARGET_DIR="${CIRCUIT_DIR}/target"
CONTRACT_WASM="${ROOT_DIR}/target/wasm32v1-none/release/identity.wasm"
IDENTITY_CONTRACT_ID_FILE="${ROOT_DIR}/.identity_contract_id"

# ---------------------------------------------------------------------------
# 1. Build circuit
# ---------------------------------------------------------------------------
echo -e "${BLUE}=== Step 1: Building identity circuit ===${NC}"
just build-circuits "${CIRCUIT_NAME}"

if [[ ! -f "${TARGET_DIR}/proof" || ! -f "${TARGET_DIR}/vk" || ! -f "${TARGET_DIR}/public_inputs" ]]; then
  echo -e "${RED}Circuit artifacts missing in ${TARGET_DIR}${NC}"
  exit 1
fi

if [ "$(uname)" = "Darwin" ]; then
    PI_SIZE=$(stat -f%z "${TARGET_DIR}/public_inputs")
    PROOF_SIZE=$(stat -f%z "${TARGET_DIR}/proof")
    VK_SIZE=$(stat -f%z "${TARGET_DIR}/vk")
else
    PI_SIZE=$(stat -c%s "${TARGET_DIR}/public_inputs")
    PROOF_SIZE=$(stat -c%s "${TARGET_DIR}/proof")
    VK_SIZE=$(stat -c%s "${TARGET_DIR}/vk")
fi

echo "  Public inputs : ${PI_SIZE} bytes"
echo "  Proof         : ${PROOF_SIZE} bytes"
echo "  VK            : ${VK_SIZE} bytes"

# ---------------------------------------------------------------------------
# 2. Build contract
# ---------------------------------------------------------------------------
echo -e "${BLUE}=== Step 2: Building identity contract ===${NC}"
stellar contract build

if [[ ! -f "${CONTRACT_WASM}" ]]; then
  echo -e "${RED}Contract WASM not found: ${CONTRACT_WASM}${NC}"
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. Fund account
# ---------------------------------------------------------------------------
echo -e "${BLUE}=== Step 3: Ensuring account is funded ===${NC}"
"${SCRIPT_DIR}/fund_account.sh"

# ---------------------------------------------------------------------------
# 4. Deploy contract with VK
# ---------------------------------------------------------------------------
echo -e "${BLUE}=== Step 4: Deploying identity contract ===${NC}"
DEPLOY_OK=0
for attempt in $(seq 1 "${STELLAR_DEPLOY_RETRIES}"); do
  echo "  Deployment attempt ${attempt}/${STELLAR_DEPLOY_RETRIES}..."
  if CONTRACT_ID=$(stellar contract deploy \
    --wasm "${CONTRACT_WASM}" \
    --source "${STELLAR_SOURCE_ACCOUNT}" \
    --network "${STELLAR_NETWORK_NAME}" \
    -- \
    --vk_bytes-file-path "${TARGET_DIR}/vk"); then
    DEPLOY_OK=1
    break
  fi
  echo -e "${RED}    Deployment failed, retrying in ${STELLAR_DEPLOY_RETRY_INTERVAL}s...${NC}"
  sleep "${STELLAR_DEPLOY_RETRY_INTERVAL}"
done

if [[ "${DEPLOY_OK}" -ne 1 ]]; then
  echo -e "${RED}Failed to deploy contract after ${STELLAR_DEPLOY_RETRIES} attempts.${NC}"
  exit 1
fi

echo "${CONTRACT_ID}" > "${IDENTITY_CONTRACT_ID_FILE}"
echo -e "${GREEN}  Contract deployed: ${CONTRACT_ID}${NC}"
echo "  (saved to ${IDENTITY_CONTRACT_ID_FILE})"

# ---------------------------------------------------------------------------
# 5. Invoke prove_identity
# ---------------------------------------------------------------------------
echo -e "${BLUE}=== Step 5: Proving identity on-chain ===${NC}"
stellar contract invoke \
  --id "${CONTRACT_ID}" \
  --source "${STELLAR_SOURCE_ACCOUNT}" \
  --network "${STELLAR_NETWORK_NAME}" \
  --send yes \
  -- \
  prove_identity \
  --public_inputs-file-path "${TARGET_DIR}/public_inputs" \
  --proof_bytes-file-path "${TARGET_DIR}/proof"

echo -e "\n${GREEN}=== Identity proven successfully! ===${NC}"
echo "  Contract: ${CONTRACT_ID}"
echo "  Network:  ${STELLAR_NETWORK_NAME}"

# ---------------------------------------------------------------------------
# 6. Measure costs
# ---------------------------------------------------------------------------
if [[ "${STELLAR_NETWORK_NAME}" == "local" ]]; then
  echo -e "${BLUE}=== Step 6: Measuring resource costs ===${NC}"
  SOURCE_SECRET=$(stellar keys secret "${STELLAR_SOURCE_ACCOUNT}" | tail -n 1 | tr -d '[:space:]')
  pushd "$ROOT_DIR/scripts/measure_ultrahonk_costs" >/dev/null
  npm run measure -- \
    --contract-id "${CONTRACT_ID}" \
    --source-secret "${SOURCE_SECRET}" \
    --dataset "${TARGET_DIR}" \
    --rpc-url "${STELLAR_RPC_URL}" \
    --network-passphrase "${STELLAR_NETWORK_PASSPHRASE}" \
    --method prove_identity
  popd >/dev/null
fi
