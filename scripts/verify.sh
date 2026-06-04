#!/bin/bash
set -e

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

if [ -z "$1" ]; then
  if [ -f "$CONTRACT_ID_FILE" ]; then
    CONTRACT_ID=$(cat "$CONTRACT_ID_FILE")
    echo -e "${BLUE}Auto-loaded CONTRACT_ID: $CONTRACT_ID${NC}"
  else
    echo -e "${RED}Usage: $0 <CONTRACT_ID>${NC}"
    echo "Or run scripts/deploy.sh first to generate $(basename "$CONTRACT_ID_FILE") automatically."
    exit 1
  fi
else
  CONTRACT_ID="$1"
fi

PUBLIC_INPUTS="$DATASET_DIR/public_inputs"
PROOF="$DATASET_DIR/proof"

if [ ! -f "$PUBLIC_INPUTS" ] || [ ! -f "$PROOF" ]; then
  echo -e "${RED}Error: Verification artifacts not found at $PUBLIC_INPUTS or $PROOF${NC}"
  exit 1
fi

if [ "$(uname)" = "Darwin" ]; then
    PI_SIZE=$(stat -f%z "$PUBLIC_INPUTS")
    PROOF_SIZE=$(stat -f%z "$PROOF")
else
    PI_SIZE=$(stat -c%s "$PUBLIC_INPUTS")
    PROOF_SIZE=$(stat -c%s "$PROOF")
fi

echo -e "${BLUE}--- Artifact Summary ---${NC}"
echo "Public Inputs : $PI_SIZE bytes"
echo "Proof         : $PROOF_SIZE bytes"
echo "------------------------"

echo -e "${BLUE}Invoking verify_proof on contract $CONTRACT_ID...${NC}"
stellar contract invoke \
  --id "$CONTRACT_ID" \
  --source "$STELLAR_SOURCE_ACCOUNT" \
  --network "$STELLAR_NETWORK_NAME" \
  --send yes \
  -- \
  verify_proof \
  --public_inputs-file-path "$PUBLIC_INPUTS" \
  --proof_bytes-file-path "$PROOF"

echo -e "\n${GREEN}Proof successfully verified on-chain!${NC}"

# Cost measurement: enabled on local by default; opt-in elsewhere because it
# extracts the source account secret to drive a JS measurement run.
# Override with MEASURE_COSTS=1 or MEASURE_COSTS=0.
if [[ -z "${MEASURE_COSTS:-}" ]]; then
  if [[ "$STELLAR_NETWORK_NAME" == "local" ]]; then
    MEASURE_COSTS=1
  else
    MEASURE_COSTS=0
  fi
fi

if [[ "$MEASURE_COSTS" == "1" ]]; then
  echo -e "\n${BLUE}Generating detailed performance report...${NC}"
  SOURCE_SECRET=$(stellar keys secret "$STELLAR_SOURCE_ACCOUNT" | tail -n 1 | tr -d '[:space:]')
  SUBMIT_ARG=()
  if [[ "${MEASURE_SUBMIT:-0}" == "1" ]]; then
    SUBMIT_ARG=(--submit)
  fi
  pushd "$ROOT_DIR/scripts/measure_ultrahonk_costs" >/dev/null
  npm run measure -- \
    --contract-id "$CONTRACT_ID" \
    --source-secret "$SOURCE_SECRET" \
    --dataset "$DATASET_DIR" \
    --rpc-url "$STELLAR_RPC_URL" \
    --network-passphrase "$STELLAR_NETWORK_PASSPHRASE" \
    "${SUBMIT_ARG[@]}"
  popd >/dev/null
else
  echo -e "\n${BLUE}Skipping cost measurement on '$STELLAR_NETWORK_NAME' (set MEASURE_COSTS=1 to enable).${NC}"
fi
