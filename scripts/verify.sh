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

PI_SIZE=$(stat -c%s "$PUBLIC_INPUTS")
PROOF_SIZE=$(stat -c%s "$PROOF")

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

# Now run the measurement script for a detailed report
echo -e "\n${BLUE}Generating detailed performance report...${NC}"
SOURCE_SECRET=$(stellar keys secret "$STELLAR_SOURCE_ACCOUNT" | tail -n 1 | tr -d '[:space:]')
pushd "$ROOT_DIR/scripts/measure_ultrahonk_costs" >/dev/null
npm run measure -- \
  --contract-id "$CONTRACT_ID" \
  --source-secret "$SOURCE_SECRET" \
  --dataset "$DATASET_DIR"
popd >/dev/null
