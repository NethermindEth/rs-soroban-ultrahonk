#!/bin/bash
set -e

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

echo -e "${BLUE}1. Ensuring $STELLAR_SOURCE_ACCOUNT account is set up...${NC}"
./scripts/fund_account.sh

echo -e "${BLUE}2. Rebuilding circuits...${NC}"
# Run the build circuit script to generate the VK, proof, public_inputs
bash "$BUILD_CIRCUITS_SCRIPT"

echo -e "${BLUE}3. Building the Soroban contract...${NC}"
stellar contract build

echo -e "${BLUE}4. Deploying the contract to $STELLAR_NETWORK_NAME...${NC}"
DEPLOY_OK=0
for attempt in $(seq 1 "$STELLAR_DEPLOY_RETRIES"); do
  echo "Deployment attempt $attempt/$STELLAR_DEPLOY_RETRIES..."
  if CONTRACT_ID=$(stellar contract deploy \
    --wasm "$CONTRACT_WASM" \
    --source "$STELLAR_SOURCE_ACCOUNT" \
    --network "$STELLAR_NETWORK_NAME" \
    -- \
    --vk_bytes-file-path "$DATASET_DIR/vk"); then
    DEPLOY_OK=1
    break
  fi
  echo -e "${RED}  Deployment failed (attempt $attempt), retrying in ${STELLAR_DEPLOY_RETRY_INTERVAL} seconds...${NC}"
  sleep "$STELLAR_DEPLOY_RETRY_INTERVAL"
done

if [[ "$DEPLOY_OK" -ne 1 ]]; then
  echo -e "${RED}Failed to deploy contract after $STELLAR_DEPLOY_RETRIES attempts.${NC}"
  exit 1
fi

echo "$CONTRACT_ID" > "$CONTRACT_ID_FILE"

echo -e "\n${GREEN}Contract deployed successfully! Contract ID:${NC}"
echo -e "${BLUE}$CONTRACT_ID (saved to $(basename "$CONTRACT_ID_FILE"))${NC}"
