#!/usr/bin/env bash
set -e

# Thin orchestrator for running the full deploy + verify flow against the
# Stellar public testnet. Mirrors run_localnet_e2e.sh but skips the Docker
# localnet bootstrap.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Force testnet for every child script via the env-var protocol exposed by
# config.sh. Users can still override the source account / RPC URL by
# exporting STELLAR_SOURCE_ACCOUNT or STELLAR_RPC_URL before invoking us.
export STELLAR_NETWORK_NAME="testnet"

source "$SCRIPT_DIR/config.sh"

echo -e "${BLUE}=== Starting Testnet E2E Pipeline ===${NC}"
echo -e "${BLUE}Network: $STELLAR_NETWORK_NAME${NC}"
echo -e "${BLUE}RPC:     $STELLAR_RPC_URL${NC}"
echo -e "${BLUE}Account: $STELLAR_SOURCE_ACCOUNT${NC}"

# 1. Register network profile + ensure account exists/funded via friendbot.
"$SCRIPT_DIR/fund_account.sh"

# 2. Build & deploy contract to testnet.
"$SCRIPT_DIR/deploy.sh"

# 3. Verify proof on-chain. Cost measurement is skipped by default on testnet
#    because it requires extracting the source-account secret. Re-enable with
#    MEASURE_COSTS=1.
"$SCRIPT_DIR/verify.sh"

echo -e "\n${GREEN}=== Testnet E2E Pipeline Completed Successfully ===${NC}"
