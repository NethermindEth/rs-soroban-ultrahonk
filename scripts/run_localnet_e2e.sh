#!/usr/bin/env bash
set -e

# Thin orchestrator for E2E tests
# It uses the modular script stack to ensure consistency between CI and local dev

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

# Automatic cleanup on exit
cleanup() {
  echo -e "${BLUE}Performing E2E cleanup...${NC}"
  "$SCRIPT_DIR/stop_stellar.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo -e "${BLUE}=== Starting Modular E2E Pipeline ===${NC}"

# 1. Start Network
"$SCRIPT_DIR/start_stellar.sh"

# 2. Setup Account
"$SCRIPT_DIR/fund_account.sh"

# 3. Build & Deploy
"$SCRIPT_DIR/deploy.sh"

# 4. Verify & Measure
"$SCRIPT_DIR/verify.sh"

echo -e "\n${GREEN}=== E2E Pipeline Completed Successfully ===${NC}"
