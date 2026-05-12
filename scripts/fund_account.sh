#!/bin/bash
set -e

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

echo -e "${BLUE}Checking/Generating identity for '$STELLAR_SOURCE_ACCOUNT'...${NC}"
stellar keys generate "$STELLAR_SOURCE_ACCOUNT" 2>/dev/null || true

echo -e "${BLUE}Funding '$STELLAR_SOURCE_ACCOUNT' on network '$STELLAR_NETWORK_NAME'...${NC}"

FUNDED=0
for i in $(seq 1 "$STELLAR_HEALTH_RETRIES"); do
  if stellar keys fund "$STELLAR_SOURCE_ACCOUNT" --network "$STELLAR_NETWORK_NAME"; then
    FUNDED=1
    break
  fi
  echo -e "${RED}  Funding failed (attempt $i), retrying in ${STELLAR_HEALTH_RETRY_INTERVAL}s...${NC}"
  sleep "$STELLAR_HEALTH_RETRY_INTERVAL"
done

if [ "$FUNDED" -ne 1 ]; then
  echo -e "${RED}Failed to fund account after $STELLAR_HEALTH_RETRIES attempts.${NC}"
  exit 1
fi

echo -e "${GREEN}Address for '$STELLAR_SOURCE_ACCOUNT':${NC}"
stellar keys address "$STELLAR_SOURCE_ACCOUNT"
