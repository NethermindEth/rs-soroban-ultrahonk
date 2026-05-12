#!/bin/bash
set -e

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

echo -e "${RED}Stopping Stellar localnet container ($STELLAR_CONTAINER_NAME)...${NC}"
stellar container stop "$STELLAR_CONTAINER_NAME" || true

echo -e "${GREEN}Stellar localnet container stopped.${NC}"
