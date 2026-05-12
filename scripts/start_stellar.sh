#!/bin/bash
set -e

source "$(dirname "${BASH_SOURCE[0]}")/config.sh"

echo -e "${BLUE}Starting Stellar localnet container ($STELLAR_CONTAINER_NAME)...${NC}"
stellar container start -t future --name "$STELLAR_CONTAINER_NAME" --limits unlimited "$@"

echo -e "${BLUE}Configuring network profile ($STELLAR_NETWORK_NAME)...${NC}"
stellar network add "$STELLAR_NETWORK_NAME" \
  --rpc-url "$STELLAR_RPC_URL" \
  --network-passphrase "$STELLAR_NETWORK_PASSPHRASE" || true
stellar network use "$STELLAR_NETWORK_NAME"

echo -e "${BLUE}Waiting for local network to become healthy ($STELLAR_HEALTH_RETRIES attempts)...${NC}"
for i in $(seq 1 "$STELLAR_HEALTH_RETRIES"); do
  OUT=$(stellar network health 2>&1 || true)
  if [[ "$OUT" == *"Unhealthy"* ]]; then
    sleep "$STELLAR_HEALTH_RETRY_INTERVAL"
    continue
  fi
  break
done

echo "Final network health check..."
stellar network health --output json

echo -e "${BLUE}Waiting for friendbot to become ready...${NC}"
for i in $(seq 1 "$STELLAR_HEALTH_RETRIES"); do
  FB_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:8000/friendbot?addr=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHG" \
    2>/dev/null || echo "000")
  if [ "$FB_STATUS" != "502" ] && [ "$FB_STATUS" != "000" ]; then
    echo -e "${GREEN}✓ Friendbot ready (HTTP $FB_STATUS)${NC}"
    break
  fi
  sleep "$STELLAR_HEALTH_RETRY_INTERVAL"
done

echo ""
echo -e "${GREEN}Stellar localnet is running and ready!${NC}"
