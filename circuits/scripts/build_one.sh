#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <circuit-name>"
  exit 1
fi

"${SCRIPT_DIR}/build_all.sh" "$1"