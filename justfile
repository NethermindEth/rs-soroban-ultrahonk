# Ultrahonk Verifier — task runner
# Install `just` (https://github.com/casey/just) then run `just` for help.

set dotenv-load := true
set shell := ["bash", "-cu"]

# Show available commands (default)
default:
    @just --list

# Check dependencies, install Node packages, add Rust target
setup:
    ./scripts/setup.sh

# Start the Stellar localnet container (pass extra args to `stellar container start`)
start *args="":
    ./scripts/start_stellar.sh {{args}}

# Stop the Stellar localnet container
stop:
    ./scripts/stop_stellar.sh

# Generate and fund the source account
fund:
    ./scripts/fund_account.sh

# Build circuits (proof, vk, public_inputs)
build-circuits:
    bash ./contracts/rs-soroban-ultrahonk/tests/build_circuits.sh

# Build the Soroban contract WASM (pass extra args to `stellar contract build`)
build-contract *args="":
    stellar contract build {{args}}

# Deploy contract (builds circuits, builds contract, deploys with retry logic)
deploy:
    ./scripts/deploy.sh

# Verify proof on-chain and generate performance report.
# If no contract_id is provided, reads from .contract_id file.
verify contract_id="":
    ./scripts/verify.sh {{contract_id}}

# Run the full localnet E2E pipeline (start → fund → deploy → verify)
e2e:
    ./scripts/run_localnet_e2e.sh

# Clean up: stop container and remove generated contract ID
clean:
    ./scripts/stop_stellar.sh 2>/dev/null || true
    rm -f .contract_id
    @echo "Cleaned up localnet state"
