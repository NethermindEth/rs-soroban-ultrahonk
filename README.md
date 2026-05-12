# rs-soroban-ultrahonk

Soroban contract wrapper around the Noir(UltraHonk) verifier. The VK is set at deploy time; proofs are verified with `public_inputs` and `proof`.

## Requirements Installation

Before you begin, ensure you have the following tools installed:

### 1. Rust and WASM target
Install Rust using [rustup](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32v1-none
```

### 2. Stellar CLI
Install the Soroban/Stellar CLI. We recommend using a recent version:
```bash
cargo install --locked stellar-cli@^3.2.0
```

### 3. Noir and Barretenberg
This project uses **Noir `1.0.0-beta.9`** and **Barretenberg `0.87.0`**. Install them using their respective version managers:
```bash
# Install noirup and switch to Noir 1.0.0-beta.9
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -v 1.0.0-beta.9

# Install bbup and switch to Barretenberg 0.87.0
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash
bbup -v 0.87.0
```

### 4. Node.js
For the helper scripts used to invoke verified transactions (`scripts/invoke_ultrahonk`), ensure you have Node.js and npm installed:
- [Install Node.js](https://nodejs.org/)

### 5. Docker
Docker is required to run the local Standalone Network container (`stellar container start`).
- [Install Docker Desktop](https://www.docker.com/products/docker-desktop/) or Docker Engine depending on your system.

### 6. `just` (task runner)
We use [`just`](https://github.com/casey/just) as a convenient task runner for discoverability. Install it via cargo:
```bash
cargo install just
```
Once installed, run `just --list` to see all available commands.

## Quickstart (localnet)

Run `just --list` at any time to see available commands. The common workflow is:

### 1. Start the Network
Start a local Stellar network in a Docker container and configure your environment:
```bash
just start
```
*Optional: pass extra args to `stellar container start`, e.g. `just start --limits unlimited`*

### 2. Deploy the Contract
This will automatically fund your `alice` test account, compile the Noir circuits, build the Soroban contract, and deploy it to the localnet:
```bash
just deploy
```
*(The generated `CONTRACT_ID` is saved locally to `.contract_id`)*

### 3. Verify a Proof
To simulate the verifier on-chain using the ZK proofs generated in the previous step:
```bash
just verify
```
*This automatically reads from `.contract_id` and executes `verify_proof` against your deployed contract. You can also pass a contract ID explicitly: `just verify <CONTRACT_ID>`*

### Stop the Network
When you're done, tear down the container:
```bash
just stop
```

### One-shot E2E
To run the full pipeline (start → fund → deploy → verify) in one command:
```bash
just e2e
```

## Available `just` commands

| Command                     | Description                                                     |
|-----------------------------|-----------------------------------------------------------------|
| `just setup`                | Check dependencies, install Node packages, add Rust target      |
| `just start`                | Start the Stellar localnet container                            |
| `just stop`                 | Stop the Stellar localnet container                             |
| `just fund`                 | Generate and fund the `alice` test account                      |
| `just build-circuits`       | Compile Noir circuits and generate proof, VK, and public inputs |
| `just build-contract`       | Build the Soroban contract WASM                                 |
| `just deploy`               | Build circuits, build contract, and deploy to the network       |
| `just verify [CONTRACT_ID]` | Verify proof on-chain (reads `.contract_id` if no arg given)    |
| `just e2e`                  | Run the full localnet pipeline in one shot                      |
| `just clean`                | Stop container and remove `.contract_id`                        |

The underlying shell scripts in `scripts/` are still available if you prefer to use them directly.

## Circuits

All Noir circuits live under `/circuits/`. Each circuit keeps its source files and generated artifacts together, with build outputs under `circuits/<name>/target/`.

See [`circuits/README.md`](circuits/README.md) for the circuit layout, rebuild commands, and how to add a new circuit.

## Advanced usage

### Use the JS helper script

Expects a dataset folder with `public_inputs`, `proof` (the VK is already on-chain from deploy):

```bash
cd scripts/invoke_ultrahonk
npm install
npx ts-node invoke_ultrahonk.ts invoke \
  --dataset ../../circuits/simple_circuit/target \
  --contract-id $(cat ../../.contract_id) \
  --network local \
  --source-account alice \
  --send yes
```

## VK policy (important)

This contract does not enforce access control:
- `__constructor` stores the VK once at deploy time (immutable after first set).
- `verify_proof` always uses the stored VK set at deploy.

## Tests

Run all unit and integration tests across the Cargo workspace (including `rs-soroban-ultrahonk` and `tornado_classic`):

```bash
cargo test --workspace --all-features --release
```

## References

- Noir language: https://noir-lang.org/
- Barretenberg (bb): https://github.com/AztecProtocol/aztec-packages
- rs-soroban-ultrahonk: https://github.com/yugocabrio/rs-soroban-ultrahonk
- Soroban documentation: https://developers.stellar.org/docs/build/smart-contracts
- Soroban SDK (Rust): https://github.com/stellar/rs-soroban-sdk

## Audit status

This project has not been audited.

## License

MIT
