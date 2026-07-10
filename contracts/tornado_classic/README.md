Tornado Classic–style Mixer (Soroban + Noir)

Scope
- Deposit stores commitments and rolls an on-chain Poseidon2 Merkle tree (depth 20).
- Withdraw verifies a Noir UltraHonk proof against the stored root and enforces single-use nullifiers.
- Educational sample: no token flow; proof/key artifacts are generated locally.

Layout
- `circuits/tornado/`: Noir project and generated non-ZK (`target/`) and ZK (`target/zk/`) artifacts.
- `contracts/`: Rust tests wiring `UltraHonkVerifierContract` and `MixerContract` in a simulated Soroban environment.

Requirements
- Noir `nargo` 1.0.0-beta.9
- Barretenberg CLI `bb` 0.87.0 with `--oracle_hash keccak`
- Rust stable toolchain (`cargo`)
- Optional Stellar CLI (`stellar-cli`) + Docker if you want to deploy the verifier contract locally

Generate ZK Artifacts
```bash
just build-circuits tornado
# produces circuits/tornado/target/zk/{vk,proof,public_inputs,...}
```

Run Contract Tests (includes real proof verification)
```bash
cargo test --manifest-path contracts/tornado_classic/contracts/Cargo.toml --features testutils -- --nocapture
```

Run the production-shaped release-Wasm ZK budget test with:

```bash
cargo test -p tornado_classic_contracts --release --features wasm-cost \
  print_wasm_budget_for_deposit_and_withdraw -- --nocapture
```

With the protocol-26 SDK cost model, the final ZK withdrawal path measured
about 135.1M CPU instructions and 7.17MB memory. Network limits are mutable;
query the target network before deployment with `stellar network settings`.

Key checks:
- `deposit` appends to the frontier and updates the on-chain root.
- `withdraw` takes separate `public_inputs` (two 32-byte values ordered `[root, nullifier_hash]`) and requires a 507-field UltraKeccakZK proof; the verifier address is fixed at deploy-time.
- Invalid proofs or double spends fail; root overrides are only exposed in test builds.

Quick Usage Notes
- Deploy `MixerContract` with the verifier contract address in the constructor.
- Normal deposits keep the root up to date automatically.
- Ensure the public inputs match the Poseidon2 tree built off committed leaves.
- This repo is instructional. Production deployments still require token custody design and careful security review.
