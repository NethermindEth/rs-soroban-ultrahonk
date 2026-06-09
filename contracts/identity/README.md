# Identity Contract

A minimal Soroban smart contract that verifies on-chain identity proofs using the UltraHonk verifier.

## What it proves

The accompanying Noir circuit (`circuits/identity/`) proves knowledge of a **Poseidon2 hash preimage**:

```noir
fn main(preimage: Field, hash: pub Field) {
    let computed_hash = Poseidon2::hash([preimage], 1);
    assert(computed_hash == hash);
}
```

- **Private input**: `preimage` — the secret value (e.g., a password, seed, or identity secret)
- **Public input**: `hash` — the Poseidon2 hash of the preimage, stored on-chain

## Contract API

### Constructor

```rust
fn __constructor(env: Env, vk_bytes: Bytes)
```

Stores the UltraHonk verification key in contract instance storage. This VK is tied to the specific Noir circuit and must be generated with the same `bb` version used to produce proofs.

### Methods

```rust
fn prove_identity(env: Env, public_inputs: Bytes, proof_bytes: Bytes) -> Result<(), Error>
```

Verifies a proof that the caller knows the preimage for the given public hash.

**Errors:**
- `VkNotSet` — contract was not initialized with a VK
- `VkInvalidLength` — VK byte slice does not match the expected exact length
- `VkInvalidParameters` — VK header contains out-of-range structural parameters
- `ProofParseError` — proof length does not match `PROOF_BYTES` (14,592)
- `VerificationFailed` — proof is invalid for the given public inputs

## Trust Model

- **Deployer responsibility:** The deployer must supply the correct VK at construction time. The VK is immutable after deployment — there is no admin key or governance mechanism to change it.
- **One-time initialization:** The VK is set exactly once in the constructor and cannot be changed.
- **No post-deploy rotation:** If the circuit changes, the contract must be redeployed with a new VK.
- **User verification:** Callers should verify the stored VK (via `vk_bytes()`) matches the expected circuit before trusting proofs.

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   Prover (off-  │     │   Identity Contract   │     │  Verifier Crate │
│   chain)        │     │   (Soroban guest)     │     │  (embedded)     │
│                 │     │                      │     │                 │
│  nargo execute  │────▶│  prove_identity()    │────▶│  UltraHonk      │
│  bb prove       │     │  - loads VK          │     │  Verifier       │
│                 │     │  - deserializes      │     │                 │
│                 │     │    proof + inputs    │     │  - host BN254    │
│                 │     │  - delegates to      │     │    primitives    │
│                 │     │    verifier          │     │                 │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
```

The contract itself is ~24KB WASM. Verification costs ~81M CPU instructions on Soroban Protocol 26.

## End-to-End Flow

### 1. Build the circuit

```bash
just build-circuits identity
```

This generates in `circuits/identity/target/`:
- `proof` — the UltraHonk proof (14,592 bytes)
- `vk` — the verification key
- `public_inputs` — the public hash (32 bytes)

### 2. Build & deploy the contract

```bash
# Localnet
just start          # start local stellar node
just fund           # fund alice account
./scripts/run_identity_e2e.sh

# Testnet
./scripts/run_identity_e2e.sh testnet
```

The script deploys the contract with the VK as a constructor argument.

### 3. Verify on-chain

The `run_identity_e2e.sh` script automatically calls `prove_identity` after deployment. To invoke manually:

```bash
cd scripts/invoke_identity
npm install
npx ts-node invoke_identity.ts prove \
  --contract-id <CONTRACT_ID> \
  --dataset ../../circuits/identity/target \
  --network local \
  --source-account alice \
  --send yes
```

## Testing

Run the unit test (in-memory Soroban environment, no network needed):

```bash
cargo test -p identity
```

The test loads circuit artifacts from `circuits/identity/target/` using `ultrahonk-test-utils::Fixture`.

## Customizing the circuit

Edit `circuits/identity/src/main.nr` and `circuits/identity/Prover.toml`:

```toml
preimage = "12345"
hash = "0x..."
```

Then rebuild and redeploy. The VK changes whenever the circuit changes, so the contract must be re-deployed (or a multi-VK pattern implemented).
