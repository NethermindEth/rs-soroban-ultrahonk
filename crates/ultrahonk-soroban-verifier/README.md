# UltraHonk Soroban Verifier

> **Supported flavor: `UltraKeccakFlavor` — non-ZK, non-recursive.**
> This verifier implements Barretenberg's *non-zero-knowledge* Keccak-transcript
> flavor. It provides **no witness-hiding guarantee**: a proof carries
> witness-dependent protocol messages, and on-chain wrappers accept the full
> proof as public transaction input. Do not use it for privacy-sensitive
> circuits, and do not treat a private circuit input as secret merely because it
> is not a public input. `UltraZKFlavor` is not implemented.
>
> A successful verification also does **not** bind the proof to the transaction
> submitter and provides no replay protection; see the contract READMEs.
>
> **Proof bytes are not a unique identifier.** Canonical encodings are now enforced
> at parse time (see `VERIFIER_PROVENANCE.md` §4.3), but an active prover can still
> vary the fixed-slot padding, so distinct byte strings can verify for one statement.
> Do not key deduplication, replay protection or nullifiers on raw proof bytes.

Rust verifier library for proofs generated from Noir (UltraHonk) on BN254, designed to integrate with Soroban contracts and `soroban-sdk`. Its purpose is to verify Noir/UltraHonk proofs produced by Nargo 1.0.0-beta.9 + barretenberg (bb v0.87.0). A small Noir asset is included only for testing the verifier.

---

## Features
- Soroban-focused verifier built on `soroban-sdk`  
- Verifies proofs generated from Noir (UltraHonk) using Nargo 1.0.0-beta.9 / barretenberg v0.87.0  
- Pure Rust core; `no_std` + `alloc` friendly  
- Expects `bb write_vk`
- Example verification artifacts under `circuits/simple_circuit/target` (for tests).
  Note these are **not** tracked in git (`target` is gitignored); they are produced
  by `just build-circuits` and must be regenerated after a clean checkout.

---

## Quick Start
```bash
cargo test --features "std"

cargo test
```

## How It Works
- Typical pipeline: Noir circuit → Nargo prove → bb emits `proof`, `public_inputs`, and `vk` → this library verifies the proof.
- Test data lives at `circuits/simple_circuit/target` and includes the following.
  It is **not** tracked in git and must be regenerated with `just build-circuits`:
  - `proof`
  - `public_inputs`
  - `vk`

---

## Crate Usage

Add the dependency from a git path or local path. The crate exposes a small API:

```rust
use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

let env = Env::default();
let vk_bytes = std::fs::read("vk").unwrap();
let vk = Bytes::from_slice(&env, &vk_bytes);
let verifier = UltraHonkVerifier::new(&env, &vk).map_err(|e| format!("vk load failed: {e:?}"))?;
let proof_bytes = std::fs::read("proof").unwrap();
let public_inputs_bytes = std::fs::read("public_inputs").unwrap();
let proof = Bytes::from_slice(&env, &proof_bytes);
let public_inputs = Bytes::from_slice(&env, &public_inputs_bytes);

verifier.verify(&proof, &public_inputs).unwrap();
```

Notes:
- Library scope: verification only (not a prover or circuit compiler). Input files must be produced by Noir/Nargo 1.0.0-beta.9 + bb v0.87.0.
- The verifier internally re-derives the Fiat–Shamir transcript and checks both Sum‑check and Shplonk batch openings over BN254.
- `std` feature enables file I/O helpers; the core logic is `no_std` + `alloc` friendly.
- Enable the `trace` feature to print step-by-step internals for cross‑checking with Solidity outputs.

## Cargo Features
- `std`: enables std I/O helpers for convenient loading.
- `trace`: prints detailed verifier internals (for debugging); off by default.
- `alloc` (default): required for `no_std` collections.

## References
- Aztec Packages (barretenberg and tooling): https://github.com/AztecProtocol/aztec-packages
- Noir language: https://noir-lang.org/
- Noir compiler (Nargo): https://github.com/noir-lang/noir#nargo

---

## License
**MIT** – see [`LICENSE`](LICENSE) for details.
