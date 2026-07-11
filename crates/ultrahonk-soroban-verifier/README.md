# UltraHonk Soroban Verifier
Rust verifier library for Noir UltraHonk proofs on BN254, designed for Soroban
contracts and `soroban-sdk`. It verifies both the non-ZK `UltraKeccakFlavor` and
the zero-knowledge `UltraKeccakZKFlavor` produced by Nargo 1.0.0-beta.9 and
Barretenberg v0.87.0.

---

## Features
- Soroban-focused verifier built on `soroban-sdk`  
- Verifies proofs generated from Noir (UltraHonk) using Nargo 1.0.0-beta.9 / barretenberg v0.87.0  
- Supports 456-field non-ZK proofs and 507-field ZK proofs (Libra + hiding polynomial)
- Pure Rust core; `no_std` + `alloc` friendly  
- Expects `bb write_vk`
- Non-ZK fixtures under `circuits/<name>/target`
- ZK fixtures under `circuits/<name>/target/zk`

---

## Quick Start
```bash
just build-circuits
cargo test --workspace --all-features
```

## How It Works
- Typical pipeline: Noir circuit → Nargo execute → `bb prove` → this library verifies `proof`, `public_inputs`, and `vk`.
- Circuit artifacts are generated locally and gitignored. The build script emits:
  - `proof`
  - `public_inputs`
  - `vk`
- `target/` uses `UltraKeccakFlavor`; `target/zk/` uses `bb prove --zk` and `UltraKeccakZKFlavor`.

---

## Crate Usage

Add the dependency from a git path or local path. The crate exposes a small API:

```rust
use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::{ProofFlavor, UltraHonkVerifier};

let env = Env::default();
let vk_bytes = std::fs::read("vk").unwrap();
let vk = Bytes::from_slice(&env, &vk_bytes);
let verifier = UltraHonkVerifier::new(&env, &vk).map_err(|e| format!("vk load failed: {e:?}"))?;
let proof_bytes = std::fs::read("proof").unwrap();
let public_inputs_bytes = std::fs::read("public_inputs").unwrap();
let proof = Bytes::from_slice(&env, &proof_bytes);
let public_inputs = Bytes::from_slice(&env, &public_inputs_bytes);

// The default API safely dispatches by the fixed proof length.
verifier.verify(&env, &proof, &public_inputs).unwrap();

// Or require a ZK proof explicitly.
verifier
    .verify_with_flavor(&env, &proof, &public_inputs, ProofFlavor::UltraKeccakZk)
    .unwrap();
```

Notes:
- Library scope: verification only (not a prover or circuit compiler). Input files must be produced by Noir/Nargo 1.0.0-beta.9 + bb v0.87.0.
- ZK support includes the Libra-masked sumcheck, Gemini hiding polynomial,
  SmallSubgroupIPA consistency check, Shplonk batching, and final KZG pairing.
- The two flavors share a VK but have distinct proof lengths, so a truncated or
  cross-flavor proof cannot be silently reinterpreted.
- Only non-recursive UltraHonk VKs are supported. The v0.87 VK byte format used
  here has no recursion marker, so deployers must enforce that provenance.
- Public inputs must be canonical 32-byte BN254 scalar encodings; modular aliases
  are rejected before verification.
- Proof scalars and commitment limbs must also use canonical encodings, and all
  proof/VK G1 points are checked before MSM or pairing operations.
- The core logic is `no_std` + `alloc` friendly.
- Enable the `trace` feature to print step-by-step internals for cross‑checking with Solidity outputs.

## Cargo Features
- `std`: enables standard-library debug formatting.
- `trace`: prints detailed verifier internals (for debugging); off by default.

## References
- Aztec Packages (barretenberg and tooling): https://github.com/AztecProtocol/aztec-packages
- Noir language: https://noir-lang.org/
- Noir compiler (Nargo): https://github.com/noir-lang/noir#nargo

---

## License
**MIT** – see [`LICENSE`](LICENSE) for details.
