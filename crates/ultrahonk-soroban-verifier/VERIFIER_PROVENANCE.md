# Verifier Provenance

This document records the 1:1 correspondence between the Rust Soroban
`ultrahonk-soroban-verifier` and the Barretenberg (BB) native UltraHonk verifier.
It is intended as a permanent audit trail so that future maintainers can
re-validate the implementation when BB is upgraded or when bugs are suspected.

**Barretenberg source of truth:** `aztec-packages` tag **v0.82.2**  
**Audit date:** 2026-05-28  
**Auditor:** Kimi Code CLI  
**Scope:** Non-ZK, non-recursive, native BN254 UltraHonk path only.

---

## 1. Supported Flavor & Limits

The verifier implements **exactly** the following BB path:

| Feature                                          | Status            |
|--------------------------------------------------|-------------------|
| UltraFlavor (native BN254)                       | ✅ Full support    |
| Keccak-256 transcript                            | ✅ Full support    |
| Non-ZK sumcheck                                  | ✅ Full support    |
| 26 subrelations (8 families)                     | ✅ Full support    |
| Shplemini batch-opening (Gemini + Shplonk + KZG) | ✅ Full support    |
| UltraZKFlavor (hiding polynomial, Libra)         | ❌ Not implemented |
| Recursive / stdlib verifier                      | ❌ Not implemented |
| Mega / Goblin flavors                            | ❌ Not implemented |
| Rollup / IPA (Grumpkin)                          | ❌ Not implemented |
| Poseidon2 transcript                             | ❌ Not implemented |

**Constants aligned with BB v0.82.2:**

| Constant                          | Value | BB Source          |
|-----------------------------------|-------|--------------------|
| `CONST_PROOF_SIZE_LOG_N`          | 28    | `ultra_flavor.hpp` |
| `NUMBER_OF_SUBRELATIONS`          | 26    | `ultra_flavor.hpp` |
| `BATCHED_RELATION_PARTIAL_LENGTH` | 8     | `ultra_flavor.hpp` |
| `NUMBER_OF_ENTITIES`              | 40    | `ultra_flavor.hpp` |
| `NUMBER_UNSHIFTED`                | 35    | `ultra_flavor.hpp` |
| `NUMBER_TO_BE_SHIFTED`            | 5     | `ultra_flavor.hpp` |
| `PAIRING_POINTS_SIZE`             | 16    | `ultra_flavor.hpp` |
| `NUMBER_OF_ALPHAS`                | 25    | `ultra_flavor.hpp` |
| `PROOF_FIELDS`                    | 456   | `proof_length.hpp` |

---

## 2. Architecture Map

```
Rust Module                         BB Component (v0.82.2)
─────────────────────────────────────────────────────────────────────────────
transcript.rs    ─────────────────► transcript/transcript.hpp
                                    oink_verifier.cpp (challenge rounds)
                                    ultra_verifier.cpp (gate challenges)
                                    sumcheck/sumcheck.hpp (sumcheck challenges)
                                    commitment_schemes/shplonk/shplemini.hpp
                                    
verifier.rs      ─────────────────► ultra_verifier.cpp::verify_proof
                                    oink_verifier.cpp::OinkVerifier::verify
                                    decider_verifier.cpp::DeciderVerifier_::verify
                                    
sumcheck.rs      ─────────────────► sumcheck/sumcheck.hpp::SumcheckVerifier::verify
                                    sumcheck/sumcheck_round.hpp
                                    polynomials/barycentric.hpp
                                    polynomials/gate_separator.hpp
                                    
relations.rs     ─────────────────► relations/ultra_arithmetic_relation.hpp
                                    relations/permutation_relation.hpp
                                    relations/logderiv_lookup_relation.hpp
                                    relations/delta_range_constraint_relation.hpp
                                    relations/elliptic_relation.hpp
                                    relations/auxiliary_relation.hpp
                                    relations/poseidon2_external_relation.hpp
                                    relations/poseidon2_internal_relation.hpp
                                    sumcheck_round.hpp::compute_full_relation_purported_value
                                    
shplemini.rs     ─────────────────► commitment_schemes/shplonk/shplemini.hpp
                                    commitment_schemes/kzg/kzg.hpp
                                    
types.rs         ─────────────────► flavor/ultra_flavor.hpp
                                    relations/relation_parameters.hpp
                                    
utils.rs         ─────────────────► honk/proof_system/types/proof.hpp
                                    flavor/ultra_flavor.hpp::Proof
                                    flavor/ultra_flavor.hpp::VerificationKey_
                                    
ec.rs            ─────────────────► Host bn254_g1_msm / pairing_check
                                    (same cryptographic primitives as BB native)
```

---

## 3. Module-to-BB Function Mapping

### 3.1 Transcript (`transcript.rs`)

| Rust Function                                   | BB Equivalent                                                       |
|-------------------------------------------------|---------------------------------------------------------------------|
| `push_coord_halves` / `push_point`              | `transcript.hpp::add_element_frs_to_hash_buffer` (BN254 limb split) |
| `split_challenge` / `split_challenge_from_be32` | `transcript.hpp::NativeTranscriptParams::split_challenge`           |
| `hash_to_fr`                                    | `transcript.hpp::keccak_hash_uint256`                               |
| `generate_eta_challenge`                        | `oink_verifier.cpp::execute_sorted_list_accumulator_round`          |
| `generate_beta_and_gamma_challenges`            | `oink_verifier.cpp::execute_log_derivative_inverse_round`           |
| `generate_alpha_challenges`                     | `oink_verifier.cpp::generate_alphas_round`                          |
| `generate_gate_challenges`                      | `ultra_verifier.cpp::verify_proof`                                  |
| `generate_sumcheck_challenges`                  | `sumcheck.hpp::SumcheckVerifier::verify`                            |
| `generate_rho_challenge`                        | `shplemini.hpp` (`"rho"`)                                           |
| `generate_gemini_r_challenge`                   | `shplemini.hpp` (`"Gemini:r"`)                                      |
| `generate_shplonk_nu_challenge`                 | `shplemini.hpp` (`"Shplonk:nu"`)                                    |
| `generate_shplonk_z_challenge`                  | `shplemini.hpp` (`"Shplonk:z"`)                                     |

### 3.2 Verifier (`verifier.rs`)

| Rust Function                | BB Equivalent                                         |
|------------------------------|-------------------------------------------------------|
| `UltraHonkVerifier::verify`  | `ultra_verifier.cpp::UltraVerifier_::verify_proof`    |
| `compute_public_input_delta` | `grand_product_delta.hpp::compute_public_input_delta` |

### 3.3 Sumcheck (`sumcheck.rs`)

| Rust Function             | BB Equivalent                                                        |
|---------------------------|----------------------------------------------------------------------|
| `check_sum`               | `sumcheck_round.hpp::SumcheckVerifierRound::check_sum`               |
| `compute_next_target_sum` | `sumcheck_round.hpp::SumcheckVerifierRound::compute_next_target_sum` |
| `partially_evaluate_pow`  | `gate_separator.hpp::GateSeparatorPolynomial::partially_evaluate`    |
| `verify_sumcheck`         | `sumcheck.hpp::SumcheckVerifier::verify`                             |

### 3.4 Relations (`relations.rs`)

| Rust Function                               | BB Equivalent                                                                   |
|---------------------------------------------|---------------------------------------------------------------------------------|
| `accumulate_arithmetic_relation`            | `ultra_arithmetic_relation.hpp::UltraArithmeticRelation::accumulate`            |
| `accumulate_permutation_relation`           | `permutation_relation.hpp::UltraPermutationRelation::accumulate`                |
| `accumulate_log_derivative_lookup_relation` | `logderiv_lookup_relation.hpp::LogDerivLookupRelation::accumulate`              |
| `accumulate_delta_range_relation`           | `delta_range_constraint_relation.hpp::DeltaRangeConstraintRelation::accumulate` |
| `accumulate_elliptic_relation`              | `elliptic_relation.hpp::EllipticRelation::accumulate`                           |
| `accumulate_auxillary_relation`             | `auxiliary_relation.hpp::AuxiliaryRelation::accumulate`                         |
| `accumulate_poseidon_external_relation`     | `poseidon2_external_relation.hpp::Poseidon2ExternalRelation::accumulate`        |
| `accumulate_poseidon_internal_relation`     | `poseidon2_internal_relation.hpp::Poseidon2InternalRelation::accumulate`        |
| `scale_and_batch_subrelations`              | `relations/utils.hpp::RelationUtils::scale_and_batch_elements`                  |
| `accumulate_relation_evaluations`           | `sumcheck_round.hpp::compute_full_relation_purported_value`                     |

### 3.5 Shplemini (`shplemini.rs`)

| Rust Function      | BB Equivalent                                                    |
|--------------------|------------------------------------------------------------------|
| `verify_shplemini` | `shplemini.hpp::ShpleminiVerifier_::compute_batch_opening_claim` |

### 3.6 Serialization (`utils.rs`)

| Rust Function                          | BB Equivalent                                      |
|----------------------------------------|----------------------------------------------------|
| `load_proof`                           | `flavor/ultra_flavor.hpp::Proof` layout            |
| `load_vk_from_bytes`                   | `flavor/ultra_flavor.hpp::VerificationKey_` layout |
| `coord_to_halves_be` / `combine_limbs` | `field_conversion::calc_num_bn254_frs`             |

---

## 4. Audit Findings & Resolutions

### 4.1 Fixed Issues

| # | Finding                                                          | Severity | Fix                                                                                                                                                        |
|---|------------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Hardcoded `pub_inputs_offset = 1` instead of reading from VK     | LOW      | Added `pub_inputs_offset: u64` to `VerificationKey`; parsed in `load_vk_from_bytes`; used dynamically in `verifier.rs`                                     |
| 2 | Duplicate shifted commitments in Shplemini MSM (5 extra entries) | NOTE     | Merged shifted scalars into unshifted counterparts (matching BB `remove_repeated_commitments`); reduced MSM from 70 → 65 entries (~2M instruction savings) |

### 4.2 Verified-Aligned Behaviours

The following were verified byte-for-byte or line-by-line against BB v0.82.2:

- **Transcript:** All 13 challenge rounds, Keccak-256 hashing, 128-bit challenge splitting, G1 point serialization (lo136/hi118), uint64 serialization.
- **Public-input delta:** Formula, loop bounds, pairing-point-object inclusion, offset handling.
- **Sumcheck:** Univariate degree (8), barycentric weights (all 8 values verified mod BN254 scalar field), `check_sum`, barycentric evaluation, `pow_β` partial evaluation, padded dummy rounds.
- **Relations:** All 26 subrelations across 8 families match exactly. Key constants verified: `neg_half`, `LIMB_SIZE = 1<<68`, `SUBLIMB_SHIFT = 1<<14`, `B_NEG = 17` (Grumpkin), Poseidon2 internal diagonal values.
- **Shplemini:** Gemini challenge powers, batch inversion layout, Shplonk unshifted/shifted weights, batched evaluation accumulation, commitment order, Gemini fold reconstruction, constant-term accumulator, further folding scalars, dummy commitment padding, generator + quotient placement, KZG pairing check.
- **Deserialization:** Proof byte offsets, VK header fields, G1 limb reconstruction, big-endian field decoding.

---

## 5. Out-of-Scope Items (Intentionally Excluded)

| Feature              | BB Component                      | Reason                                                     |
|----------------------|-----------------------------------|------------------------------------------------------------|
| ZK (UltraZKFlavor)   | `ultra_zk_flavor.hpp`             | Hiding polynomial, Libra sumcheck not implemented          |
| Recursive verifier   | `stdlib/honk_verifier/`           | Circuit-native verification only; no recursive composition |
| Mega / ECC / Goblin  | `mega_flavor.hpp`, `goblin/`      | Different flavor with ECC op wires, databus columns        |
| Rollup / IPA         | `ultra_rollup_flavor.hpp`         | IPA claim handling, Grumpkin MSM                           |
| Poseidon2 transcript | `UltraFlavor` (poseidon2 variant) | Only Keccak-256 path is implemented                        |

---

## 6. Test Fixtures

All verification is validated against BB-generated fixtures in `circuits/`:

| Fixture          | Circuit Size | Description                          |
|------------------|--------------|--------------------------------------|
| `simple_circuit` | 2^3          | Basic arithmetic + permutation       |
| `fib_chain`      | 2^5          | Fibonacci sequence in-circuit        |
| `small_circuit`  | 2^3          | Minimal gate set                     |
| `lookup_heavy`   | 2^5          | Heavy lookup-table usage             |
| `range_heavy`    | 2^5          | Heavy range-check usage              |
| `many_pubs`      | 2^5          | Many public inputs                   |
| `identity`       | —            | Identity circuit (contract e2e)      |
| `tornado`        | —            | Tornado-style circuit (contract e2e) |

Test commands:
```bash
# Full Rust test matrix
cargo test --package ultrahonk_soroban_verifier

# WASM release build (Soroban target)
cargo build --package ultrahonk_soroban_verifier --target wasm32v1-none --release

# E2E scripts
./scripts/run_identity_e2e.sh
./scripts/run_localnet_e2e.sh
```

---

## 7. Re-Auditing Instructions

When Barretenberg is upgraded, follow these steps to validate the Rust verifier:

1. **Update the BB source tree** to the new tag and note the old→new tag in this file.
2. **Check constants** in `types.rs` against `ultra_flavor.hpp`. Any change to `NUM_ALL_ENTITIES`, `NUM_PRECOMPUTED`, `NUM_WITNESS`, `NUM_SHIFTED`, `NUM_SUBRELATIONS`, `BATCHED_RELATION_PARTIAL_LENGTH`, or `CONST_PROOF_SIZE_LOG_N` is **CRITICAL**.
3. **Check proof size** in `lib.rs` (`PROOF_FIELDS`, `PROOF_BYTES`) against `proof_length.hpp`.
4. **Audit transcript** (`transcript.rs`) against `transcript.hpp` and `oink_verifier.cpp`. Challenge labels are **not** hashed in either codebase, but the *order* of absorptions must match exactly.
5. **Audit sumcheck** (`sumcheck.rs`) against `sumcheck.hpp`. Verify barycentric weights if `BATCHED_RELATION_PARTIAL_LENGTH` changes.
6. **Audit relations** (`relations.rs`) against the 8 relation headers. Even a single coefficient change breaks verification.
7. **Audit Shplemini** (`shplemini.rs`) against `shplemini.hpp`. The MSM layout is especially fragile.
8. **Run the full test matrix** (`cargo test --workspace`) and all e2e scripts.
9. **Update this file** with the new BB tag, any changed constants, and the new audit date.

---

## 8. Glossary

| Term               | Meaning                                                                                                                                      |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| **Oink**           | The first phase of UltraHonk verification: transcript preamble, wire commitments, lookup commitments, and challenge generation (η, β, γ, α). |
| **Sumcheck**       | Multivariate polynomial identity protocol. The verifier checks round univariates and derives round challenges.                               |
| **Shplemini**      | Batch-opening protocol combining Gemini (folding), Shplonk (batching), and KZG (pairing).                                                    |
| **PPO**            | Pairing Point Object — 16 Fr values appended to public inputs in the permutation argument.                                                   |
| **Gate separator** | Polynomial `pow_β = ∏((1−Xᵢ) + Xᵢ·βᵢ)` used to combine multiple relations into one sumcheck claim.                                           |
| **Domain sep**     | The partial evaluation of `pow_β` at the sumcheck challenges, scaling each relation contribution.                                            |

---

*Last updated: 2026-05-28*  
*Barretenberg tag: v0.82.2*
8