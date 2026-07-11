# Verifier Provenance

This document records the protocol variants implemented by
`ultrahonk-soroban-verifier` and the Barretenberg sources against which they
must be checked.

- **Barretenberg source:** `aztec-packages` tag `v0.87.0`
- **Commit:** `9081b0ed38c43c120afb7c80f8f6cd418ca5ad70`
- **Last updated:** 2026-07-10
- **Scope:** BN254, Keccak transcript, non-recursive UltraHonk

## Supported flavors

| Flavor | Proof words | Support |
|---|---:|---|
| `UltraKeccakFlavor` | 456 | Full |
| `UltraKeccakZKFlavor` | 507 | Full |
| Recursive UltraHonk | — | Not supported |
| Poseidon2 transcript | — | Not supported |
| Mega/Goblin/Rollup/IPA | — | Not supported |

Both flavors use the same 1,760-byte verification-key encoding: four `u64`
header fields followed by 27 BN254 G1 commitments. The proof length selects the
flavor automatically; callers can also require an explicit `ProofFlavor`.

## Common protocol

The two flavors share:

- 16 proof-contained pairing-point-object field elements;
- eight Ultra witness/lookup/permutation commitments;
- 26 Ultra relations and 25 batching alphas;
- 40 multilinear entity evaluations (35 unshifted, five shifted);
- Gemini multilinear reduction, Shplonk batching, and BN254 KZG pairing;
- Keccak Fiat-Shamir challenges split into 128-bit field challenges.

Public inputs must use their unique big-endian BN254 scalar encoding. Values
greater than or equal to the scalar modulus are rejected before transcript or
proof checks so byte-oriented application logic (such as nullifier tracking)
cannot observe aliases of the same circuit field element.

Proof scalars are likewise required to be canonical. Proof commitments require
zero padding in the `(lo136, hi118)` limb encoding, canonical base-field
coordinates, and on-curve G1 points; VK commitments receive the same coordinate
and curve checks. Malformed encodings return verifier/VK errors instead of
reaching an MSM or pairing host trap.

Common Rust modules map to Barretenberg as follows:

| Rust | Barretenberg v0.87 |
|---|---|
| `relations.rs` | `relations/*_relation.hpp` |
| `verifier.rs` | `ultra_honk/ultra_verifier.cpp`, `decider_verifier.cpp` |
| `ec.rs` | KZG final pairing / Soroban BN254 host functions |
| `types.rs`, `utils.rs` | `ultra_flavor.hpp`, `honk_contract.hpp` |

## Non-ZK UltraKeccak

| Rust | Barretenberg v0.87 |
|---|---|
| `transcript.rs` | `honk_contract.hpp::TranscriptLib` |
| `sumcheck.rs` | non-ZK `SumcheckVerifier` / 8-value univariates |
| `shplemini.rs` | non-ZK `ShpleminiVerifier_` |

The fixed proof layout is `PROOF_FIELDS = 456` (`PROOF_BYTES = 14,592`).

## ZK UltraKeccak

The ZK implementation follows `UltraKeccakZKFlavor` and the generated
`honk_zk_contract.hpp` verifier.

| Rust | Barretenberg v0.87 |
|---|---|
| `zk_types.rs`, `zk_utils.rs` | `ultra_zk_flavor.hpp::Transcript_`, ZK proof loader |
| `zk_transcript.rs` | `honk_zk_contract.hpp::ZKTranscriptLib` |
| `zk_sumcheck.rs` | ZK `SumcheckVerifier`, row-disabling polynomial |
| `zk_shplemini.rs` | ZK `ShpleminiVerifier_`, `SmallSubgroupIPAVerifier` |

The fixed proof layout is `ZK_PROOF_FIELDS = 507`
(`ZK_PROOF_BYTES = 16,224`). Relative to the non-ZK proof it adds:

- a commitment to concatenated Libra masking univariates and their claimed sum;
- 9-value rather than 8-value sumcheck univariates;
- the Libra evaluation used in the masked sumcheck identity;
- grand-sum and quotient commitments for the SmallSubgroupIPA;
- a Gemini hiding-polynomial commitment and evaluation;
- four Libra opening evaluations.

The verifier checks the order-256 Libra subgroup identity, batches the hiding
polynomial at `rho^0`, starts ordinary entity claims at `rho^1`, and batches the
four Libra openings at fixed powers `nu^58` through `nu^61` before the final KZG
pairing.

## Intentional exclusions

Recursive proofs are not supported. The 16 pairing-point-object limbs are
included in the transcript and permutation public-input delta, but nested
pairing accumulators are not reconstructed or aggregated. Only VKs for
non-recursive circuits may be used.

The implementation is version-specific. Proofs or VKs from another
Barretenberg version must not be assumed compatible even when their lengths
match.

## Fixture generation and tests

`circuits/scripts/build_all.sh` generates both variants for every circuit:

- `circuits/<name>/target/{proof,vk,public_inputs}` — non-ZK;
- `circuits/<name>/target/zk/{proof,vk,public_inputs}` — ZK.

Set `GENERATE_ZK=0` only when the companion ZK fixtures are not needed.

Required validation when upgrading Barretenberg:

1. Regenerate both proof variants with the pinned `nargo` and `bb` versions.
2. Verify both variants with native `bb` and the Rust verifier.
3. Recheck proof layouts and every transcript absorption boundary.
4. Recheck 8- and 9-point barycentric constants.
5. Recheck the row-disabling factor, Libra subgroup constants and consistency identity.
6. Recheck fixed Shplonk powers for the four Libra claims.
7. Run `cargo test --workspace --all-features` and the Soroban Wasm build.
