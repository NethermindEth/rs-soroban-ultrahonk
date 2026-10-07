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
> at parse time (see [verifier provenance](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/VERIFIER_PROVENANCE.md) §4.3), but an active prover can still
> vary the fixed-slot padding, so distinct byte strings can verify for one statement.
> Do not key deduplication, replay protection or nullifiers on raw proof bytes.

Rust verifier library for Noir/UltraHonk proofs on BN254, built for Soroban
contracts using `soroban-sdk` 28.x. Compatible proof tooling is **Nargo
1.0.0-beta.9 + Barretenberg 0.87.0**, using the Keccak oracle. Contracts built
with this SDK require Stellar protocol **28 or newer**.

## Installation

For applications consuming the published 0.1.0 release:

```toml
[dependencies]
ultrahonk_soroban_verifier = "0.1.0"
soroban-sdk = { version = "28.0.0", default-features = false }
```

The verifier is a library, not a prover or circuit compiler. Nargo and
Barretenberg are needed to generate proofs; they are not needed to compile a
Rust application that depends on this crate.

## Usage in a Soroban contract

Pass the contract's `Env` and binary inputs to the verifier. This helper maps
errors to strings for illustration; a contract should map them to its own
`#[contracterror]` enum.

```rust
use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

fn verify(
    env: &Env,
    vk: &Bytes,
    proof: &Bytes,
    public_inputs: &Bytes,
) -> Result<(), &'static str> {
    let verifier = UltraHonkVerifier::new(env, vk)
        .map_err(|_| "invalid verification key")?;
    verifier.verify(proof, public_inputs)
        .map_err(|_| "invalid proof")
}
```

All `Bytes` arguments must belong to the same `Env`:

- `vk`: the 1,760-byte binary verification key produced by `bb write_vk`.
- `proof`: the 14,592-byte proof (`PROOF_BYTES`).
- `public_inputs`: canonical, big-endian 32-byte field elements concatenated in
  circuit order. The verifier checks their count against the key.

The verifier re-derives the Fiat–Shamir transcript, checks sumcheck, then checks
Shplemini batch openings with BN254 host operations. The application must select
a trusted verification key and enforce its own authorization and replay policy.

See the [contract wrapper](https://github.com/NethermindEth/rs-soroban-ultrahonk/tree/main/contracts/rs-soroban-ultrahonk)
for a complete integration and the
[verifier provenance](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/VERIFIER_PROVENANCE.md)
for the supported proof format.

## Cargo features

| Feature | Effect |
| --- | --- |
| Default (empty) | `no_std` core with `alloc`; use this for Soroban Wasm. |
| `std` | Standard-library debug formatting helpers. It does not add file-loading APIs. |
| `trace` | Diagnostic output when combined with `std`; use `--features std,trace` on the host. |

There is no `alloc` Cargo feature. The core links `alloc` internally.

## Building and testing from the repository

The minimum supported Rust version (MSRV) is **1.92.0**, declared as
`rust-version = "1.92"` in the manifest. CI checks the extracted crate with
default and all features on Rust 1.92.0 and builds the Soroban contract that
embeds it for `wasm32v1-none`. These checks use the committed dependency lockfile;
dependency updates must continue to pass them. The other CI jobs use stable Rust.

Install the `wasm32v1-none` target and Stellar CLI 28.0.0, then build the example
contract that embeds the verifier. From the repository root:

```bash
rustup target add wasm32v1-none
stellar contract build --package rs-soroban-ultrahonk
```

Tests need the private workspace helper crate and circuit fixtures. Run them
from a repository checkout, not from the downloaded crates.io archive:

```bash
# Requires Nargo 1.0.0-beta.9 and Barretenberg 0.87.0.
./circuits/scripts/build_all.sh simple_circuit fib_chain small_circuit lookup_heavy range_heavy many_pubs
cargo test -p ultrahonk_soroban_verifier --locked
cargo test -p ultrahonk_soroban_verifier --locked --all-features
```

Fixtures are generated under `circuits/<name>/target/` and are not distributed
in the crate. Cargo removes the path-only `ultrahonk-test-utils` development
dependency when packaging; it is not a dependency of applications using this
library.

## Audit status

The [repository's audit status](https://github.com/NethermindEth/rs-soroban-ultrahonk#audit-status)
records an OpenZeppelin audit dated **31 August 2026**, covering commit
[`661db07200f890b1bd9a7349ed787c70a706dd12`](https://github.com/NethermindEth/rs-soroban-ultrahonk/tree/661db07200f890b1bd9a7349ed787c70a706dd12),
with five Low severity findings and six notes, and no Critical, High, or Medium
findings. Later commits contain remediation and SDK upgrades; the audited
revision is not the current release revision. The original auditor report still
needs to be obtained and added to the repository before the first publication.

## Publishing

Maintainers should follow the repository's
[publishing guide](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/PUBLISHING.md).

## References

- [Barretenberg](https://github.com/AztecProtocol/aztec-packages)
- [Noir](https://noir-lang.org/)
- [Nargo](https://github.com/noir-lang/noir#nargo)

## License

MIT — see [LICENSE](https://github.com/NethermindEth/rs-soroban-ultrahonk/blob/main/crates/ultrahonk-soroban-verifier/LICENSE).
