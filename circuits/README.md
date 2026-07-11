# Circuits

This directory is the canonical home for Noir circuits used by the verifier, example contracts, and integration tests.

## Layout

```text
circuits/
  simple_circuit/  Nargo.toml, Prover.toml, src/main.nr, target/
  fib_chain/       Nargo.toml, Prover.toml, src/main.nr, target/
  tornado/         Nargo.toml, Prover.toml, src/main.nr, target/
  scripts/         build_all.sh
```

Each circuit directory must contain a `Nargo.toml`. The build scripts discover
those directories automatically and skip anything without a Noir manifest.

## Rebuild Artifacts

Build every circuit, one circuit, or a selected list:

```bash
./circuits/scripts/build_all.sh
./circuits/scripts/build_all.sh simple_circuit
./circuits/scripts/build_all.sh simple_circuit fib_chain
```

The scripts use Noir `1.0.0-beta.9` and Barretenberg `0.87.0`, installing them
when missing from `PATH`.

## Target Files

After a successful build, `circuits/<name>/target/` contains:

- `<project>.json` and `<project>.gz` from `nargo compile` / `nargo execute`
- `proof` and `proof_fields.json`
- `vk` and `vk_fields.json`
- `public_inputs` and `public_inputs_fields.json`

Those top-level artifacts are the 456-field non-ZK UltraKeccak flavor. A
second self-contained set is written under `target/zk/` using `bb prove --zk`:

- `proof` — 507-field UltraKeccakZK proof
- `vk` — the same flavor-independent verification key
- `public_inputs`
- matching `*_fields.json` files

Set `GENERATE_ZK=0` to skip companion ZK generation. Existing `target/zk`
artifacts are not refreshed in that mode; do not use them as outputs of the
current build.

## Add A Circuit

1. Create `circuits/<name>/src/main.nr`.
2. Add `circuits/<name>/Nargo.toml`.
3. Add or generate `circuits/<name>/Prover.toml`.
4. Run `./circuits/scripts/build_all.sh <name>`.
5. Point privacy-preserving examples at `circuits/<name>/target/zk/`.

For `tornado`, the build script regenerates `Prover.toml` through `contracts/tornado_classic/contracts/examples/populate_publics.rs` by default.
Set `GENERATE_PROVER=0` to keep existing prover inputs.
