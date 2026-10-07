# Publishing the UltraHonk verifier

This guide publishes only **`ultrahonk_soroban_verifier`**, initially version
**`0.1.0`**, to crates.io. The three contract packages and `ultrahonk-test-utils`
are private workspace packages (`publish = false`). They do not need to be
published first. The verifier's only runtime dependency is `soroban-sdk` from
crates.io.

Run these commands from the repository root. The preparation and CI checks below
do not upload a crate. Only the command in **Publish** uploads it.

## 1. Check the release identity and publishing access

- Confirm the `name` and `version` in
  `crates/ultrahonk-soroban-verifier/Cargo.toml` are the intended release.
- Obtain coworkers' approval to publish under `ultrahonk_soroban_verifier`.
  Registry availability alone does not establish that approval.
- Obtain OpenZeppelin's original audit report, verify its source and audited
  revision, commit it, and link it from the crate README's audit section.
- Check [the crate page](https://crates.io/crates/ultrahonk_soroban_verifier).
  For a first release the name must be available; for a later release your
  account must be an owner and the version must not already exist. Hyphens and
  underscores are treated as equivalent for name uniqueness.
- Confirm your existing crates.io account has a verified email address and a
  token that permits publishing this crate (including creation for the first
  release). Configure it interactively if Cargo is not already authenticated:

  ```bash
  cargo login --registry crates-io
  ```

  Keep the token out of the repository and command history. The preparation
  commands do not require you to share it.
- Review the MIT license and retained copyright notices, README, repository URL,
  feature descriptions, and explicit non-ZK proof-flavor limitations.

## 2. Run release checks

The crate's declared minimum supported Rust version is **1.92.0**. CI builds
the extracted package with default and all features and its Soroban contract
integration on that version, using the committed dependency lockfile. Confirm
the MSRV job passes for the release commit, including after dependency updates.
Use Rust 1.92.0 or newer, Stellar CLI 28.0.0, Nargo 1.0.0-beta.9, and Barretenberg
0.87.0 for the checks below.
The Noir tools are required for repository tests, not for package consumers.
The regular CI job builds the fixtures and Wasm; the package CI job checks both
feature configurations and documentation without publishing.

```bash
rustup target add wasm32v1-none
cargo fmt --all -- --check
./circuits/scripts/build_all.sh
./circuits/scripts/check_artifact_hashes.sh
cargo test -p ultrahonk_soroban_verifier --locked
cargo test -p ultrahonk_soroban_verifier --locked --all-features
stellar contract build --package rs-soroban-ultrahonk
RUSTDOCFLAGS="-D warnings" cargo doc \
  -p ultrahonk_soroban_verifier --locked --all-features --no-deps
```

Inspect the documentation and usage example. The repository test suite uses
`ultrahonk-test-utils` and generated circuit files outside the library directory.
Those are intentionally not registry dependencies or distributed fixtures;
run the full tests from the checkout. Cargo drops the versionless path-only
development dependency when it normalizes the package manifest.

Review and commit the release changes through the normal project workflow.
The final release checks should run on the exact commit being released, with
`git status --short` showing no changes. Generated, ignored build files are fine.
Do not bypass failures with `--no-verify`.

## 3. Inspect and dry-run the package

```bash
cargo package -p ultrahonk_soroban_verifier --locked --list
cargo publish -p ultrahonk_soroban_verifier \
  --registry crates-io --locked --dry-run
cargo publish -p ultrahonk_soroban_verifier \
  --registry crates-io --locked --dry-run --all-features
```

During review of uncommitted changes, `--allow-dirty` can be added to the dry-run
commands only. Omit it for the final release.

Cargo writes `target/package/ultrahonk_soroban_verifier-0.1.0.crate` and verifies
that its extracted source builds. Inspect its contents:

```bash
tar -tzf target/package/ultrahonk_soroban_verifier-0.1.0.crate
tar -xOf target/package/ultrahonk_soroban_verifier-0.1.0.crate \
  ultrahonk_soroban_verifier-0.1.0/Cargo.toml
```

Confirm the archive includes the source, README, MIT license, and verifier
provenance file, and contains no generated proofs, credentials, build output,
or unrelated contracts. Check that the normalized manifest has a crates.io
version for `soroban-sdk` and no dependency on the private test helper. Its
compressed size must fit crates.io's default 10 MiB limit.

Both dry runs must succeed. They validate local packaging and compilation;
the registry still checks account permissions and release availability at
upload time. Recheck the name/version immediately before publishing.

## 4. Publish — run manually when ready

This is the actual upload command. It is deliberately absent from CI:

```bash
cargo publish -p ultrahonk_soroban_verifier --registry crates-io --locked
```

Never remove `--dry-run` from an automated preparation command to test it. A
published version cannot be overwritten; corrections require a new version.

## 5. Confirm the release and ownership

1. Confirm `0.1.0` appears on the crate page and that
   [docs.rs](https://docs.rs/ultrahonk_soroban_verifier/0.1.0) builds successfully.
2. In a fresh consumer project, add
   `ultrahonk_soroban_verifier = "0.1.0"` and compatible `soroban-sdk = "28.0.0"`
   dependencies, then run `cargo check`. For a Soroban contract, build it with
   Stellar CLI 28.0.0 and the `wasm32v1-none` target.
3. Inspect the owners:

   ```bash
   cargo owner --list ultrahonk_soroban_verifier --registry crates-io
   ```

   If the project should be owned by a GitHub team, a current individual owner
   who belongs to that team can add it. Replace `TEAM_SLUG` with the actual
   authorized team; repository ownership does not automatically grant registry
   ownership:

   ```bash
   cargo owner --add github:NethermindEth:TEAM_SLUG \
     ultrahonk_soroban_verifier --registry crates-io
   ```

4. Tag the exact published commit and push the tag after publication succeeds:

   ```bash
   git tag -a ultrahonk_soroban_verifier-v0.1.0 -m "Release ultrahonk_soroban_verifier 0.1.0"
   git push origin ultrahonk_soroban_verifier-v0.1.0
   ```

For subsequent releases, update the package version and version-specific usage
instructions, repeat these checks, and use a new tag. If a released version is
broken, publish a fixed version and consider yanking the broken version; a yank
prevents new resolutions from selecting it but does not remove existing copies.

## Official references

- [Publishing on crates.io](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Cargo package](https://doc.rust-lang.org/cargo/commands/cargo-package.html)
- [Cargo publish and dry-run options](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)
- [Dependency rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
- [docs.rs build configuration](https://docs.rs/about/metadata)
