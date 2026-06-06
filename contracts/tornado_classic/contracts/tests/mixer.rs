#![allow(dead_code)]

use soroban_env_host::DiagnosticLevel;
use soroban_poseidon::{poseidon2_hash, Field};
use soroban_sdk::{
    crypto::BnScalar, testutils::Address as TestAddress, Address, Bytes, BytesN, Env,
    Vec as SorobanVec, U256,
};

use std::sync::{Mutex, OnceLock};

#[cfg(feature = "wasm-cost")]
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(feature = "wasm-cost")]
use soroban_sdk::{IntoVal, InvokeError, Symbol, Val};

use rs_soroban_ultrahonk::UltraHonkVerifierContract;
use tornado_classic_contracts::mixer::{MixerContract, MixerError};

#[cfg(feature = "testutils")]
use ultrahonk_soroban_verifier::PROOF_BYTES;

const TREE_DEPTH_TEST: u32 = 20;

fn verify_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn vk_bytes(env: &Env) -> Bytes {
    Bytes::from_slice(
        env,
        include_bytes!("../../../../circuits/tornado/target/vk"),
    )
}

fn be32_from_u64(x: u64) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[24..32].copy_from_slice(&x.to_be_bytes());
    a
}

fn hash2(env: &Env, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a_bytes = Bytes::from_array(env, a);
    let b_bytes = Bytes::from_array(env, b);
    let modulus = <BnScalar as Field>::modulus(env);
    let mut inputs = SorobanVec::new(env);
    inputs.push_back(U256::from_be_bytes(env, &a_bytes).rem_euclid(&modulus));
    inputs.push_back(U256::from_be_bytes(env, &b_bytes).rem_euclid(&modulus));
    let out = poseidon2_hash::<4, BnScalar>(env, &inputs);
    let out_bytes = out.to_be_bytes();
    let mut out_arr = [0u8; 32];
    out_bytes.copy_into_slice(&mut out_arr);
    out_arr
}

fn zero_at(env: &Env, level: u32) -> [u8; 32] {
    let mut z = [0u8; 32];
    for _ in 0..level {
        let zz = z;
        z = hash2(env, &zz, &zz);
    }
    z
}

fn frontier_root_from_leaves(env: &Env, leaves: &[[u8; 32]], depth: u32) -> [u8; 32] {
    let mut frontier: Vec<Option<[u8; 32]>> = vec![None; depth as usize];
    let mut root = zero_at(env, depth);
    for (i, leaf) in leaves.iter().enumerate() {
        let idx = i as u32;
        let mut cur = *leaf;
        let mut level = 0u32;
        while level < depth {
            let bit = (idx >> level) & 1;
            if bit == 0 {
                frontier[level as usize] = Some(cur);
                let z = zero_at(env, level);
                cur = hash2(env, &cur, &z);
            } else {
                let left = frontier[level as usize]
                    .as_ref()
                    .copied()
                    .unwrap_or_else(|| zero_at(env, level));
                cur = hash2(env, &left, &cur);
            }
            level += 1;
        }
        root = cur;
    }
    root
}

fn register_verifier(env: &Env, vk_bytes: &Bytes) -> Address {
    env.register(UltraHonkVerifierContract, (vk_bytes.clone(),))
}
fn register_mixer(env: &Env, verifier: Address) -> Address {
    env.register(MixerContract, (verifier,))
}

#[cfg(feature = "wasm-cost")]
fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../../..")
        .canonicalize()
        .expect("workspace root must exist")
}

#[cfg(feature = "wasm-cost")]
fn wasm_release_path(file_name: &str) -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        workspace_root()
            .join("target/wasm32v1-none/release")
            .join(file_name),
        manifest_dir
            .join("../../target/wasm32v1-none/release")
            .join(file_name),
        manifest_dir
            .join("target/wasm32v1-none/release")
            .join(file_name),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(feature = "wasm-cost")]
fn ensure_release_wasm(file_name: &str, package: &str, extra_args: &[&str]) -> Vec<u8> {
    // Always rebuild here: the same output path is used for different feature sets,
    // and the wasm-cost test needs the test-only exports enabled.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root());
    cmd.args([
        "build",
        "--release",
        "--target",
        "wasm32v1-none",
        "-p",
        package,
    ]);
    cmd.args(extra_args);
    let status = cmd
        .status()
        .expect("failed to spawn cargo; ensure cargo is installed and on PATH");
    assert!(
        status.success(),
        "failed to build release wasm for package `{package}`"
    );

    if let Some(path) = wasm_release_path(file_name) {
        return fs::read(&path).expect("reading built wasm artifact should succeed");
    }

    panic!(
        "release wasm artifact `{file_name}` not found after build; expected under `target/wasm32v1-none/release/`"
    );
}

#[cfg(feature = "wasm-cost")]
fn register_wasm_verifier(env: &Env, vk_bytes: &Bytes) -> Address {
    let wasm = ensure_release_wasm("rs_soroban_ultrahonk.wasm", "rs-soroban-ultrahonk", &[]);
    env.register(wasm.as_slice(), (vk_bytes.clone(),))
}

#[cfg(feature = "wasm-cost")]
fn register_wasm_mixer(env: &Env, verifier: Address) -> Address {
    let wasm = ensure_release_wasm(
        "tornado_classic_contracts.wasm",
        "tornado_classic_contracts",
        &["--features", "wasm-cost"],
    );
    env.register(wasm.as_slice(), (verifier,))
}

#[cfg(feature = "wasm-cost")]
fn wasm_call_ok<T>(env: &Env, id: &Address, fn_name: &str, args: SorobanVec<Val>) -> T
where
    T: soroban_sdk::TryFromVal<Env, Val>,
{
    env.try_invoke_contract::<T, InvokeError>(id, &Symbol::new(env, fn_name), args)
        .expect("host contract invocation should succeed")
        .expect("contract call should succeed")
}

/// Deposits a sequence of leaves and checks the contract frontier updates match a reference implementation.
#[test]
#[cfg(feature = "testutils")]
fn merkle_frontier_updates_root_matches_reference() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);
    let verifier_id = <Address as TestAddress>::generate(&env);
    let mixer_id: Address = register_mixer(&env, verifier_id);

    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for i in 0u64..8 {
        let a = be32_from_u64(i);
        let b = be32_from_u64(i + 100);
        leaves.push(hash2(&env, &a, &b));
    }

    for (n, leaf) in leaves.iter().enumerate() {
        env.as_contract(&mixer_id, || {
            MixerContract::deposit(env.clone(), BytesN::from_array(&env, leaf))
        })
        .unwrap();
        let onchain_root = env
            .as_contract(&mixer_id, || MixerContract::get_root(env.clone()))
            .unwrap();
        let expected_root = frontier_root_from_leaves(&env, &leaves[0..=n], TREE_DEPTH_TEST);
        assert_eq!(onchain_root, BytesN::from_array(&env, &expected_root));
    }
}

/// Happy-path withdraw followed by a double-spend attempt confirms the nullifier is enforced.
#[test]
#[cfg(feature = "testutils")]
fn mixer_withdraw_and_double_spend_rejected() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    // Artifacts
    let vk_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/public_inputs");

    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    // Register contracts
    let verifier_id: Address = register_verifier(&env, &vk_bytes);
    let mixer_id: Address = register_mixer(&env, verifier_id.clone());

    // Deposit a commitment so root is non-zero
    let commitment = BytesN::from_array(&env, &[0x11; 32]);
    env.as_contract(&mixer_id, || {
        MixerContract::deposit(env.clone(), commitment)
    })
    .unwrap();

    // Set on-chain root to circuit public root
    assert!(pub_inputs_bin.len() >= 64);
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&pub_inputs_bin[..32]);
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &root_arr))
    })
    .expect("set_root ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    env.as_contract(&mixer_id, || {
        MixerContract::withdraw(env.clone(), public_inputs.clone(), proof_bytes.clone())
    })
    .expect("withdraw ok");

    // Double-spend attempt with same nullifier must fail
    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::withdraw(env.clone(), public_inputs.clone(), proof_bytes.clone())
        })
        .expect_err("expected error");
    assert_eq!(err as u32, MixerError::NullifierUsed as u32);
}

/// Confirms the test-only root override updates the stored root.
#[test]
#[cfg(feature = "testutils")]
fn set_root_overrides_root() {
    let env = Env::default();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);
    let verifier_id = <Address as TestAddress>::generate(&env);
    let mixer_id: Address = register_mixer(&env, verifier_id);

    let root = BytesN::from_array(&env, &[0xAB; 32]);
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), root.clone())
    })
    .expect("set_root ok");
    let stored = env.as_contract(&mixer_id, || MixerContract::get_root(env.clone()));
    assert_eq!(stored, Some(root));
}

/// Verifies that tampering with public inputs causes the withdraw to fail and leaves the nullifier unused.
#[test]
#[cfg(feature = "testutils")]
fn withdraw_rejects_invalid_public_inputs() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/public_inputs");

    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    let verifier_id: Address = register_verifier(&env, &vk_bytes);
    let mixer_id: Address = register_mixer(&env, verifier_id.clone());

    let commitment = BytesN::from_array(&env, &[0x22; 32]);
    env.as_contract(&mixer_id, || {
        MixerContract::deposit(env.clone(), commitment)
    })
    .unwrap();

    assert!(pub_inputs_bin.len() >= 64);
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&pub_inputs_bin[..32]);
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &root_arr))
    })
    .expect("set_root ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let mut corrupted_inputs = pub_inputs_bin.to_vec();
    corrupted_inputs[63] ^= 0x01;
    let public_inputs: Bytes = Bytes::from_slice(&env, &corrupted_inputs);
    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::withdraw(env.clone(), public_inputs.clone(), proof_bytes.clone())
        })
        .expect_err("expected verification failure");
    assert_eq!(err as u32, MixerError::VerificationFailed as u32);

    let mut nf_arr = [0u8; 32];
    nf_arr.copy_from_slice(&pub_inputs_bin[32..64]);
    let nf_from_proof = BytesN::from_array(&env, &nf_arr);
    let used = env.as_contract(&mixer_id, || {
        MixerContract::is_nullifier_used(env.clone(), nf_from_proof.clone())
    });
    assert!(!used, "nullifier should remain unused after invalid inputs");
}

/// Verifies that public inputs shorter than 64 bytes are rejected with InvalidPublicInputs.
#[test]
#[cfg(feature = "testutils")]
fn withdraw_rejects_short_public_inputs() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/proof");

    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    let verifier_id: Address = register_verifier(&env, &vk_bytes);
    let mixer_id: Address = register_mixer(&env, verifier_id.clone());

    let commitment = BytesN::from_array(&env, &[0x22; 32]);
    env.as_contract(&mixer_id, || {
        MixerContract::deposit(env.clone(), commitment)
    })
    .unwrap();

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let short_inputs = Bytes::from_slice(&env, &[0u8; 63]);

    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::withdraw(env.clone(), short_inputs.clone(), proof_bytes.clone())
        })
        .expect_err("expected InvalidPublicInputs");
    assert_eq!(err as u32, MixerError::InvalidPublicInputs as u32);
}

/// Verifies that public inputs longer than 64 bytes are rejected with InvalidPublicInputs.
#[test]
#[cfg(feature = "testutils")]
fn withdraw_rejects_long_public_inputs() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/proof");

    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    let verifier_id: Address = register_verifier(&env, &vk_bytes);
    let mixer_id: Address = register_mixer(&env, verifier_id.clone());

    let commitment = BytesN::from_array(&env, &[0x22; 32]);
    env.as_contract(&mixer_id, || {
        MixerContract::deposit(env.clone(), commitment)
    })
    .unwrap();

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let long_inputs = Bytes::from_slice(&env, &[0u8; 65]);

    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::withdraw(env.clone(), long_inputs.clone(), proof_bytes.clone())
        })
        .expect_err("expected InvalidPublicInputs");
    assert_eq!(err as u32, MixerError::InvalidPublicInputs as u32);
}

/// Confirms withdraw fails if the proof root differs from the stored root and does not consume the nullifier.
#[test]
#[cfg(feature = "testutils")]
fn withdraw_rejects_root_mismatch() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let proof_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/public_inputs");

    let vk_bytes: Bytes = vk_bytes(&env);
    let verifier_id: Address = register_verifier(&env, &vk_bytes);
    let mixer_id: Address = register_mixer(&env, verifier_id.clone());

    // Deposit one leaf to seed tree
    let commitment = BytesN::from_array(&env, &[0x33; 32]);
    env.as_contract(&mixer_id, || {
        MixerContract::deposit(env.clone(), commitment)
    })
    .unwrap();

    // Set an incorrect root (all zero)
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &[0u8; 32]))
    })
    .expect("set_root ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::withdraw(env.clone(), public_inputs.clone(), proof_bytes.clone())
        })
        .expect_err("expected root mismatch");
    assert_eq!(err as u32, MixerError::RootMismatch as u32);

    let mut nf_arr = [0u8; 32];
    nf_arr.copy_from_slice(&pub_inputs_bin[32..64]);
    let nf = BytesN::from_array(&env, &nf_arr);
    let spent = env.as_contract(&mixer_id, || {
        MixerContract::is_nullifier_used(env.clone(), nf.clone())
    });
    assert!(!spent, "nullifier should remain unused after root mismatch");
}

/// Measure deposit/withdraw budget using release WASM contracts.
#[cfg(feature = "wasm-cost")]
#[cfg_attr(debug_assertions, ignore = "budget test is release-only")]
#[allow(clippy::assertions_on_constants)]
#[test]
fn print_wasm_budget_for_deposit_and_withdraw() {
    assert!(
        !cfg!(debug_assertions),
        "run wasm-cost budget tests with `--release --features wasm-cost`"
    );
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_bytes: Bytes = vk_bytes(&env);
    let proof_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/public_inputs");

    let verifier_id: Address = register_wasm_verifier(&env, &vk_bytes);
    let mixer_id: Address = register_wasm_mixer(&env, verifier_id.clone());

    env.cost_estimate().budget().reset_unlimited();
    let commitment = BytesN::from_array(&env, &[0x55; 32]);
    let mut deposit_args: SorobanVec<Val> = SorobanVec::new(&env);
    deposit_args.push_back(commitment.into_val(&env));
    let _: u32 = wasm_call_ok(&env, &mixer_id, "deposit", deposit_args);
    println!("=== wasm deposit budget usage ===");
    env.cost_estimate().budget().print();

    assert!(pub_inputs_bin.len() >= 64);
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&pub_inputs_bin[..32]);
    let mut set_root_args: SorobanVec<Val> = SorobanVec::new(&env);
    set_root_args.push_back(BytesN::from_array(&env, &root_arr).into_val(&env));
    let _: () = wasm_call_ok(&env, &mixer_id, "set_root", set_root_args);

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    env.cost_estimate().budget().reset_unlimited();
    let mut withdraw_args: SorobanVec<Val> = SorobanVec::new(&env);
    withdraw_args.push_back(public_inputs.into_val(&env));
    withdraw_args.push_back(proof_bytes.into_val(&env));
    let _: () = wasm_call_ok(&env, &mixer_id, "withdraw", withdraw_args);
    println!("=== wasm withdraw budget usage ===");
    env.cost_estimate().budget().print();
}

#[test]
fn deposit_rejects_duplicate_commitment() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);
    let verifier_id = <Address as TestAddress>::generate(&env);
    let mixer_id: Address = register_mixer(&env, verifier_id);

    let cm = BytesN::from_array(&env, &[0x55; 32]);
    env.as_contract(&mixer_id, || {
        MixerContract::deposit(env.clone(), cm.clone())
    })
    .expect("first deposit ok");

    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::deposit(env.clone(), cm.clone())
        })
        .expect_err("expected duplicate commitment error");
    assert_eq!(err as u32, MixerError::CommitmentExists as u32);
}

#[test]
#[cfg(feature = "testutils")]
fn deposit_then_withdraw_against_real_root_succeeds() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../../../circuits/tornado/target/e2e/proof");
    let pub_inputs_bin: &[u8] =
        include_bytes!("../../../../circuits/tornado/target/e2e/public_inputs");
    let commitment_bin: &[u8] =
        include_bytes!("../../../../circuits/tornado/target/e2e/commitment");

    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    let verifier_id: Address = register_verifier(&env, &vk_bytes);
    let mixer_id: Address = register_mixer(&env, verifier_id.clone());

    let mut commitment_arr = [0u8; 32];
    commitment_arr.copy_from_slice(commitment_bin);
    let commitment = BytesN::from_array(&env, &commitment_arr);

    // Deposit the known commitment. It will be inserted at leaf index 0,
    // and since the tree is empty, the resulting root will match the one
    // generated by the e2e step in build_all.sh.
    env.as_contract(&mixer_id, || {
        MixerContract::deposit(env.clone(), commitment)
    })
    .expect("deposit ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    // Withdraw without set_root! The root computed during deposit is used.
    env.as_contract(&mixer_id, || {
        MixerContract::withdraw(env.clone(), public_inputs.clone(), proof_bytes.clone())
    })
    .expect("withdraw ok");

    // Double check that the nullifier is marked as used
    let mut nf_arr = [0u8; 32];
    nf_arr.copy_from_slice(&pub_inputs_bin[32..64]);
    let nf = BytesN::from_array(&env, &nf_arr);
    let spent = env.as_contract(&mixer_id, || {
        MixerContract::is_nullifier_used(env.clone(), nf)
    });
    assert!(spent, "nullifier should be marked as used");
}
