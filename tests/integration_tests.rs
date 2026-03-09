use soroban_sdk::{Bytes, Env};

// const CONTRACT_WASM: &[u8] =
//     include_bytes!("../target/wasm32v1-none/release/rs_soroban_ultrahonk.wasm");

mod ultrahonk_contract {
    soroban_sdk::contractimport!(file = "target/wasm32v1-none/release/rs_soroban_ultrahonk.wasm");
}

fn register_client<'a>(env: &'a Env, vk_bytes: &Bytes) -> ultrahonk_contract::Client<'a> {
    let contract_id = env.register(ultrahonk_contract::WASM, (vk_bytes.clone(),));
    ultrahonk_contract::Client::new(env, &contract_id)
}

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let vk_bytes_raw: &[u8] = include_bytes!("simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();


    // Prepare inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}

#[test]
fn verify_fib_chain_proof_succeeds() {
    let vk_bytes_raw: &[u8] = include_bytes!("fib_chain/target/vk");
    let proof_bin: &[u8] = include_bytes!("fib_chain/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("fib_chain/target/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();


    // Prepare inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}

#[test]
fn print_budget_for_deploy_and_verify() {
    let vk_bytes_raw: &[u8] = include_bytes!("simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();

    // Measure deploy budget usage.
    env.cost_estimate().budget().reset_unlimited();
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let client = register_client(&env, &vk_bytes);

    println!("=== Deploy budget usage ===");
    env.cost_estimate().budget().print();

    // Prepare proof inputs

    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    // Measure verify_proof invocation budget usage in isolation.
    env.cost_estimate().budget().reset_unlimited();
    client.verify_proof(&public_inputs, &proof_bytes);
    println!("=== verify_proof budget usage ===");
    env.cost_estimate().budget().print();
}

#[test]
#[should_panic]
fn verify_simple_circuit_with_wrong_proof_fails() {
    let vk_bytes_raw: &[u8] = include_bytes!("simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("fib_chain/target/proof"); // Wrong proof!
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}

#[test]
#[should_panic]
fn verify_with_tampered_public_inputs_fails() {
    let vk_bytes_raw: &[u8] = include_bytes!("simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let mut pub_inputs_vec = include_bytes!("simple_circuit/target/public_inputs").to_vec();
    pub_inputs_vec[0] ^= 0xff; // Tamper with first byte

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, &pub_inputs_vec);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}
