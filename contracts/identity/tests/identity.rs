use identity::{IdentityContract, IdentityContractClient};
use soroban_sdk::{testutils::Ledger, Env};
use ultrahonk_test_utils::Fixture;

fn test_env() -> Env {
    let env = Env::default();
    env.ledger().set_protocol_version(25);
    env
}

#[test]
fn identity_proof_verifies() {
    let env = test_env();
    let f = Fixture::load("identity");
    let (proof, vk, pi) = f.into_bytes(&env);

    let contract_id = env.register(IdentityContract, (vk.clone(),));
    let client = IdentityContractClient::new(&env, &contract_id);

    client.prove_identity(&pi, &proof);
}
