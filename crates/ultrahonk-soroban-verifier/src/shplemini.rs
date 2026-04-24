//! Shplemini batch-opening verifier for BN254

use crate::ec::{g1_msm, pairing_check};
use crate::env::Bn254FrGenerator;
use crate::field::batch_inverse;
use crate::trace;
use crate::types::{
    G1Point, Proof, Transcript, VerificationKey, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ENTITIES,
    NUMBER_TO_BE_SHIFTED, NUMBER_UNSHIFTED,
};
use core::array::repeat;
use core::ops::Neg;
use soroban_sdk::Env;

/// Shplemini verification
pub fn verify_shplemini(
    env: &Env,
    proof: &Proof,
    vk: &VerificationKey,
    tp: &Transcript,
) -> Result<(), &'static str> {
    // 1) r^{2^i}
    let log_n = vk.log_circuit_size as usize;
    let mut r_pows = env.zero_array::<CONST_PROOF_SIZE_LOG_N>();
    r_pows[0] = tp.gemini_r.clone();
    for i in 1..log_n {
        r_pows[i] = &r_pows[i - 1] * &r_pows[i - 1];
    }

    // We need the following inversions:
    //   - (z - r^0), (z + r^0)          for shplonk weights (pos0, neg0)
    //   - gemini_r                       for shifted weight
    //   - (r^j*(1-u_j) + u_j)           for j in 1..=log_n  (fold round denoms)
    //   - (z - r^j), (z + r^j)          for j in 1..log_n   (further folding)
    //
    // Total: 2 + 1 + log_n + 2*(log_n - 1) = 3*log_n + 1 values.

    // Collect all values to invert into a flat array.
    // Layout:
    //   [0]           = z - r^0
    //   [1]           = z + r^0
    //   [2]           = gemini_r
    //   [3 .. 3+log_n)  = fold round denominators (j = log_n down to 1)
    //   [3+log_n .. 3+log_n + 2*(log_n-1))  = pairs (z - r^j, z + r^j) for j=1..log_n
    // Max batch size: 3*CONST_PROOF_SIZE_LOG_N + 1 (upper bound when log_n == CONST_PROOF_SIZE_LOG_N)
    const MAX_BATCH: usize = 3 * CONST_PROOF_SIZE_LOG_N + 1;
    let batch_size = 3 + log_n + 2 * (log_n - 1);
    let mut to_invert = env.zero_array::<MAX_BATCH>();
    let mut inverted = env.zero_array::<MAX_BATCH>();

    to_invert[0] = &tp.shplonk_z - &r_pows[0];
    to_invert[1] = &tp.shplonk_z + &r_pows[0];
    to_invert[2] = tp.gemini_r.clone();

    // fold round denominators: r^j * (1 - u_j) + u_j, for j = log_n down to 1
    for j in (1..=log_n).rev() {
        let u = &tp.sumcheck_u_challenges[j - 1];
        to_invert[3 + (log_n - j)] = &r_pows[j - 1] * &(env.one() - u) + u;
    }

    // further folding denominators: (z - r^j) and (z + r^j) for j = 1..log_n
    let further_base = 3 + log_n;
    for j in 1..log_n {
        to_invert[further_base + 2 * (j - 1)] = &tp.shplonk_z - &r_pows[j];
        to_invert[further_base + 2 * (j - 1) + 1] = &tp.shplonk_z + &r_pows[j];
    }

    batch_inverse(&to_invert[..batch_size], &mut inverted[..batch_size]).map_err(|_| {
        "shplemini: batch inversion failed (zero denominator in shplonk/gemini/fold)"
    })?;

    // Unpack results
    let pos0 = inverted[0].clone();
    let neg0 = inverted[1].clone();
    let gemini_r_inv = inverted[2].clone();

    // 2) allocate arrays
    // Match Solidity sizing: NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2
    // Layout:
    //   [0]                 = shplonk_Q
    //   [1..=40]            = VK + proof entities (NUMBER_OF_ENTITIES)
    //   [41..=67]           = gemini_fold_comms (CONST_PROOF_SIZE_LOG_N - 1 = 27)
    //   [68]                = generator (1,2) with const_acc scalar
    //   [69]                = kzg_quotient with scalar z
    const TOTAL: usize = 1 + NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 1;
    trace!("total = {}", TOTAL);
    let mut scalars = env.zero_array::<TOTAL>();
    let mut coms = repeat::<G1Point, TOTAL>(G1Point::infinity(env));

    // 3) compute shplonk weights
    let unshifted = &tp.shplonk_nu * &neg0 + &pos0;
    let shifted = gemini_r_inv * (&pos0 - &(&tp.shplonk_nu * &neg0));
    let neg_unshifted = -&unshifted;
    let neg_shifted = -&shifted;
    // 4) shplonk_Q
    scalars[0] = env.one();
    coms[0] = proof.shplonk_q.clone();

    // 5) weight sumcheck evals
    let mut rho_pow = env.one();
    let mut eval_acc = env.zero();
    let shifted_end = NUMBER_UNSHIFTED + NUMBER_TO_BE_SHIFTED;
    debug_assert_eq!(NUMBER_OF_ENTITIES, shifted_end);
    for (idx, eval) in proof
        .sumcheck_evaluations
        .iter()
        .take(NUMBER_OF_ENTITIES)
        .enumerate()
    {
        let scalar = if idx < NUMBER_UNSHIFTED {
            neg_unshifted.clone()
        } else {
            neg_shifted.clone()
        } * &rho_pow;
        scalars[1 + idx] = scalar;
        eval_acc = eval_acc + &(eval * &rho_pow);
        rho_pow = rho_pow * &tp.rho;
    }
    // 6) load VK & proof (MSM layout must match Solidity: VK order, then proof wires unshifted + shifted)
    {
        let mut j = 1;
        macro_rules! push_vk {
            ($($field:ident),+ $(,)?) => {
                $(
                    coms[j] = vk.$field.clone();
                    j += 1;
                )+
            };
        }
        push_vk![
            qm,
            qc,
            ql,
            qr,
            qo,
            q4,
            q_lookup,
            q_arith,
            q_delta_range,
            q_elliptic,
            q_aux,
            q_poseidon2_external,
            q_poseidon2_internal,
            s1,
            s2,
            s3,
            s4,
            id1,
            id2,
            id3,
            id4,
            t1,
            t2,
            t3,
            t4,
            lagrange_first,
            lagrange_last
        ];

        for p in [
            &proof.w1,
            &proof.w2,
            &proof.w3,
            &proof.w4,
            &proof.z_perm,
            &proof.lookup_inverses,
            &proof.lookup_read_counts,
            &proof.lookup_read_tags,
        ] {
            coms[j] = p.clone();
            j += 1;
        }
        for p in [&proof.w1, &proof.w2, &proof.w3, &proof.w4, &proof.z_perm] {
            coms[j] = p.clone();
            j += 1;
        }
        let _ = j;
    }

    // 7) folding rounds — use batch-inverted denominators
    let mut fold_pos = env.zero_array::<CONST_PROOF_SIZE_LOG_N>();
    let mut cur = eval_acc;
    for j in (1..=log_n).rev() {
        let r2 = &r_pows[j - 1];
        let u = &tp.sumcheck_u_challenges[j - 1];
        let fold_lin = r2 * &(env.one() - u) - u;
        let num =
            r2 * &cur * env.fr_from_u64(2) - &(&proof.gemini_a_evaluations[j - 1] * &fold_lin);
        let den_inv = inverted[3 + (log_n - j)].clone();
        cur = num * &den_inv;
        fold_pos[j - 1] = cur.clone();
    }
    // 8) accumulate constant term
    let nu_sq = &tp.shplonk_nu * &tp.shplonk_nu;
    let mut const_acc =
        &fold_pos[0] * &pos0 + &(&proof.gemini_a_evaluations[0] * &tp.shplonk_nu * &neg0);
    let mut v_pow = nu_sq.clone();
    // 9) further folding + commit — use batch-inverted denominators
    // Base index where fold commitments start
    let base = 1 + NUMBER_OF_ENTITIES;
    for j in 1..log_n {
        let pos_inv = inverted[further_base + 2 * (j - 1)].clone();
        let neg_inv = inverted[further_base + 2 * (j - 1) + 1].clone();
        let sp = &v_pow * &pos_inv;
        let sn = &v_pow * &tp.shplonk_nu * &neg_inv;

        scalars[base + j - 1] = -(&sp + &sn);
        const_acc = const_acc + &(&proof.gemini_a_evaluations[j] * &sn) + &(&fold_pos[j] * &sp);

        v_pow = v_pow * &nu_sq;

        coms[base + j - 1] = proof.gemini_fold_comms[j - 1].clone();
    }

    // Fill remaining (dummy) fold commitments so MSM layout matches Solidity (total 27 entries)
    coms[((log_n - 1) + base)..((CONST_PROOF_SIZE_LOG_N - 1) + base)]
        .clone_from_slice(&proof.gemini_fold_comms[(log_n - 1)..(CONST_PROOF_SIZE_LOG_N - 1)]);

    // 10) add generator
    // Generator goes right after all fold commitments (27 entries)
    let one_idx = base + (CONST_PROOF_SIZE_LOG_N - 1);
    trace!("one_idx = {}", one_idx);
    coms[one_idx] = G1Point::generator(env);
    scalars[one_idx] = const_acc;

    // 11) add quotient
    let q_idx = one_idx + 1;
    trace!("q_idx = {}", q_idx);
    coms[q_idx] = proof.kzg_quotient.clone();
    scalars[q_idx] = tp.shplonk_z.clone();

    // 12) MSM + pairing
    let p0 = g1_msm(env, &coms, &scalars)?;
    let p1 = proof.kzg_quotient.0.clone().neg();
    if pairing_check(env, &p0, &p1) {
        Ok(())
    } else {
        Err("Shplonk pairing check failed")
    }
}
