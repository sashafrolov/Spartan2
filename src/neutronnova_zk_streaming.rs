// Adapted code from Microsoft's Spartan2 repository.
// SPDX-License-Identifier: MIT
// This file is part of the Spartan2 project.
// See the LICENSE file in the project root for full license information.
// Source repository: https://github.com/Microsoft/Spartan2

//! This implements a "Read/Write Streaming" version of the proof system in neutronnova_zk_streaming.rs.
//! For ease of implementation (and because there were some bugs in the implementation at time of writing),
//! this doesn't implement the "small value sumcheck" optimizations. 
use scribe_streams::{
  iterator::{BatchedIterator, from_iter},
  serialize::{DeserializeRaw, SerializeRaw},
};
use crate::start_span;
use crate::{
  Commitment, CommitmentKey, VerifierKey,
  bellpepper::{
    r1cs::{
      MultiRoundSpartanShape, MultiRoundSpartanWitness, SpartanShape,
      SpartanWitness,
    },
    shape_cs::ShapeCS,
    solver::SatisfyingAssignment,
  },
  big_num::{
    DelayedReduction,
  },
  digest::DigestComputer,
  errors::SpartanError,
  math::Math,
  nifs::NovaNIFS,
  polys::{
    eq::EqPolynomial,
    multilinear::{MultilinearPolynomial, SparsePolynomial},
    power::PowPolynomial,
    univariate::UniPoly,
  },
  r1cs::{
    R1CSInstance, R1CSShape, R1CSWitness, RelaxedR1CSInstance, SplitMultiRoundR1CSInstance,
    SplitMultiRoundR1CSShape, SplitR1CSInstance, SplitR1CSShape, weights_from_r,
  },
  sumcheck::SumcheckProof,
  traits::{
    Engine,
    circuit::SpartanCircuit,
    pcs::{FoldingEngineTrait, PCSEngineTrait},
    snark::{DigestHelperTrait, SpartanDigest},
    transcript::TranscriptEngineTrait,
  },
  zk::NeutronNovaVerifierCircuit,
};
use ff::Field;
use once_cell::sync::OnceCell;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

fn compute_tensor_decomp(n: usize) -> (usize, usize, usize) {
  let ell = n.next_power_of_two().log_2();
  // we split ell into ell1 and ell2 such that ell1 + ell2 = ell and ell1 >= ell2
  let ell1 = ell.div_ceil(2); // This ensures ell1 >= ell2
  let ell2 = ell / 2;
  let left = 1 << ell1;
  let right = 1 << ell2;

  (ell, left, right)
}

/// A type that holds the NeutronNova NIFS (Non-Interactive Folding Scheme)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NeutronNovaNIFS<E: Engine> {
  polys: Vec<UniPoly<E::Scalar>>,
}

#[inline(always)]
#[allow(clippy::needless_range_loop)]
fn suffix_weight_full<F: Field>(t: usize, ell_b: usize, pair_idx: usize, rhos: &[F]) -> F {
  let mut w = F::ONE;
  let mut k = pair_idx;
  for s in (t + 1)..ell_b {
    let bit = (k & 1) as u8; // LSB-first
    w *= if bit == 0 { F::ONE - rhos[s] } else { rhos[s] };
    k >>= 1;
  }
  w
}

impl<E: Engine> NeutronNovaNIFS<E>
where
  E::PCS: FoldingEngineTrait<E>,
{
  /// Computes the evaluations of the sum-check polynomial at 0, 2, and 3
  /// Uses two-level delayed modular reduction (inner + middle levels).
  /// Note: Outer level (over pairs) uses regular field arithmetic since there are few pairs.
  #[inline(always)]
  #[allow(clippy::needless_range_loop)]
  fn prove_helper(
    round: usize,
    (left, right): (usize, usize),
    e: &[E::Scalar],
    Az1: &scribe_streams::file_vec::FileVec<E::Scalar>,
    Bz1: &scribe_streams::file_vec::FileVec<E::Scalar>,
    Cz1: &scribe_streams::file_vec::FileVec<E::Scalar>,
    Az2: &scribe_streams::file_vec::FileVec<E::Scalar>,
    Bz2: &scribe_streams::file_vec::FileVec<E::Scalar>,
  ) -> (E::Scalar, E::Scalar)
  where
    E::Scalar: SerializeRaw + DeserializeRaw,
  {
    type Acc<S> = <S as DelayedReduction<S>>::Accumulator;

    // sanity check sizes
    assert_eq!(e.len(), left + right);
    assert_eq!(Az1.len(), left * right);

    let f = &e[left..];
    let e_left = &e[..left];
    let compute_e0 = round != 0;

    let mut acc_e0 = Acc::<E::Scalar>::default();
    let mut acc_quad = Acc::<E::Scalar>::default();

    if compute_e0 {
      let mut iter = Az1.iter()
        .zip(Bz1.iter())
        .zip(Cz1.iter())
        .zip(Az2.iter())
        .zip(Bz2.iter());
      let mut idx = 0usize;
      let mut inner_e0 = Acc::<E::Scalar>::default();
      let mut inner_quad = Acc::<E::Scalar>::default();
      while let Some(batch) = iter.next_batch() {
        for ((((az1, bz1), cz1), az2), bz2) in batch.collect::<Vec<_>>() {
          let j = idx % left;
          let i = idx / left;
          let inner_val = az1 * bz1 - cz1;
          <E::Scalar as DelayedReduction<E::Scalar>>::unreduced_multiply_accumulate(
            &mut inner_e0, &e_left[j], &inner_val,
          );
          let quad_val = (az2 - az1) * (bz2 - bz1);
          <E::Scalar as DelayedReduction<E::Scalar>>::unreduced_multiply_accumulate(
            &mut inner_quad, &e_left[j], &quad_val,
          );
          if j == left - 1 {
            let inner_e0_red = <E::Scalar as DelayedReduction<E::Scalar>>::reduce(&inner_e0);
            let inner_quad_red = <E::Scalar as DelayedReduction<E::Scalar>>::reduce(&inner_quad);
            inner_e0 = Acc::<E::Scalar>::default();
            inner_quad = Acc::<E::Scalar>::default();
            <E::Scalar as DelayedReduction<E::Scalar>>::unreduced_multiply_accumulate(
              &mut acc_e0, &f[i], &inner_e0_red,
            );
            <E::Scalar as DelayedReduction<E::Scalar>>::unreduced_multiply_accumulate(
              &mut acc_quad, &f[i], &inner_quad_red,
            );
          }
          idx += 1;
        }
      }
    } else {
      let mut iter = Az1.iter()
        .zip(Bz1.iter())
        .zip(Az2.iter())
        .zip(Bz2.iter());
      let mut idx = 0usize;
      let mut inner_quad = Acc::<E::Scalar>::default();
      while let Some(batch) = iter.next_batch() {
        for (((az1, bz1), az2), bz2) in batch.collect::<Vec<_>>() {
          let j = idx % left;
          let i = idx / left;
          let quad_val = (az2 - az1) * (bz2 - bz1);
          <E::Scalar as DelayedReduction<E::Scalar>>::unreduced_multiply_accumulate(
            &mut inner_quad, &e_left[j], &quad_val,
          );
          if j == left - 1 {
            let inner_quad_red = <E::Scalar as DelayedReduction<E::Scalar>>::reduce(&inner_quad);
            inner_quad = Acc::<E::Scalar>::default();
            <E::Scalar as DelayedReduction<E::Scalar>>::unreduced_multiply_accumulate(
              &mut acc_quad, &f[i], &inner_quad_red,
            );
          }
          idx += 1;
        }
      }
    }

    (
      <E::Scalar as DelayedReduction<E::Scalar>>::reduce(&acc_e0),
      <E::Scalar as DelayedReduction<E::Scalar>>::reduce(&acc_quad),
    )
  }

  /// Compact folded results from positions [4j, 4j+2]
  /// down to [2j, 2j+1] for A, B, and C layers.
  fn compact_folded_layers_abc(
    a: &mut [scribe_streams::file_vec::FileVec<E::Scalar>],
    b: &mut [scribe_streams::file_vec::FileVec<E::Scalar>],
    c: &mut [scribe_streams::file_vec::FileVec<E::Scalar>],
    prove_pairs: usize,
  )
  where
    E::Scalar: SerializeRaw + DeserializeRaw,
  {
    for j in 0..prove_pairs {
      a.swap(2 * j, 4 * j);
      a.swap(2 * j + 1, 4 * j + 2);
      b.swap(2 * j, 4 * j);
      b.swap(2 * j + 1, 4 * j + 2);
      c.swap(2 * j, 4 * j);
      c.swap(2 * j + 1, 4 * j + 2);
    }
  }

  /// ZK version of NeutronNova NIFS prove. This function performs the NIFS folding
  /// rounds while interacting with the multi-round verifier circuit/state to derive
  /// per-round challenges via Fiat-Shamir, and populates the verifier circuit's
  /// NIFS-related public values. It returns:
  /// - the constructed NIFS (list of cubic univariate polynomials),
  /// - the split equality polynomial evaluations E (length left+right),
  /// - the final A/B/C layers after folding (as multilinear tables),
  /// - the final outer claim T_out for the step branch, and
  /// - the sequence of challenges r_b used to fold instances/witnesses.
  pub fn prove(
    S: &SplitR1CSShape<E>,
    _ck: &CommitmentKey<E>,
    Us: Vec<R1CSInstance<E>>,
    mut Ws_is_small: Vec<bool>,
    mut Ws_r_W: Vec<<E::PCS as PCSEngineTrait<E>>::Blind>,
    mut Ws_W: Vec<scribe_streams::file_vec::FileVec<E::Scalar>>,
    mut A_layers: Vec<scribe_streams::file_vec::FileVec<E::Scalar>>,
    mut B_layers: Vec<scribe_streams::file_vec::FileVec<E::Scalar>>,
    mut C_layers: Vec<scribe_streams::file_vec::FileVec<E::Scalar>>,
    vc: &mut NeutronNovaVerifierCircuit<E>,
    vc_state: &mut <SatisfyingAssignment<E> as MultiRoundSpartanWitness<E>>::MultiRoundState, // wrapper circuit, fine
    vc_shape: &SplitMultiRoundR1CSShape<E>, // wrapper circuit, fine
    vc_ck: &CommitmentKey<E>, // wrapper circuit related, fine
    transcript: &mut E::TE, // just a hash
  ) -> Result<
    (
      Vec<E::Scalar>,  // E_eq (split evals, length left+right)
      Vec<E::Scalar>,  // Az layer 0
      Vec<E::Scalar>,  // Bz layer 0
      Vec<E::Scalar>,  // Cz layer 0
      R1CSWitness<E>,  // final folded witness
      R1CSInstance<E>, // final folded instance
    ),
    SpartanError,
  >
  where
    E::Scalar: SerializeRaw + DeserializeRaw,
  {
    // Determine padding and NIFS rounds
    let n = Us.len();
    let n_padded = Us.len().next_power_of_two();
    let ell_b = n_padded.log_2();

    info!(
      "NeutronNova NIFS prove for {} instances and padded to {} instances",
      Us.len(),
      n_padded
    );

    let mut Us = Us;
    if Us.len() < n_padded {
      Us.extend(vec![Us[0].clone(); n_padded - n]);
      Ws_is_small.extend(vec![Ws_is_small[0]; n_padded - n]);
      Ws_r_W.extend(vec![Ws_r_W[0].clone(); n_padded - n]);
      for _ in n..n_padded {
        Ws_W.push(scribe_streams::file_vec::FileVec::clone(&Ws_W[0]));
      }
    }
    let (_absorb_span, absorb_t) = start_span!("transcript_operations");
    for U in Us.iter() {
      transcript.absorb(b"U", U);
    }
    let T = E::Scalar::ZERO;
    transcript.absorb(b"T", &T);

    // Squeeze tau and rhos fresh inside this function (like ZK sum-check APIs)
    let (ell_cons, left, right) = compute_tensor_decomp(S.num_cons);
    let tau = transcript.squeeze(b"tau")?;

    let E_eq = PowPolynomial::split_evals(tau, ell_cons, left, right);

    let mut rhos = Vec::with_capacity(ell_b);
    for _ in 0..ell_b {
      rhos.push(transcript.squeeze(b"rho")?);
    }
    info!(elapsed_ms = %absorb_t.elapsed().as_millis(), "transcript_operations");

    // Execute NIFS rounds, generating cubic polynomials and driving r_b via multi-round state

    let mut polys: Vec<UniPoly<E::Scalar>> = Vec::with_capacity(ell_b);
    let mut r_bs: Vec<E::Scalar> = Vec::with_capacity(ell_b);
    let mut T_cur = E::Scalar::ZERO; // the current target value, starts at 0
    let mut acc_eq = E::Scalar::ONE;
    let mut m = n_padded;

    // Helper closure: build polynomial, process round, extract r_b
    // (factored out since it's identical for standalone and merged rounds)
    macro_rules! finish_round {
      ($t:expr, $e0:expr, $quad_coeff:expr) => {{
        let rho_t = rhos[$t];
        let one_minus_rho = E::Scalar::ONE - rho_t;
        let two_rho_minus_one = rho_t - one_minus_rho;
        let c = $e0 * acc_eq;
        let a = $quad_coeff * acc_eq;
        let rho_t_inv: Option<E::Scalar> = rho_t.invert().into();
        let a_b_c = (T_cur - c * one_minus_rho) * rho_t_inv.ok_or(SpartanError::DivisionByZero)?;
        let b = a_b_c - a - c;
        let new_a = a * two_rho_minus_one;
        let new_b = b * two_rho_minus_one + a * one_minus_rho;
        let new_c = c * two_rho_minus_one + b * one_minus_rho;
        let new_d = c * one_minus_rho;

        let poly_t = UniPoly {
          coeffs: vec![new_d, new_c, new_b, new_a],
        };
        polys.push(poly_t.clone());

        let c = &poly_t.coeffs;
        vc.nifs_polys[$t] = [c[0], c[1], c[2], c[3]];

        let chals =
          SatisfyingAssignment::<E>::process_round(vc_state, vc_shape, vc_ck, vc, $t, transcript)?;
        let r_b = chals[0];
        r_bs.push(r_b);

        acc_eq *= (E::Scalar::ONE - r_b) * (E::Scalar::ONE - rho_t) + r_b * rho_t;
        T_cur = poly_t.evaluate(&r_b);
        r_b
      }};
    }

    macro_rules! fold_abc_pair {
      ($src_even:expr, $src_odd:expr, $dest:expr, $r_b:expr) => {{
        {
          let even = std::mem::take(&mut A_layers[$src_even]);
          let odd = &A_layers[$src_odd];
          let folded = even.iter().zip(odd.iter()).map(|(l, h)| {
            l + $r_b * (h - l)
          }).to_file_vec();
          A_layers[$dest] = folded;
        }
        {
          let even = std::mem::take(&mut B_layers[$src_even]);
          let odd = &B_layers[$src_odd];
          let folded = even.iter().zip(odd.iter()).map(|(l, h)| {
            l + $r_b * (h - l)
          }).to_file_vec();
          B_layers[$dest] = folded;
        }
        {
          let even = std::mem::take(&mut C_layers[$src_even]);
          let odd = &C_layers[$src_odd];
          let folded = even.iter().zip(odd.iter()).map(|(l, h)| {
            l + $r_b * (h - l)
          }).to_file_vec();
          C_layers[$dest] = folded;
        }
      }};
    }

    // Round 0: prove_helper
    {
      let pairs = m / 2;
      let (e0, quad_coeff) = A_layers
        .par_chunks(2)
        .zip(B_layers.par_chunks(2))
        .zip(C_layers.par_chunks(2))
        .enumerate()
        .map(|(pair_idx, ((pair_a, pair_b), pair_c))| {
          let (e0, quad_coeff) = Self::prove_helper(
            0,
            (left, right),
            &E_eq,
            &pair_a[0],
            &pair_b[0],
            &pair_c[0],
            &pair_a[1],
            &pair_b[1],
          );
          let w = suffix_weight_full::<E::Scalar>(0, ell_b, pair_idx, &rhos);
          (e0 * w, quad_coeff * w)
        })
        .reduce(
          || (E::Scalar::ZERO, E::Scalar::ZERO),
          |a, b| (a.0 + b.0, a.1 + b.1),
        );
      let r_b = finish_round!(0, e0, quad_coeff);

      if ell_b == 1 {
        for i in 0..pairs {
          fold_abc_pair!(2 * i, 2 * i + 1, i, r_b);
        }
        A_layers.truncate(pairs);
        B_layers.truncate(pairs);
        C_layers.truncate(pairs);
        m = pairs;
      }
    }

    // Rounds 1..ell_b-1: merged fold(prev round) + prove_helper(current round)
    if ell_b > 1 {
      let mut prev_r_b = r_bs[0];

      for t in 1..ell_b {
        let fold_pairs = m / 2;
        let prove_pairs = fold_pairs / 2;
        let mut e0_acc = E::Scalar::ZERO;
        let mut quad_acc = E::Scalar::ZERO;

        {
          let e_eq_ref = &E_eq;
          let rhos_ref = &rhos;

          let (a_head, _) = A_layers.split_at_mut(4 * prove_pairs);
          let (b_head, _) = B_layers.split_at_mut(4 * prove_pairs);
          let (c_head, _) = C_layers.split_at_mut(4 * prove_pairs);

          let (e0_sum, qc_sum) = a_head
            .par_chunks_mut(4)
            .zip(b_head.par_chunks_mut(4))
            .zip(c_head.par_chunks_mut(4))
            .enumerate()
            .map(|(j, ((a_chunk, b_chunk), c_chunk))| {
              // Fold [0] += r * ([1] - [0]) and [2] += r * ([3] - [2]) for A, B, C
              for chunk in [&mut *a_chunk, &mut *b_chunk, &mut *c_chunk] {
                {
                  let (lo, hi) = chunk.split_at_mut(1);
                  lo[0] = lo[0].iter().zip(hi[0].iter()).map(|(l, h)| {
                    l + prev_r_b * (h - l)
                  }).to_file_vec();
                }
                {
                  let (lo, hi) = chunk.split_at_mut(3);
                  lo[2] = lo[2].iter().zip(hi[0].iter()).map(|(l, h)| {
                    l + prev_r_b * (h - l)
                  }).to_file_vec();
                }
              }
              // Prove from folded positions [0] and [2]
              let (e0, qc) = Self::prove_helper(
                t,
                (left, right),
                e_eq_ref,
                &a_chunk[0],
                &b_chunk[0],
                &c_chunk[0],
                &a_chunk[2],
                &b_chunk[2],
              );
              let w = suffix_weight_full::<E::Scalar>(t, ell_b, j, rhos_ref);
              (e0 * w, qc * w)
            })
            .reduce(
              || (E::Scalar::ZERO, E::Scalar::ZERO),
              |a, b| (a.0 + b.0, a.1 + b.1),
            );
          e0_acc += e0_sum;
          quad_acc += qc_sum;

          // Compact folded results from positions [4j, 4j+2] into [2j, 2j+1]
          Self::compact_folded_layers_abc(&mut A_layers, &mut B_layers, &mut C_layers, prove_pairs);

          for i in (2 * prove_pairs)..fold_pairs {
            fold_abc_pair!(2 * i, 2 * i + 1, i, prev_r_b);
          }
        }

        A_layers.truncate(fold_pairs);
        B_layers.truncate(fold_pairs);
        C_layers.truncate(fold_pairs);
        m = fold_pairs;
        prev_r_b = finish_round!(t, e0_acc, quad_acc);
      }

      // Final fold: fold remaining A/B/C layers
      let final_pairs = m / 2;
      for i in 0..final_pairs {
        fold_abc_pair!(2 * i, 2 * i + 1, i, prev_r_b);
      }
      A_layers.truncate(final_pairs);
      B_layers.truncate(final_pairs);
      C_layers.truncate(final_pairs);
    }
    // T_out = poly_last(r_last) / eq(r_b, rho)
    let acc_eq_inv: Option<E::Scalar> = acc_eq.invert().into();
    let T_out = T_cur * acc_eq_inv.ok_or(SpartanError::DivisionByZero)?;
    vc.t_out_step = T_out;
    vc.eq_rho_at_rb = acc_eq;
    let _ =
      SatisfyingAssignment::<E>::process_round(vc_state, vc_shape, vc_ck, vc, ell_b, transcript)?;

    // Truncate witness W vectors to skip zero rest portion before folding.
    // The rest portion (indices effective_len..) is all zero for step circuits,
    // so the folded result there is also zero. We resize back after folding.
    // Only apply when shared+precommitted > 0 (otherwise truncation would zero everything).
    // This doesn't apply and is hard to implemetn with filevec. Did not implement.
    // let effective_len = S.num_shared + S.num_precommitted;
    // let use_truncated_fold = effective_len > 0;
    // if use_truncated_fold {
    //   for w in Ws_W.iter_mut() {
    //     w.W.truncate(effective_len);
    //   }
    // }

    let (_fold_final_span, fold_final_t) = start_span!("fold_witnesses");
    let folded_W = R1CSWitness::fold_multiple_streaming(&r_bs, &Ws_r_W, &Ws_W)?;
    // if use_truncated_fold {
    //   let full_dim = S.num_shared + S.num_precommitted + S.num_rest;
    //   folded_W.W.resize(full_dim, E::Scalar::ZERO);
    // }
    info!(elapsed_ms = %fold_final_t.elapsed().as_millis(), "fold_witnesses");

    // Optimized instance fold: only MSM data rows (shared+precommitted),
    // compute rest rows from folded blind + h (field arithmetic instead of MSM).
    // Fall back to full fold when shared+precommitted=0.
    let (_fold_final_span, fold_final_t) = start_span!("fold_instances");
    let w = weights_from_r::<E::Scalar>(&r_bs, Us.len());
    let d = Us[0].X.len();

    let mut X_acc = vec![E::Scalar::ZERO; d];
    for (i, Ui) in Us.iter().enumerate() {
      let wi = w[i];
      for (j, Uij) in Ui.X.iter().enumerate() {
        X_acc[j] += wi * Uij;
      }
    }

    let comms: Vec<_> = Us.iter().map(|U| U.comm_W.clone()).collect();
    let comm_acc = <E::PCS as FoldingEngineTrait<E>>::fold_commitments(&comms, &w)?;
    
    // if use_truncated_fold {
    //   let num_data_rows = (S.num_shared + S.num_precommitted).div_ceil(DEFAULT_COMMITMENT_WIDTH);
    //   <E::PCS as FoldingEngineTrait<E>>::fold_commitments_partial(
    //     &comms,
    //     &w,
    //     num_data_rows,
    //     &folded_W.r_W,
    //     ck,
    //   )?
    // } else {
    //   <E::PCS as FoldingEngineTrait<E>>::fold_commitments(&comms, &w)?
    // };
    let folded_U = R1CSInstance::<E>::new_unchecked(comm_acc, X_acc)?;
    info!(elapsed_ms = %fold_final_t.elapsed().as_millis(), "fold_instances");

    Ok((
      E_eq,
      std::mem::take(&mut A_layers[0]).into_vec(),
      std::mem::take(&mut B_layers[0]).into_vec(),
      std::mem::take(&mut C_layers[0]).into_vec(),
      folded_W,
      folded_U,
    ))
  }
}

/// A type that represents the prover's key
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NeutronNovaProverKey<E: Engine> {
  ck: CommitmentKey<E>,
  S_step: SplitR1CSShape<E>,
  S_core: SplitR1CSShape<E>,
  vk_digest: SpartanDigest, // digest of the verifier's key
  vc_shape: SplitMultiRoundR1CSShape<E>,
  vc_shape_regular: R1CSShape<E>,
  vc_ck: CommitmentKey<E>,
}

/// A type that represents the verifier's key
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NeutronNovaVerifierKey<E: Engine> {
  ck: CommitmentKey<E>,
  vk_ee: <E::PCS as PCSEngineTrait<E>>::VerifierKey,
  S_step: SplitR1CSShape<E>,
  S_core: SplitR1CSShape<E>,
  vc_shape: SplitMultiRoundR1CSShape<E>,
  vc_shape_regular: R1CSShape<E>,
  vc_ck: CommitmentKey<E>,
  vc_vk: VerifierKey<E>,
  #[serde(skip, default = "OnceCell::new")]
  digest: OnceCell<SpartanDigest>,
}

impl<E: Engine> crate::digest::Digestible for NeutronNovaVerifierKey<E> {
  fn write_bytes<W: Sized + std::io::Write>(&self, w: &mut W) -> Result<(), std::io::Error> {
    use bincode::Options;
    let config = bincode::DefaultOptions::new()
      .with_little_endian()
      .with_fixint_encoding();
    config
      .serialize_into(&mut *w, &self.ck)
      .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    config
      .serialize_into(&mut *w, &self.vk_ee)
      .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Use fast raw-byte path for the R1CS shapes
    self.S_step.write_bytes(w)?;
    self.S_core.write_bytes(w)?;
    // Serialize remaining small fields with bincode
    config
      .serialize_into(&mut *w, &self.vc_shape)
      .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    config
      .serialize_into(&mut *w, &self.vc_shape_regular)
      .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    config
      .serialize_into(&mut *w, &self.vc_ck)
      .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    config
      .serialize_into(&mut *w, &self.vc_vk)
      .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(())
  }
}

impl<E: Engine> DigestHelperTrait<E> for NeutronNovaVerifierKey<E> {
  /// Returns the digest of the verifier's key.
  fn digest(&self) -> Result<SpartanDigest, SpartanError> {
    self
      .digest
      .get_or_try_init(|| {
        let dc = DigestComputer::<_>::new(self);
        dc.digest()
      })
      .cloned()
      .map_err(|_| SpartanError::DigestError {
        reason: "Unable to compute digest for SpartanVerifierKey".to_string(),
      })
  }
}

/// Holds the proof produced by the NeutronNova folding scheme followed by NeutronNova SNARK
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NeutronNovaZkSNARK<E: Engine> {
  /// Shared commitment stored once (same for all step instances and core).
  comm_W_shared: Option<Commitment<E>>,
  step_instances: Vec<SplitR1CSInstance<E>>,
  core_instance: SplitR1CSInstance<E>,
  eval_arg: <E::PCS as PCSEngineTrait<E>>::EvaluationArgument,
  U_verifier: SplitMultiRoundR1CSInstance<E>,
  nifs: NovaNIFS<E>,
  random_U: RelaxedR1CSInstance<E>,
  relaxed_snark: crate::spartan_relaxed::RelaxedR1CSSpartanProof<E>,
}

impl<E: Engine> NeutronNovaZkSNARK<E>
where
  E::PCS: FoldingEngineTrait<E>,
{
  /// Sets up the NeutronNova SNARK for a batch of circuits of type `C1` and a single circuit of type `C2`
  ///
  /// # Parameters
  /// - `step_circuit`: The circuit to be folded in the batch
  /// - `core_circuit`: The core circuit that connects the batch together
  /// - `num_steps`: The number of step circuits in the batch (will be padded to next power of two internally)
  pub fn setup<C1: SpartanCircuit<E>, C2: SpartanCircuit<E>>(
    step_circuit: &C1,
    core_circuit: &C2,
    num_steps: usize,
  ) -> Result<(NeutronNovaProverKey<E>, NeutronNovaVerifierKey<E>), SpartanError> {
    let (_setup_span, setup_t) = start_span!("neutronnova_setup");

    let (_r1cs_span, r1cs_t) = start_span!("r1cs_shape_generation");
    debug!("Synthesizing step circuit");
    let mut S_step = ShapeCS::r1cs_shape(step_circuit)?;
    debug!("Finished synthesizing step circuit");

    debug!("Synthesizing core circuit");
    let mut S_core = ShapeCS::r1cs_shape(core_circuit)?;
    debug!("Finished synthesizing core circuit");

    SplitR1CSShape::equalize(&mut S_step, &mut S_core);

    info!(
      "Step circuit's witness sizes: shared = {}, precommitted = {}, rest = {}",
      S_step.num_shared, S_step.num_precommitted, S_step.num_rest
    );
    info!(
      "Core circuit's witness sizes: shared = {}, precommitted = {}, rest = {}",
      S_core.num_shared, S_core.num_precommitted, S_core.num_rest
    );
    info!(elapsed_ms = %r1cs_t.elapsed().as_millis(), "r1cs_shape_generation");

    let (_ck_span, ck_t) = start_span!("commitment_key_generation");
    let (ck, vk_ee) = SplitR1CSShape::commitment_key(&[&S_step, &S_core])?;
    E::PCS::precompute_ck(&ck);
    info!(elapsed_ms = %ck_t.elapsed().as_millis(), "commitment_key_generation");

    // Calculate num_rounds_b from num_steps by padding to next power of two
    let (_vc_span, vc_t) = start_span!("verifier_circuit_setup");
    let num_rounds_b = num_steps.next_power_of_two().log_2();

    let num_vars = S_step.num_shared + S_step.num_precommitted + S_step.num_rest;
    let num_rounds_x = usize::try_from(S_step.num_cons.ilog2()).unwrap();
    let num_rounds_y = usize::try_from(num_vars.ilog2()).unwrap() + 1;
    let vc = NeutronNovaVerifierCircuit::<E>::default(num_rounds_b, num_rounds_x, num_rounds_y, 32);
    let (vc_shape, vc_ck, vc_vk) =
      <ShapeCS<E> as MultiRoundSpartanShape<E>>::multiround_r1cs_shape(&vc)?;
    let vc_shape_regular = vc_shape.to_regular_shape();
    info!(elapsed_ms = %vc_t.elapsed().as_millis(), "verifier_circuit_setup");
    // Eagerly init FixedBaseMul table before cloning so both pk/vk get it
    E::PCS::precompute_ck(&vc_ck);
    let vk: NeutronNovaVerifierKey<E> = NeutronNovaVerifierKey {
      ck: ck.clone(),
      S_step: S_step.clone(),
      S_core: S_core.clone(),
      vk_ee,
      vc_shape: vc_shape.clone(),
      vc_shape_regular: vc_shape_regular.clone(),
      vc_ck: vc_ck.clone(),
      vc_vk: vc_vk.clone(),
      digest: OnceCell::new(),
    };

    let vk_digest = vk.digest()?;
    let pk = NeutronNovaProverKey {
      ck,
      S_step,
      S_core,
      vc_shape,
      vc_shape_regular,
      vc_ck,
      vk_digest,
    };

    // Eagerly precompute sparse matrix data for the step and core circuits
    pk.S_step.precompute();
    pk.S_core.precompute();
    vk.S_step.precompute();
    vk.S_core.precompute();
    info!(elapsed_ms = %setup_t.elapsed().as_millis(), "neutronnova_setup");
    Ok((pk, vk))
  }

  /// Proves the folding of a batch of R1CS instances and a core circuit that connects them together.
  pub fn prove<C1: SpartanCircuit<E>, C2: SpartanCircuit<E>>(
    pk: &NeutronNovaProverKey<E>,
    step_circuits: &[C1],
    core_circuit: &C2,
    is_small: bool,
  ) -> Result<Self, SpartanError>
  where
    E::Scalar: SerializeRaw + DeserializeRaw,
  {
    let (_prep_span, prep_t) = start_span!("shared_initialization");

    // Shared witness (serial): seed for all per-circuit clones.
    let ps =
      SatisfyingAssignment::shared_witness(&pk.S_step, &pk.ck, &step_circuits[0], is_small)?;

    // Core precommitted witness + rerandomize (serial): produces comm_W_shared needed by steps.
    let mut ps_core = ps.clone();
    SatisfyingAssignment::precommitted_witness(
      &mut ps_core,
      &pk.S_core,
      &pk.ck,
      core_circuit,
      is_small,
    )?;
    ps_core.rerandomize_in_place(&pk.ck, &pk.S_core)?;
    let comm_W_shared = ps_core.comm_W_shared.clone();
    let r_W_shared = ps_core.r_W_shared.clone();

    info!(elapsed_ms = %prep_t.elapsed().as_millis(), "shared_initialization");

    let (_prove_span, prove_t) = start_span!("neutronnova_prove");

    // Build verifier circuit before parallel section — sizes are known from pk and step count.
    let n = step_circuits.len();
    let n_padded = n.next_power_of_two();
    let num_vars = pk.S_step.num_shared + pk.S_step.num_precommitted + pk.S_step.num_rest;
    let num_rounds_b = n_padded.log_2();
    let num_rounds_x = pk.S_step.num_cons.log_2();
    let num_rounds_y = num_vars.log_2() + 1;

    let mut vc = NeutronNovaVerifierCircuit::<E>::default(
      num_rounds_b,
      num_rounds_x,
      num_rounds_y,
      pk.vc_shape.commitment_width,
    );
    let mut vc_state = SatisfyingAssignment::<E>::initialize_multiround_witness(&pk.vc_shape)?;

    // One parallel section: steps run the full pipeline per circuit; core runs r1cs + to_regular.
    let (_gen_span, gen_t) = start_span!(
      "generate_instances_witnesses",
      step_circuits = step_circuits.len()
    );
    let (res_steps, res_core) = rayon::join(
      || -> Result<Vec<_>, SpartanError> {
        (0..n)
          .into_par_iter()
          .map(|i| -> Result<_, SpartanError> {
            let mut ps_i = ps.clone();
            SatisfyingAssignment::precommitted_witness(
              &mut ps_i,
              &pk.S_step,
              &pk.ck,
              &step_circuits[i],
              is_small,
            )?;
            ps_i.rerandomize_with_shared_in_place(
              &pk.ck,
              &pk.S_step,
              &comm_W_shared,
              &r_W_shared,
            )?;

            let mut transcript = E::TE::new(b"neutronnova_prove");
            transcript.absorb(b"vk", &pk.vk_digest);
            transcript.absorb(b"num_circuits", &E::Scalar::from(n as u64));
            transcript.absorb(b"circuit_index", &E::Scalar::from(i as u64));
            let public_values = step_circuits[i].public_values().map_err(|e| {
              SpartanError::SynthesisError {
                reason: format!("Circuit does not provide public IO: {e}"),
              }
            })?;
            transcript.absorb(b"public_values", &public_values.as_slice());

            let (split_instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
              &mut ps_i,
              &pk.S_step,
              &pk.ck,
              &step_circuits[i],
              is_small,
              &mut transcript,
            )?;

            let regular_instance = split_instance.to_regular_instance()?;

            let mut z = Vec::with_capacity(witness.W.len() + 1 + regular_instance.X.len());
            z.extend_from_slice(&witness.W);
            z.push(E::Scalar::ONE);
            z.extend_from_slice(&regular_instance.X);
            let (av_fv, bv_fv, cv_fv) =
              from_iter(pk.S_step.multiply_vec_iter(&z)?).unzip3();

            let R1CSWitness { W: _, r_W, is_small } = witness;
            // TODO: Make this stylistically look like Pratyush's code. 
            // TODO: should be able to do a non-owning iter and move it up to get a bit more interleaving.
            let w_fv = from_iter(W.into_iter()).to_file_vec();

            Ok((split_instance, is_small, r_W, w_fv, regular_instance, av_fv, bv_fv, cv_fv))
          })
          .collect()
      },
      || -> Result<_, SpartanError> {
        let mut transcript = E::TE::new(b"neutronnova_prove");
        transcript.absorb(b"vk", &pk.vk_digest);
        let public_values_core = core_circuit.public_values().map_err(|e| {
          SpartanError::SynthesisError {
            reason: format!("Core circuit does not provide public IO: {e}"),
          }
        })?;
        transcript.absorb(b"public_values", &public_values_core.as_slice());
        let (core_instance, core_witness) = SatisfyingAssignment::r1cs_instance_and_witness(
          &mut ps_core,
          &pk.S_core,
          &pk.ck,
          core_circuit,
          is_small,
          &mut transcript,
        )?;
        let core_instance_regular = core_instance.to_regular_instance()?;
        Ok((core_instance, core_witness, core_instance_regular))
      },
    );

    let step_tuples = res_steps?;
    let (core_instance, core_witness, core_instance_regular) = res_core?;
    info!(elapsed_ms = %gen_t.elapsed().as_millis(), step_circuits = step_circuits.len(), "generate_instances_witnesses");

    let du_out = std::process::Command::new("du")
      .args(["-sk", "/tmp"])
      .output();
    if let Ok(out) = du_out {
      info!(output = %String::from_utf8_lossy(&out.stdout), "du_tmp");
    }

    // Unpack step results and pad A/B/C layers to n_padded (cloning from index 0).
    let mut step_instances = Vec::with_capacity(n);
    let mut step_witness_blinds = Vec::with_capacity(n);
    let mut step_witness_is_small = Vec::with_capacity(n);
    let mut step_witnesses: Vec<scribe_streams::file_vec::FileVec<E::Scalar>> = Vec::with_capacity(n);
    let mut step_instances_regular = Vec::with_capacity(n);
    let mut A_layers: Vec<scribe_streams::file_vec::FileVec<E::Scalar>> = Vec::with_capacity(n_padded);
    let mut B_layers: Vec<scribe_streams::file_vec::FileVec<E::Scalar>> = Vec::with_capacity(n_padded);
    let mut C_layers: Vec<scribe_streams::file_vec::FileVec<E::Scalar>> = Vec::with_capacity(n_padded);
    for (si, is_small, r_W, w_fv, ri, av_fv, bv_fv, cv_fv) in step_tuples {
      step_instances.push(si);
      step_witness_is_small.push(is_small);
      step_witness_blinds.push(r_W);
      step_witnesses.push(w_fv);
      step_instances_regular.push(ri);
      A_layers.push(av_fv);
      B_layers.push(bv_fv);
      C_layers.push(cv_fv);
    }
    for _ in n..n_padded {
      A_layers.push(scribe_streams::file_vec::FileVec::clone(&A_layers[0]));
      B_layers.push(scribe_streams::file_vec::FileVec::clone(&B_layers[0]));
      C_layers.push(scribe_streams::file_vec::FileVec::clone(&C_layers[0]));
    }

    // NIFS transcript: absorb core instance, then NIFS will absorb step instances.
    let mut transcript = E::TE::new(b"neutronnova_prove");
    transcript.absorb(b"vk", &pk.vk_digest);
    transcript.absorb(b"core_instance", &core_instance_regular);

    let (_nifs_span, nifs_t) = start_span!("NIFS");
    let (E_eq, Az_step, Bz_step, Cz_step, folded_W, folded_U) = NeutronNovaNIFS::<E>::prove(
      &pk.S_step,
      &pk.ck,
      step_instances_regular,
      step_witness_is_small,
      step_witness_blinds,
      step_witnesses,
      A_layers,
      B_layers,
      C_layers,
      &mut vc,
      &mut vc_state,
      &pk.vc_shape,
      &pk.vc_ck,
      &mut transcript,
    )?;
    info!(elapsed_ms = %nifs_t.elapsed().as_millis(), "NIFS");

    let (_tensor_span, tensor_t) = start_span!("compute_tensor_and_poly_tau");
    let (_ell, left, _right) = compute_tensor_decomp(pk.S_step.num_cons);
    let mut E1 = E_eq;
    let E2 = E1.split_off(left);

    let mut poly_tau_left = MultilinearPolynomial::new(E1);
    let poly_tau_right = MultilinearPolynomial::new(E2);

    info!(elapsed_ms = %tensor_t.elapsed().as_millis(), "compute_tensor_and_poly_tau");

    // outer sum-check preparation
    let (_mp_span, mp_t) = start_span!("prepare_multilinear_polys");
    let (mut poly_Az_step, mut poly_Bz_step, mut poly_Cz_step) = (
      MultilinearPolynomial::new(Az_step),
      MultilinearPolynomial::new(Bz_step),
      MultilinearPolynomial::new(Cz_step),
    );

    let (mut poly_Az_core, mut poly_Bz_core, mut poly_Cz_core) = {
      let (_core_span, core_t) = start_span!("compute_core_polys");
      let z = [
        core_witness.W.clone(),
        vec![E::Scalar::ONE],
        core_instance.public_values.clone(),
        core_instance.challenges.clone(),
      ]
      .concat();

      let (Az, Bz, Cz) = pk.S_core.multiply_vec(&z)?;
      info!(elapsed_ms = %core_t.elapsed().as_millis(), "compute_core_polys");
      (
        MultilinearPolynomial::new(Az),
        MultilinearPolynomial::new(Bz),
        MultilinearPolynomial::new(Cz),
      )
    };

    info!(elapsed_ms = %mp_t.elapsed().as_millis(), "prepare_multilinear_polys");
    let outer_start_index = num_rounds_b + 1;
    // outer sum-check (batched)
    let (_sc_span, sc_t) = start_span!("outer_sumcheck_batched");
    let r_x = SumcheckProof::<E>::prove_cubic_with_additive_term_batched_zk(
      num_rounds_x,
      &mut poly_tau_left,
      &poly_tau_right,
      &mut poly_Az_step,
      &mut poly_Az_core,
      &mut poly_Bz_step,
      &mut poly_Bz_core,
      &mut poly_Cz_step,
      &mut poly_Cz_core,
      &mut vc,
      &mut vc_state,
      &pk.vc_shape,
      &pk.vc_ck,
      &mut transcript,
      outer_start_index,
    )?;
    info!(elapsed_ms = %sc_t.elapsed().as_millis(), "outer_sumcheck_batched");
    vc.claim_Az_step = poly_Az_step[0];
    vc.claim_Bz_step = poly_Bz_step[0];
    vc.claim_Cz_step = poly_Cz_step[0];
    vc.claim_Az_core = poly_Az_core[0];
    vc.claim_Bz_core = poly_Bz_core[0];
    vc.claim_Cz_core = poly_Cz_core[0];
    vc.tau_at_rx = poly_tau_left[0];

    let chals = SatisfyingAssignment::<E>::process_round(
      &mut vc_state,
      &pk.vc_shape,
      &pk.vc_ck,
      &vc,
      outer_start_index + num_rounds_x,
      &mut transcript,
    )?;
    let r = chals[0];

    // inner sum-check preparation
    let claim_inner_joint_step = vc.claim_Az_step + r * vc.claim_Bz_step + r * r * vc.claim_Cz_step;
    let claim_inner_joint_core = vc.claim_Az_core + r * vc.claim_Bz_core + r * r * vc.claim_Cz_core;

    let (_eval_rx_span, eval_rx_t) = start_span!("compute_eval_rx");
    let evals_rx = EqPolynomial::evals_from_points(&r_x);
    info!(elapsed_ms = %eval_rx_t.elapsed().as_millis(), "compute_eval_rx");

    let (_sparse_span, sparse_t) = start_span!("compute_eval_table_sparse");
    let (poly_ABC_step, step_lo_eff, step_hi_eff) =
      pk.S_step.bind_and_prepare_poly_ABC_full(&evals_rx, &r);
    let (poly_ABC_core, core_lo_eff, core_hi_eff) =
      pk.S_core.bind_and_prepare_poly_ABC_full(&evals_rx, &r);
    info!(elapsed_ms = %sparse_t.elapsed().as_millis(), "compute_eval_table_sparse");
    // inner sum-check
    let (_sc2_span, sc2_t) = start_span!("inner_sumcheck_batched");

    debug!("Proving inner sum-check with {} rounds", num_rounds_y);
    debug!(
      "Inner sum-check sizes - poly_ABC_step: {}, poly_ABC_core: {}",
      poly_ABC_step.len(),
      poly_ABC_core.len()
    );

    // Build z vectors for the folded and core instances.
    // Non-zero prefix = w_len + 1 + x_len (witness + u + public inputs).
    let (z_folded_vec, z_folded_lo, z_folded_hi) = {
      let mut v = vec![E::Scalar::ZERO; num_vars * 2];
      let w_len = folded_W.W.len();
      v[..w_len].copy_from_slice(&folded_W.W);
      v[w_len] = E::Scalar::ONE;
      let x_len = folded_U.X.len();
      v[w_len + 1..w_len + 1 + x_len].copy_from_slice(&folded_U.X);
      let last_nz = w_len + 1 + x_len;
      (v, last_nz.min(num_vars), last_nz.saturating_sub(num_vars))
    };
    let (z_core_vec, z_core_lo, z_core_hi) = {
      let mut v = vec![E::Scalar::ZERO; num_vars * 2];
      let w_len = core_witness.W.len();
      v[..w_len].copy_from_slice(&core_witness.W);
      v[w_len] = E::Scalar::ONE;
      let x_len = core_instance_regular.X.len();
      v[w_len + 1..w_len + 1 + x_len].copy_from_slice(&core_instance_regular.X);
      let last_nz = w_len + 1 + x_len;
      (v, last_nz.min(num_vars), last_nz.saturating_sub(num_vars))
    };

    // Use actual X length for hi_eff (num_public in SplitR1CSShape may not include shared inputs)
    let step_hi_eff = step_hi_eff.max(z_folded_hi);
    let core_hi_eff = core_hi_eff.max(z_core_hi);

    let (r_y, evals) = SumcheckProof::<E>::prove_quad_batched_zk(
      &[claim_inner_joint_step, claim_inner_joint_core],
      num_rounds_y,
      &mut MultilinearPolynomial::new_with_halves(poly_ABC_step, step_lo_eff, step_hi_eff),
      &mut MultilinearPolynomial::new_with_halves(poly_ABC_core, core_lo_eff, core_hi_eff),
      &mut MultilinearPolynomial::new_with_halves(z_folded_vec, z_folded_lo, z_folded_hi),
      &mut MultilinearPolynomial::new_with_halves(z_core_vec, z_core_lo, z_core_hi),
      &mut vc,
      &mut vc_state,
      &pk.vc_shape,
      &pk.vc_ck,
      &mut transcript,
      outer_start_index + num_rounds_x + 1,
    )?;
    info!(elapsed_ms = %sc2_t.elapsed().as_millis(), "inner_sumcheck_batched");

    let eval_Z_step = evals[2];
    let eval_Z_core = evals[3];

    let eval_X_step = {
      let X = vec![E::Scalar::ONE]
        .into_iter()
        .chain(folded_U.X.iter().cloned())
        .collect::<Vec<E::Scalar>>();
      let num_vars_log2 = usize::try_from(num_vars.ilog2()).unwrap();
      SparsePolynomial::new(num_vars_log2, X).evaluate(&r_y[1..])
    };
    let eval_X_core = {
      let X = vec![E::Scalar::ONE]
        .into_iter()
        .chain(core_instance_regular.X.iter().cloned())
        .collect::<Vec<E::Scalar>>();
      let num_vars_log2 = usize::try_from(num_vars.ilog2()).unwrap();
      SparsePolynomial::new(num_vars_log2, X).evaluate(&r_y[1..])
    };
    let inv: Option<E::Scalar> = (E::Scalar::ONE - r_y[0]).invert().into();
    let one_minus_ry0_inv = inv.ok_or(SpartanError::DivisionByZero)?;
    let eval_W_step = (eval_Z_step - r_y[0] * eval_X_step) * one_minus_ry0_inv;
    let eval_W_core = (eval_Z_core - r_y[0] * eval_X_core) * one_minus_ry0_inv;

    vc.eval_W_step = eval_W_step;
    vc.eval_W_core = eval_W_core;
    vc.eval_X_step = eval_X_step;
    vc.eval_X_core = eval_X_core;

    // Inner final equality round
    let _ = SatisfyingAssignment::<E>::process_round(
      &mut vc_state,
      &pk.vc_shape,
      &pk.vc_ck,
      &vc,
      outer_start_index + num_rounds_x + 1 + num_rounds_y,
      &mut transcript,
    )?;

    // Commit eval_W_step
    let eval_w_step_commit_round = outer_start_index + num_rounds_x + 1 + num_rounds_y + 1;
    let _ = SatisfyingAssignment::<E>::process_round(
      &mut vc_state,
      &pk.vc_shape,
      &pk.vc_ck,
      &vc,
      eval_w_step_commit_round,
      &mut transcript,
    )?;

    // Commit eval_W_core
    let _ = SatisfyingAssignment::<E>::process_round(
      &mut vc_state,
      &pk.vc_shape,
      &pk.vc_ck,
      &vc,
      eval_w_step_commit_round + 1,
      &mut transcript,
    )?;

    let (U_verifier, W_verifier) =
      SatisfyingAssignment::<E>::finalize_multiround_witness(&mut vc_state, &pk.vc_shape)?;

    let U_verifier_regular = U_verifier.to_regular_instance()?;

    // Sample fresh random instance/witness for ZK (must be done per-prove to preserve zero-knowledge).
    let (random_U, random_W) = pk
      .vc_shape_regular
      .sample_random_instance_witness(&pk.vc_ck)?;
    let (nifs, folded_W_verifier, folded_u, folded_X) = NovaNIFS::<E>::prove(
      &pk.vc_ck,
      &pk.vc_shape_regular,
      &random_U,
      &random_W,
      &U_verifier_regular,
      &W_verifier,
      &mut transcript,
    )?;

    // Prove satisfiability of the folded VC instance via relaxed R1CS Spartan
    let relaxed_snark = crate::spartan_relaxed::RelaxedR1CSSpartanProof::prove(
      &pk.vc_shape_regular,
      &pk.vc_ck,
      &folded_u,
      &folded_X,
      &folded_W_verifier,
      &mut transcript,
    )?;
    // access two claimed commitments to evaluations of W_step and W_core
    let comm_eval_W_step = U_verifier.comm_w_per_round[eval_w_step_commit_round].clone();
    let blind_eval_W_step = vc_state.r_w_per_round[eval_w_step_commit_round].clone();

    let comm_eval_W_core = U_verifier.comm_w_per_round[eval_w_step_commit_round + 1].clone();
    let blind_eval_W_core = vc_state.r_w_per_round[eval_w_step_commit_round + 1].clone();

    // the commitments are already absorbed in the transcript, so we simply squeeze the challenge
    let c_eval = transcript.squeeze(b"c_eval")?;

    // fold evaluation claims into one
    let (_fold_eval_span, fold_eval_t) = start_span!("fold_evaluation_claims");
    let comm = <E::PCS as FoldingEngineTrait<E>>::fold_commitments(
      &[folded_U.comm_W, core_instance_regular.comm_W],
      &[E::Scalar::ONE, c_eval],
    )?;
    let blind = <E::PCS as FoldingEngineTrait<E>>::fold_blinds(
      &[folded_W.r_W.clone(), core_witness.r_W.clone()],
      &[E::Scalar::ONE, c_eval],
    )?;
    let W = folded_W
      .W
      .par_iter()
      .zip(core_witness.W.par_iter())
      .map(|(w1, w2)| *w1 + c_eval * *w2)
      .collect::<Vec<_>>();
    let comm_eval = <E::PCS as FoldingEngineTrait<E>>::fold_commitments(
      &[comm_eval_W_step, comm_eval_W_core],
      &[E::Scalar::ONE, c_eval],
    )?;
    let blind_eval = <E::PCS as FoldingEngineTrait<E>>::fold_blinds(
      &[blind_eval_W_step, blind_eval_W_core],
      &[E::Scalar::ONE, c_eval],
    )?;
    info!(elapsed_ms = %fold_eval_t.elapsed().as_millis(), "fold_evaluation_claims");

    let (_pcs_span, pcs_t) = start_span!("pcs_prove");
    let eval_arg = E::PCS::prove(
      &pk.ck,
      &pk.vc_ck,
      &mut transcript,
      &comm,
      &W,
      &blind,
      &r_y[1..],
      &comm_eval,
      &blind_eval,
    )?;
    info!(elapsed_ms = %pcs_t.elapsed().as_millis(), "pcs_prove");

    // Extract shared commitment (same for all step instances and core) and strip from instances
    let comm_W_shared = step_instances.first().and_then(|u| u.comm_W_shared.clone());
    let step_instances = step_instances
      .into_iter()
      .map(|mut u| {
        u.comm_W_shared = None;
        u
      })
      .collect::<Vec<_>>();
    let mut core_instance = core_instance;
    core_instance.comm_W_shared = None;

    let result = Self {
      comm_W_shared,
      step_instances,
      core_instance,
      eval_arg,
      U_verifier,
      nifs,
      random_U,
      relaxed_snark,
    };

    info!(elapsed_ms = %prove_t.elapsed().as_millis(), "neutronnova_prove");
    Ok(result)
  }

  /// Verifies the NeutronNovaZkSNARK and returns the public IO from the instances
  pub fn verify(
    &self,
    vk: &NeutronNovaVerifierKey<E>,
    num_instances: usize,
  ) -> Result<(Vec<Vec<E::Scalar>>, Vec<E::Scalar>), SpartanError> {
    let (_verify_span, _verify_t) = start_span!("neutronnova_verify");
    if num_instances == 0 || num_instances != self.step_instances.len() {
      return Err(SpartanError::ProofVerifyError {
        reason: format!(
          "Expected {} instances (non-zero), got {}",
          num_instances,
          self.step_instances.len()
        ),
      });
    }

    // Reconstruct step instances and core instance with the shared commitment
    let step_instances: Vec<SplitR1CSInstance<E>> = self
      .step_instances
      .iter()
      .map(|u| {
        let mut u = u.clone();
        u.comm_W_shared = self.comm_W_shared.clone();
        u
      })
      .collect();
    let mut core_instance = self.core_instance.clone();
    core_instance.comm_W_shared = self.comm_W_shared.clone();

    // validate the step instances
    let (_validate_span, validate_t) =
      start_span!("validate_instances", instances = step_instances.len());
    for (i, u) in step_instances.iter().enumerate() {
      let mut transcript = E::TE::new(b"neutronnova_prove");
      transcript.absorb(b"vk", &vk.digest()?);
      transcript.absorb(
        b"num_circuits",
        &E::Scalar::from(step_instances.len() as u64),
      );
      transcript.absorb(b"circuit_index", &E::Scalar::from(i as u64));
      // absorb the public IO into the transcript
      transcript.absorb(b"public_values", &u.public_values.as_slice());

      u.validate(&vk.S_step, &mut transcript)?;
    }

    // validate the core instance
    let mut transcript = E::TE::new(b"neutronnova_prove");
    transcript.absorb(b"vk", &vk.digest()?);
    // absorb the public IO into the transcript
    transcript.absorb(b"public_values", &core_instance.public_values.as_slice());

    core_instance.validate(&vk.S_core, &mut transcript)?;
    info!(elapsed_ms = %validate_t.elapsed().as_millis(), instances = step_instances.len(), "validate_instances");

    // shared commitment consistency was enforced at construction -- all step instances share comm_W_shared
    // also verify it matches the core instance
    for u in &step_instances {
      if u.comm_W_shared != core_instance.comm_W_shared {
        return Err(SpartanError::ProofVerifyError {
          reason: "All instances must have the same shared commitment".to_string(),
        });
      }
    }

    let (_convert_span, convert_t) = start_span!("convert_to_regular_verify");
    let mut step_instances_padded = step_instances.clone();
    if step_instances_padded.len() != step_instances_padded.len().next_power_of_two() {
      step_instances_padded.extend(std::iter::repeat_n(
        step_instances_padded[0].clone(),
        step_instances_padded.len().next_power_of_two() - step_instances_padded.len(),
      ));
    }
    let step_instances_regular = step_instances_padded
      .par_iter()
      .map(|u| u.to_regular_instance())
      .collect::<Result<Vec<_>, _>>()?;

    let core_instance_regular = core_instance.to_regular_instance()?;
    info!(elapsed_ms = %convert_t.elapsed().as_millis(), "convert_to_regular_verify");
    // We start a new transcript for the NeutronNova NIFS proof
    let mut transcript = E::TE::new(b"neutronnova_prove");

    // absorb the verifier key and instances
    transcript.absorb(b"vk", &vk.digest()?);
    transcript.absorb(b"core_instance", &core_instance_regular);
    for U in step_instances_regular.iter() {
      transcript.absorb(b"U", U);
    }
    transcript.absorb(b"T", &E::Scalar::ZERO); // we always have T=0 in NeutronNova

    // compute the number of rounds of NIFS, outer sum-check, and inner sum-check
    let num_rounds_b = step_instances_regular.len().log_2();
    let num_vars = vk.S_step.num_shared + vk.S_step.num_precommitted + vk.S_step.num_rest;
    let num_rounds_x = vk.S_step.num_cons.log_2();
    let num_rounds_y = num_vars.log_2() + 1;

    // we need num_rounds_b challenges for folding the step instances; we also need tau to compress multiple R1CS checks
    let tau = transcript.squeeze(b"tau")?;
    let rhos = (0..num_rounds_b)
      .map(|_| transcript.squeeze(b"rho"))
      .collect::<Result<Vec<_>, _>>()?;

    // validate the provided multi-round verifier instance and advance transcript
    let (_u_verifier_validate_span, u_verifier_validate_t) = start_span!("u_verifier_validate");
    self.U_verifier.validate(&vk.vc_shape, &mut transcript)?;
    info!(elapsed_ms = %u_verifier_validate_t.elapsed().as_millis(), "u_verifier_validate");

    let U_verifier_regular = self.U_verifier.to_regular_instance()?;

    // extract challenges and public IO from U_verifier's public IO
    let num_public_values = 6usize;
    let num_challenges = num_rounds_b + num_rounds_x + 1 + num_rounds_y;
    if U_verifier_regular.X.len() != num_challenges + num_public_values {
      return Err(SpartanError::ProofVerifyError {
        reason: format!(
          "Verifier instance has incorrect number of public IO: expected {}, got {}",
          num_challenges + num_public_values,
          U_verifier_regular.X.len()
        ),
      });
    }

    let challenges = &U_verifier_regular.X[0..num_challenges];
    let public_values = &U_verifier_regular.X[num_challenges..num_challenges + 6];

    let r_b = challenges[0..num_rounds_b].to_vec();
    let r_x = challenges[num_rounds_b..num_rounds_b + num_rounds_x].to_vec();
    let r = challenges[num_rounds_b + num_rounds_x]; // r for combining inner claims
    let r_y = challenges[num_rounds_b + num_rounds_x + 1..].to_vec();

    // fold_multiple and nifs.verify are independent: overlap them
    let (_fold_nifs_span, fold_nifs_t) = start_span!("fold_and_nifs_verify");
    let (folded_U_result, folded_U_verifier_result) = rayon::join(
      || R1CSInstance::fold_multiple(&r_b, &step_instances_regular),
      || {
        self
          .nifs
          .verify(&mut transcript, &self.random_U, &U_verifier_regular)
      },
    );
    let folded_U = folded_U_result?;
    let folded_U_verifier = folded_U_verifier_result?;
    info!(elapsed_ms = %fold_nifs_t.elapsed().as_millis(), "fold_and_nifs_verify");

    let (_relaxed_snark_span, relaxed_snark_t) = start_span!("relaxed_snark_verify");
    self
      .relaxed_snark
      .verify(
        &vk.vc_shape_regular,
        &vk.vc_vk,
        &folded_U_verifier,
        &mut transcript,
      )
      .map_err(|e| SpartanError::ProofVerifyError {
        reason: format!("Relaxed Spartan verify failed: {e}"),
      })?;
    info!(elapsed_ms = %relaxed_snark_t.elapsed().as_millis(), "relaxed_snark_verify");
    let (_matrix_eval_span, matrix_eval_t) = start_span!("matrix_evaluations");
    let (eval_A_step, eval_B_step, eval_C_step, eval_A_core, eval_B_core, eval_C_core) = {
      let T_x = EqPolynomial::evals_from_points(&r_x);
      let T_y = EqPolynomial::evals_from_points(&r_y);
      let (eval_A_step, eval_B_step, eval_C_step) = vk.S_step.evaluate_with_tables_fast(&T_x, &T_y);
      let (eval_A_core, eval_B_core, eval_C_core) = vk.S_core.evaluate_with_tables_fast(&T_x, &T_y);

      (
        eval_A_step,
        eval_B_step,
        eval_C_step,
        eval_A_core,
        eval_B_core,
        eval_C_core,
      )
    };
    info!(elapsed_ms = %matrix_eval_t.elapsed().as_millis(), "matrix_evaluations");

    let eval_X_step = {
      let X = vec![E::Scalar::ONE]
        .into_iter()
        .chain(folded_U.X.iter().cloned())
        .collect::<Vec<E::Scalar>>();
      let num_vars_log2 = usize::try_from(num_vars.ilog2()).unwrap();
      SparsePolynomial::new(num_vars_log2, X).evaluate(&r_y[1..])
    };
    let eval_X_core = {
      let X = vec![E::Scalar::ONE]
        .into_iter()
        .chain(core_instance_regular.X.iter().cloned())
        .collect::<Vec<E::Scalar>>();
      let num_vars_log2 = usize::try_from(num_vars.ilog2()).unwrap();
      SparsePolynomial::new(num_vars_log2, X).evaluate(&r_y[1..])
    };

    // Compute quotient_* = (eval_A + r*eval_B + r^2*eval_C) for both branches
    let quotient_step = eval_A_step + r * eval_B_step + r * r * eval_C_step;
    let quotient_core = eval_A_core + r * eval_B_core + r * r * eval_C_core;
    let tau_at_rx = PowPolynomial::new(&tau, r_x.len()).evaluate(&r_x)?;
    let eq_rho_at_rb = EqPolynomial::new(r_b).evaluate(&rhos);

    if public_values[0] != tau_at_rx
      || public_values[1] != eval_X_step
      || public_values[2] != eval_X_core
      || public_values[3] != eq_rho_at_rb
      || public_values[4] != quotient_step
      || public_values[5] != quotient_core
    {
      return Err(SpartanError::ProofVerifyError {
        reason:
          "Verifier instance public tau_at_rx/eval_X_step/eq_rho_at_rb/eval_X_core/quotients do not match recomputation"
            .to_string(),
      });
    }

    // verify PCS eval
    let c_eval = transcript.squeeze(b"c_eval")?;

    let eval_w_step_commit_round = num_rounds_b + 1 + num_rounds_x + 1 + num_rounds_y + 1;
    let comm_eval_W_step = self.U_verifier.comm_w_per_round[eval_w_step_commit_round].clone();
    let comm_eval_W_core = self.U_verifier.comm_w_per_round[eval_w_step_commit_round + 1].clone();

    let comm = <E::PCS as FoldingEngineTrait<E>>::fold_commitments(
      &[folded_U.comm_W, core_instance_regular.comm_W],
      &[E::Scalar::ONE, c_eval],
    )?;
    let comm_eval = <E::PCS as FoldingEngineTrait<E>>::fold_commitments(
      &[comm_eval_W_step, comm_eval_W_core],
      &[E::Scalar::ONE, c_eval],
    )?;

    let (_pcs_verify_span, pcs_verify_t) = start_span!("pcs_verify");
    E::PCS::verify(
      &vk.vk_ee,
      &vk.vc_ck,
      &mut transcript,
      &comm,
      &r_y[1..],
      &comm_eval,
      &self.eval_arg,
    )?;
    info!(elapsed_ms = %pcs_verify_t.elapsed().as_millis(), "pcs_verify");

    info!(elapsed_ms = %_verify_t.elapsed().as_millis(), "neutronnova_verify");

    let public_values_step = step_instances
      .iter()
      .take(num_instances)
      .map(|u| u.public_values.clone())
      .collect::<Vec<Vec<_>>>();

    let public_values_core = core_instance.public_values.clone();

    // return a vector of public values
    Ok((public_values_step, public_values_core))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::provider::T256HyraxEngine;
  use bellpepper::gadgets::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    sha256::sha256,
  };
  use bellpepper_core::{ConstraintSystem, SynthesisError};
  use core::marker::PhantomData;

  #[derive(Clone, Debug)]
  struct Sha256Circuit<E: Engine> {
    preimage: Vec<u8>,
    _p: PhantomData<E>,
  }

  impl<E: Engine> SpartanCircuit<E> for Sha256Circuit<E> {
    fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
      Ok(vec![E::Scalar::ZERO]) // Placeholder, we don't use public values in this example
    }

    fn shared<CS: ConstraintSystem<E::Scalar>>(
      &self,
      _: &mut CS,
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
      Ok(vec![]) // Placeholder, we don't use shared variables in this example
    }

    fn precommitted<CS: ConstraintSystem<E::Scalar>>(
      &self,
      _: &mut CS,
      _: &[AllocatedNum<E::Scalar>],
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
      Ok(vec![]) // Placeholder, we don't use precommitted variables in this example
    }

    fn num_challenges(&self) -> usize {
      0 // Placeholder, we don't use challenges in this example
    }

    fn synthesize<CS: ConstraintSystem<E::Scalar>>(
      &self,
      cs: &mut CS,
      _shared: &[AllocatedNum<E::Scalar>],
      _precommitted: &[AllocatedNum<E::Scalar>],
      _challenges: Option<&[E::Scalar]>, // challenges from the verifier
    ) -> Result<(), SynthesisError> {
      // we write a circuit that checks if the input is a SHA256 preimage
      let bit_values: Vec<_> = self
        .preimage
        .clone()
        .into_iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
        .map(Some)
        .collect();
      assert_eq!(bit_values.len(), self.preimage.len() * 8);

      let preimage_bits = bit_values
        .into_iter()
        .enumerate()
        .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {i}")), b))
        .map(|b| b.map(Boolean::from))
        .collect::<Result<Vec<_>, _>>()?;

      let _ = sha256(cs.namespace(|| "sha256"), &preimage_bits)?;

      let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(E::Scalar::ZERO))?;
      x.inputize(cs.namespace(|| "inputize x"))?;

      Ok(())
    }
  }

  fn generate_sha_r1cs<E: Engine>(
    num_circuits: usize,
    len: usize,
  ) -> (
    NeutronNovaProverKey<E>,
    NeutronNovaVerifierKey<E>,
    Vec<Sha256Circuit<E>>,
  )
  where
    E::PCS: FoldingEngineTrait<E>, // Ensure that the PCS supports folding
  {
    let circuit = Sha256Circuit::<E> {
      preimage: vec![0u8; len],
      _p: Default::default(),
    };

    let (pk, vk) = NeutronNovaZkSNARK::<E>::setup(&circuit, &circuit, num_circuits).unwrap();

    let circuits = (0..num_circuits)
      .map(|i| Sha256Circuit::<E> {
        preimage: vec![i as u8; len],
        _p: Default::default(),
      })
      .collect::<Vec<_>>();

    (pk, vk, circuits)
  }

  fn test_neutron_inner<E: Engine, C1: SpartanCircuit<E>, C2: SpartanCircuit<E>>(
    name: &str,
    pk: &NeutronNovaProverKey<E>,
    vk: &NeutronNovaVerifierKey<E>,
    step_circuits: &[C1],
    core_circuit: &C2,
  ) where
    E::PCS: FoldingEngineTrait<E>,
  {
    println!(
      "[bench_neutron_inner] name: {name}, num_circuits: {}",
      step_circuits.len()
    );

    let res = NeutronNovaZkSNARK::prove(pk, step_circuits, core_circuit, true);
    assert!(res.is_ok());

    let snark = res.unwrap();
    let res = snark.verify(vk, step_circuits.len());
    println!(
      "[bench_neutron_inner] name: {name}, num_circuits: {}, verify res: {:?}",
      step_circuits.len(),
      res
    );
    assert!(res.is_ok());

    let (public_values_step, _public_values_core) = res.unwrap();
    assert_eq!(public_values_step.len(), step_circuits.len());
  }

  #[test]
  fn test_neutron_sha256() {
    let _ = tracing_subscriber::fmt()
      .with_target(false)
      .with_ansi(true)
      .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
      .try_init();

    type E = T256HyraxEngine;

    for num_circuits in [2, 7, 32, 64] {
      for len in [32, 64].iter() {
        let (pk, vk, circuits) = generate_sha_r1cs::<E>(num_circuits, *len);
        test_neutron_inner(
          &format!("sha256_num_circuits={num_circuits}_len={len}"),
          &pk,
          &vk,
          &circuits,
          &circuits[0], // core circuit is the first one, for test purposes
        );
      }
    }
  }
}
