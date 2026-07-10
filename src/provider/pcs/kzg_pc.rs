// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
// This file is part of the Spartan2 project.
// See the LICENSE file in the project root for full license information.
// Source repository: https://github.com/Microsoft/Spartan2

//! A Spartan2 PCS adapter for Nova's HyperKZG multilinear polynomial commitment scheme.
//!
//! HyperKZG commits to multilinear polynomials represented in evaluation form and
//! provides succinct evaluation arguments.
//!
//! This adapter is intentionally **not zero-knowledge**: it uses unblinded
//! HyperKZG commitments, exposes the evaluation scalar in the evaluation
//! argument, and only checks `comm_eval` as a consistency commitment to that
//! scalar. It is suitable for transparent/benchmarking paths, or for protocols
//! that add their own ZK layer outside the PCS.
//!
//! Note: This is a modified version of kzg_pc.rs from the original repository.

use crate::{
  errors::SpartanError,
  polys::eq::EqPolynomial,
  provider::{
    Bn254KzgEngine,
    keccak::Keccak256Transcript,
    traits::{DlogGroup, DlogGroupExt},
  },
  traits::{
    Engine,
    pcs::{CommitmentTrait, FoldingEngineTrait, PCSEngineTrait},
    transcript::{TranscriptEngineTrait as SpartanTranscriptEngineTrait, TranscriptReprTrait},
  },
};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use nova_snark::{
  errors::NovaError,
  provider::{
    hyperkzg,
    poseidon::{PoseidonRO, PoseidonROCircuit},
  },
  traits::{
    Engine as NovaEngine, TranscriptEngineTrait as NovaTranscriptEngineTrait,
    TranscriptReprTrait as NovaTranscriptReprTrait,
    commitment::CommitmentEngineTrait as NovaCommitmentEngineTrait,
    evaluation::EvaluationEngineTrait as NovaEvaluationEngineTrait,
  },
};
use serde::{Deserialize, Serialize};
use std::{
  env,
  fs::File,
  io::{BufReader, Read, Seek},
  path::Path,
};

const DEFAULT_PTAU_PATH: &str = "video_data/ppot_0080_24.ptau";
const PTAU_ENV_VAR: &str = "SPARTAN2_HYPERKZG_PTAU";

/// Nova-compatible engine type that reuses Spartan2's BN254 types and transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NovaCompatBn254KzgEngine;

impl NovaEngine for NovaCompatBn254KzgEngine {
  type Base = <Bn254KzgEngine as Engine>::Base;
  type Scalar = <Bn254KzgEngine as Engine>::Scalar;
  type GE = <Bn254KzgEngine as Engine>::GE;
  type RO = PoseidonRO<Self::Base>;
  type ROCircuit = PoseidonROCircuit<Self::Base>;
  type RO2 = PoseidonRO<Self::Scalar>;
  type RO2Circuit = PoseidonROCircuit<Self::Scalar>;
  type TE = Keccak256Transcript<Bn254KzgEngine>;
  type CE = hyperkzg::CommitmentEngine<Self>;
}

struct NovaTranscriptBytes(Vec<u8>);

impl TranscriptReprTrait<<Bn254KzgEngine as Engine>::GE> for NovaTranscriptBytes {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    self.0.clone()
  }
}

impl NovaTranscriptEngineTrait<NovaCompatBn254KzgEngine> for Keccak256Transcript<Bn254KzgEngine> {
  fn new(label: &'static [u8]) -> Self {
    <Self as SpartanTranscriptEngineTrait<Bn254KzgEngine>>::new(label)
  }

  fn squeeze(
    &mut self,
    label: &'static [u8],
  ) -> Result<<NovaCompatBn254KzgEngine as NovaEngine>::Scalar, NovaError> {
    <Self as SpartanTranscriptEngineTrait<Bn254KzgEngine>>::squeeze(self, label)
      .map_err(|_| NovaError::InternalTranscriptError)
  }

  fn squeeze_bits(
    &mut self,
    label: &'static [u8],
    num_bits: usize,
    start_with_one: bool,
  ) -> Result<<NovaCompatBn254KzgEngine as NovaEngine>::Scalar, NovaError> {
    let challenge = <Self as SpartanTranscriptEngineTrait<Bn254KzgEngine>>::squeeze(self, label)
      .map_err(|_| NovaError::InternalTranscriptError)?;
    let mut repr = challenge.to_repr();
    let bytes = repr.as_mut();
    for bit in num_bits..bytes.len() * 8 {
      bytes[bit / 8] &= !(1u8 << (bit % 8));
    }
    if start_with_one && num_bits > 0 {
      let bit = num_bits - 1;
      bytes[bit / 8] |= 1u8 << (bit % 8);
    }
    Option::from(<NovaCompatBn254KzgEngine as NovaEngine>::Scalar::from_repr(
      repr,
    ))
    .ok_or(NovaError::InternalTranscriptError)
  }

  fn absorb<T: NovaTranscriptReprTrait<<NovaCompatBn254KzgEngine as NovaEngine>::GE>>(
    &mut self,
    label: &'static [u8],
    o: &T,
  ) {
    let bytes = NovaTranscriptBytes(o.to_transcript_bytes());
    <Self as SpartanTranscriptEngineTrait<Bn254KzgEngine>>::absorb(self, label, &bytes);
  }

  fn dom_sep(&mut self, bytes: &'static [u8]) {
    <Self as SpartanTranscriptEngineTrait<Bn254KzgEngine>>::dom_sep(self, bytes);
  }
}

type NovaCE = <NovaCompatBn254KzgEngine as NovaEngine>::CE;
type NovaCommitmentKey =
  <NovaCE as NovaCommitmentEngineTrait<NovaCompatBn254KzgEngine>>::CommitmentKey;
type NovaCommitment = <NovaCE as NovaCommitmentEngineTrait<NovaCompatBn254KzgEngine>>::Commitment;
type NovaEvaluationEngine = hyperkzg::EvaluationEngine<NovaCompatBn254KzgEngine>;
type NovaEvaluationArgument =
  <NovaEvaluationEngine as NovaEvaluationEngineTrait<NovaCompatBn254KzgEngine>>::EvaluationArgument;
type NovaProverKey =
  <NovaEvaluationEngine as NovaEvaluationEngineTrait<NovaCompatBn254KzgEngine>>::ProverKey;
type NovaVerifierKey =
  <NovaEvaluationEngine as NovaEvaluationEngineTrait<NovaCompatBn254KzgEngine>>::VerifierKey;

/// A HyperKZG commitment key and evaluation prover key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KzgCommitmentKey {
  ck: NovaCommitmentKey,
  pk: NovaProverKey,
}

impl KzgCommitmentKey {
  /// Loads a HyperKZG key from a Powers-of-Tau file.
  pub fn from_ptau_reader(
    reader: &mut (impl Read + Seek),
    label: &'static [u8],
    n: usize,
  ) -> Result<(Self, KzgVerifierKey), SpartanError> {
    let ck = NovaCE::load_setup(reader, label, n).map_err(map_debug_err)?;
    Self::from_nova_ck(ck)
  }

  /// Loads a HyperKZG key from a Powers-of-Tau file path.
  pub fn from_ptau_file(
    path: impl AsRef<Path>,
    label: &'static [u8],
    n: usize,
  ) -> Result<(Self, KzgVerifierKey), SpartanError> {
    let file = File::open(path).map_err(|err| SpartanError::InternalError {
      reason: format!("failed to open ptau file: {err}"),
    })?;
    let mut reader = BufReader::new(file);
    Self::from_ptau_reader(&mut reader, label, n)
  }

  fn from_nova_ck(ck: NovaCommitmentKey) -> Result<(Self, KzgVerifierKey), SpartanError> {
    let capacity = ck.ck().len();
    let (pk, vk) = NovaEvaluationEngine::setup(&ck).map_err(map_debug_err)?;
    Ok((
      Self { ck: ck.clone(), pk },
      KzgVerifierKey { vk, ck, capacity },
    ))
  }

  /// Returns the number of G1 powers in this commitment key.
  pub fn len(&self) -> usize {
    self.ck.ck().len()
  }

  /// Returns `true` when the commitment key contains no powers.
  pub fn is_empty(&self) -> bool {
    self.ck.ck().is_empty()
  }
}

/// A HyperKZG verifier key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KzgVerifierKey {
  vk: NovaVerifierKey,
  ck: NovaCommitmentKey,
  capacity: usize,
}

impl KzgVerifierKey {
  /// Returns the number of G1 powers supported by the corresponding commitment key.
  pub fn len(&self) -> usize {
    self.capacity
  }

  /// Returns `true` when the verifier key supports no commitment powers.
  pub fn is_empty(&self) -> bool {
    self.capacity == 0
  }
}

/// A HyperKZG commitment to a multilinear polynomial in evaluation form.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct KzgCommitment {
  comm: NovaCommitment,
  shifted_comm: Option<NovaCommitment>,
  offset: usize,
  len: usize,
}

impl KzgCommitment {
  /// Returns the underlying BN254 group element.
  pub fn into_inner(self) -> <Bn254KzgEngine as Engine>::GE {
    self.comm.into_inner()
  }

  /// Returns the number of evaluations committed by this commitment.
  pub fn len(&self) -> usize {
    self.len
  }

  /// Returns `true` when this commitment is to an empty vector.
  pub fn is_empty(&self) -> bool {
    self.len == 0
  }
}

impl PartialEq for KzgCommitment {
  fn eq(&self, other: &Self) -> bool {
    self.comm == other.comm && self.len == other.len
  }
}

impl Eq for KzgCommitment {}

/// A HyperKZG evaluation argument plus the non-hiding claimed evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KzgEvaluationArgument {
  eval: <Bn254KzgEngine as Engine>::Scalar,
  arg: NovaEvaluationArgument,
}

impl KzgEvaluationArgument {
  /// Returns the scalar evaluation claimed by this argument.
  pub fn eval(&self) -> <Bn254KzgEngine as Engine>::Scalar {
    self.eval
  }
}

/// Spartan2 adapter for Nova HyperKZG over BN254.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KzgPCS<E: Engine> {
  _p: PhantomData<E>,
}

impl KzgPCS<Bn254KzgEngine> {
  /// Loads a HyperKZG setup from a Powers-of-Tau file.
  pub fn setup_from_ptau_file(
    path: impl AsRef<Path>,
    label: &'static [u8],
    n: usize,
  ) -> Result<(KzgCommitmentKey, KzgVerifierKey), SpartanError> {
    KzgCommitmentKey::from_ptau_file(path, label, n)
  }

  /// Loads a HyperKZG setup from a reader.
  pub fn setup_from_ptau_reader(
    reader: &mut (impl Read + Seek),
    label: &'static [u8],
    n: usize,
  ) -> Result<(KzgCommitmentKey, KzgVerifierKey), SpartanError> {
    KzgCommitmentKey::from_ptau_reader(reader, label, n)
  }

  fn compute_eval(
    poly: &[<Bn254KzgEngine as Engine>::Scalar],
    point: &[<Bn254KzgEngine as Engine>::Scalar],
  ) -> Result<<Bn254KzgEngine as Engine>::Scalar, SpartanError> {
    let expected =
      1usize
        .checked_shl(point.len() as u32)
        .ok_or_else(|| SpartanError::InvalidInputLength {
          reason: "HyperKZG point length is too large".to_string(),
        })?;
    if poly.len() != expected {
      return Err(SpartanError::InvalidInputLength {
        reason: format!(
          "HyperKZG prove expects 2^{} = {} evaluations, got {}",
          point.len(),
          expected,
          poly.len()
        ),
      });
    }

    Ok(
      EqPolynomial::evals_from_points(point)
        .iter()
        .zip(poly.iter())
        .map(|(eq, z)| *eq * *z)
        .sum(),
    )
  }

  fn commit_eval(ck: &KzgCommitmentKey, eval: <Bn254KzgEngine as Engine>::Scalar) -> KzgCommitment {
    let comm = NovaCE::commit(&ck.ck, &[eval], &<Bn254KzgEngine as Engine>::Scalar::ZERO);
    KzgCommitment {
      comm,
      shifted_comm: Some(comm),
      offset: 0,
      len: 1,
    }
  }

  fn zero_commitment(offset: usize, len: usize) -> KzgCommitment {
    let comm = NovaCommitment::new(<Bn254KzgEngine as Engine>::GE::zero());
    KzgCommitment {
      comm,
      shifted_comm: Some(comm),
      offset,
      len,
    }
  }
}

impl PCSEngineTrait<Bn254KzgEngine> for KzgPCS<Bn254KzgEngine> {
  type CommitmentKey = KzgCommitmentKey;
  type VerifierKey = KzgVerifierKey;
  type Commitment = KzgCommitment;
  // HyperKZG is used here in transparent mode. The Spartan2 PCS trait requires a
  // blind type, so this adapter uses `()` and commits with zero randomness.
  type Blind = ();
  type EvaluationArgument = KzgEvaluationArgument;

  fn setup(
    label: &'static [u8],
    n: usize,
    _width: usize,
  ) -> (Self::CommitmentKey, Self::VerifierKey) {
    let ptau_path = env::var(PTAU_ENV_VAR).unwrap_or_else(|_| DEFAULT_PTAU_PATH.to_string());
    KzgCommitmentKey::from_ptau_file(&ptau_path, label, n).unwrap_or_else(|err| {
      panic!(
        "failed to load Nova HyperKZG setup from {ptau_path:?} ({err:?}). \
         Set {PTAU_ENV_VAR} to a compatible Powers-of-Tau file, or use \
         KzgPCS::<Bn254KzgEngine>::setup_from_ptau_file/setup_from_ptau_reader directly."
      )
    })
  }

  fn blind(_ck: &Self::CommitmentKey, _n: usize) -> Self::Blind {
    // Dummy blind: commitments and openings produced by this adapter are not
    // hiding. Do not use this PCS as the sole source of witness zero-knowledge.
  }

  fn commit(
    ck: &Self::CommitmentKey,
    v: &[<Bn254KzgEngine as Engine>::Scalar],
    r: &Self::Blind,
    is_small: bool,
  ) -> Result<Self::Commitment, SpartanError> {
    Self::commit_with_offset(ck, v, 0, r, is_small)
  }

  fn commit_with_offset(
    ck: &Self::CommitmentKey,
    v: &[<Bn254KzgEngine as Engine>::Scalar],
    offset: usize,
    _r: &Self::Blind,
    _is_small: bool,
  ) -> Result<Self::Commitment, SpartanError> {
    let end = offset
      .checked_add(v.len())
      .ok_or_else(|| SpartanError::InvalidInputLength {
        reason: "HyperKZG commit_with_offset: offset + length overflowed".to_string(),
      })?;
    if end > ck.ck.ck().len() {
      return Err(SpartanError::InvalidVectorSize {
        actual: end,
        max: ck.ck.ck().len(),
      });
    }
    if v.is_empty() {
      return Ok(Self::zero_commitment(offset, 0));
    }

    let comm = NovaCE::commit(&ck.ck, v, &<Bn254KzgEngine as Engine>::Scalar::ZERO);
    let shifted_comm = if offset == 0 {
      comm
    } else {
      NovaCommitment::new(<Bn254KzgEngine as Engine>::GE::vartime_multiscalar_mul(
        v,
        &ck.ck.ck()[offset..end],
        false,
      )?)
    };
    Ok(KzgCommitment {
      comm,
      shifted_comm: Some(shifted_comm),
      offset,
      len: v.len(),
    })
  }

  fn commit_zeros(
    ck: &Self::CommitmentKey,
    n: usize,
    r: &Self::Blind,
  ) -> Result<Self::Commitment, SpartanError> {
    let zeros = vec![<Bn254KzgEngine as Engine>::Scalar::ZERO; n];
    Self::commit(ck, &zeros, r, true)
  }

  fn commit_zeros_with_offset(
    ck: &Self::CommitmentKey,
    n: usize,
    offset: usize,
    _r: &Self::Blind,
  ) -> Result<Self::Commitment, SpartanError> {
    let end = offset
      .checked_add(n)
      .ok_or_else(|| SpartanError::InvalidInputLength {
        reason: "HyperKZG commit_zeros_with_offset: offset + length overflowed".to_string(),
      })?;
    if end > ck.ck.ck().len() {
      return Err(SpartanError::InvalidVectorSize {
        actual: end,
        max: ck.ck.ck().len(),
      });
    }
    Ok(Self::zero_commitment(offset, n))
  }

  fn check_commitment(
    comm: &Self::Commitment,
    n: usize,
    _width: usize,
  ) -> Result<(), SpartanError> {
    if comm.len != n {
      return Err(SpartanError::InvalidCommitmentLength {
        reason: format!(
          "HyperKZG commitment length mismatch: actual {}, expected {}",
          comm.len, n
        ),
      });
    }
    Ok(())
  }

  fn rerandomize_commitment(
    _ck: &Self::CommitmentKey,
    comm: &Self::Commitment,
    _r_old: &Self::Blind,
    _r_new: &Self::Blind,
  ) -> Result<Self::Commitment, SpartanError> {
    Ok(*comm)
  }

  fn combine_commitments(comms: &[Self::Commitment]) -> Result<Self::Commitment, SpartanError> {
    if comms.is_empty() {
      return Err(SpartanError::InvalidInputLength {
        reason: "HyperKZG combine_commitments: no commitments provided".to_string(),
      });
    }

    let mut expected_offset = 0usize;
    let mut acc = <Bn254KzgEngine as Engine>::GE::zero();
    for comm in comms {
      if comm.offset != expected_offset {
        return Err(SpartanError::InvalidCommitmentLength {
          reason: format!(
            "HyperKZG combine_commitments: expected next offset {}, got {}",
            expected_offset, comm.offset
          ),
        });
      }
      let shifted_comm = comm
        .shifted_comm
        .ok_or_else(|| SpartanError::InternalError {
          reason: "HyperKZG combine_commitments: shifted commitment is unavailable".to_string(),
        })?;
      acc += shifted_comm.into_inner();
      expected_offset += comm.len;
    }
    let comm = NovaCommitment::new(acc);
    Ok(KzgCommitment {
      comm,
      shifted_comm: Some(comm),
      offset: 0,
      len: expected_offset,
    })
  }

  fn combine_blinds(blinds: &[Self::Blind]) -> Result<Self::Blind, SpartanError> {
    if blinds.is_empty() {
      return Err(SpartanError::InvalidInputLength {
        reason: "HyperKZG combine_blinds: no blinds provided".to_string(),
      });
    }
    Ok(())
  }

  fn prove(
    ck: &Self::CommitmentKey,
    _ck_eval: &Self::CommitmentKey,
    transcript: &mut <Bn254KzgEngine as Engine>::TE,
    comm: &Self::Commitment,
    poly: &[<Bn254KzgEngine as Engine>::Scalar],
    _blind: &Self::Blind,
    point: &[<Bn254KzgEngine as Engine>::Scalar],
    _comm_eval: &Self::Commitment,
    _blind_eval: &Self::Blind,
  ) -> Result<Self::EvaluationArgument, SpartanError> {
    let eval = Self::compute_eval(poly, point)?;
    let arg =
      NovaEvaluationEngine::prove(&ck.ck, &ck.pk, transcript, &comm.comm, poly, point, &eval)
        .map_err(map_debug_err)?;
    Ok(KzgEvaluationArgument { eval, arg })
  }

  fn verify(
    vk: &Self::VerifierKey,
    ck_eval: &Self::CommitmentKey,
    transcript: &mut <Bn254KzgEngine as Engine>::TE,
    comm: &Self::Commitment,
    point: &[<Bn254KzgEngine as Engine>::Scalar],
    comm_eval: &Self::Commitment,
    arg: &Self::EvaluationArgument,
  ) -> Result<(), SpartanError> {
    if comm_eval.is_empty() {
      return Err(SpartanError::ProofVerifyError {
        reason: "HyperKZG evaluation commitment is empty".to_string(),
      });
    }
    let expected_eval_comm = Self::commit_eval(ck_eval, arg.eval);
    if comm_eval.comm != expected_eval_comm.comm {
      return Err(SpartanError::ProofVerifyError {
        reason: "HyperKZG evaluation commitment does not match argument evaluation".to_string(),
      });
    }
    NovaEvaluationEngine::verify(&vk.vk, transcript, &comm.comm, point, &arg.eval, &arg.arg)
      .map_err(map_debug_err)
  }

  fn prove_direct(
    _ck: &Self::CommitmentKey,
    poly: &[<Bn254KzgEngine as Engine>::Scalar],
    _blind: &Self::Blind,
    point: &[<Bn254KzgEngine as Engine>::Scalar],
  ) -> Result<
    (
      Vec<<Bn254KzgEngine as Engine>::Scalar>,
      <Bn254KzgEngine as Engine>::Scalar,
    ),
    SpartanError,
  > {
    let expected =
      1usize
        .checked_shl(point.len() as u32)
        .ok_or_else(|| SpartanError::InvalidInputLength {
          reason: "HyperKZG direct opening point length is too large".to_string(),
        })?;
    if poly.len() > expected {
      return Err(SpartanError::InvalidInputLength {
        reason: format!(
          "HyperKZG direct opening expects at most {} evaluations, got {}",
          expected,
          poly.len()
        ),
      });
    }

    let mut v = poly.to_vec();
    v.resize(expected, <Bn254KzgEngine as Engine>::Scalar::ZERO);
    Ok((v, <Bn254KzgEngine as Engine>::Scalar::ZERO))
  }

  fn verify_direct(
    vk: &Self::VerifierKey,
    comm: &Self::Commitment,
    v: &[<Bn254KzgEngine as Engine>::Scalar],
    combined_blind: &<Bn254KzgEngine as Engine>::Scalar,
    point: &[<Bn254KzgEngine as Engine>::Scalar],
  ) -> Result<<Bn254KzgEngine as Engine>::Scalar, SpartanError> {
    if *combined_blind != <Bn254KzgEngine as Engine>::Scalar::ZERO {
      return Err(SpartanError::ProofVerifyError {
        reason: "HyperKZG direct opening received a non-zero blind".to_string(),
      });
    }

    let expected =
      1usize
        .checked_shl(point.len() as u32)
        .ok_or_else(|| SpartanError::InvalidInputLength {
          reason: "HyperKZG direct opening point length is too large".to_string(),
        })?;
    if v.len() != expected {
      return Err(SpartanError::ProofVerifyError {
        reason: format!(
          "HyperKZG direct opening vector length mismatch: actual {}, expected {}",
          v.len(),
          expected
        ),
      });
    }
    if comm.len > expected {
      return Err(SpartanError::ProofVerifyError {
        reason: format!(
          "HyperKZG direct opening commitment length {} exceeds point domain {}",
          comm.len, expected
        ),
      });
    }
    if expected > vk.ck.ck().len() {
      return Err(SpartanError::InvalidVectorSize {
        actual: expected,
        max: vk.ck.ck().len(),
      });
    }

    let expected_comm = NovaCE::commit(&vk.ck, v, &<Bn254KzgEngine as Engine>::Scalar::ZERO);
    if comm.comm != expected_comm {
      return Err(SpartanError::ProofVerifyError {
        reason: "HyperKZG direct opening commitment mismatch".to_string(),
      });
    }

    Self::compute_eval(v, point)
  }
}

impl FoldingEngineTrait<Bn254KzgEngine> for KzgPCS<Bn254KzgEngine> {
  fn fold_commitments(
    comms: &[Self::Commitment],
    weights: &[<Bn254KzgEngine as Engine>::Scalar],
  ) -> Result<Self::Commitment, SpartanError> {
    if comms.is_empty() || comms.len() != weights.len() {
      return Err(SpartanError::InvalidInputLength {
        reason:
          "HyperKZG fold_commitments: commitments and weights must be non-empty and same length"
            .to_string(),
      });
    }
    let len = comms[0].len;
    if !comms.iter().all(|comm| comm.len == len) {
      return Err(SpartanError::InvalidCommitmentLength {
        reason: "HyperKZG fold_commitments: all commitments must have the same length".to_string(),
      });
    }

    let acc = comms.iter().zip(weights.iter()).fold(
      <Bn254KzgEngine as Engine>::GE::zero(),
      |acc, (comm, weight)| acc + comm.comm.into_inner() * *weight,
    );
    let common_offset = comms[0].offset;
    let shifted_comm = if comms
      .iter()
      .all(|comm| comm.offset == common_offset && comm.shifted_comm.is_some())
    {
      let shifted_acc = comms.iter().zip(weights.iter()).fold(
        <Bn254KzgEngine as Engine>::GE::zero(),
        |acc, (comm, weight)| acc + comm.shifted_comm.unwrap().into_inner() * *weight,
      );
      Some(NovaCommitment::new(shifted_acc))
    } else {
      None
    };
    Ok(KzgCommitment {
      comm: NovaCommitment::new(acc),
      shifted_comm,
      offset: common_offset,
      len,
    })
  }

  fn fold_blinds(
    blinds: &[Self::Blind],
    weights: &[<Bn254KzgEngine as Engine>::Scalar],
  ) -> Result<Self::Blind, SpartanError> {
    if blinds.is_empty() || blinds.len() != weights.len() {
      return Err(SpartanError::InvalidInputLength {
        reason: "HyperKZG fold_blinds: blinds and weights must be non-empty and same length"
          .to_string(),
      });
    }
    Ok(())
  }
}

impl TranscriptReprTrait<<Bn254KzgEngine as Engine>::GE> for KzgCommitment {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    let (x, y, is_infinity) = self.into_inner().to_coordinates();
    let mut bytes = b"hyperkzg_commitment".to_vec();
    bytes.extend_from_slice(&(self.len as u64).to_le_bytes());
    bytes
      .extend(<_ as TranscriptReprTrait<<Bn254KzgEngine as Engine>::GE>>::to_transcript_bytes(&x));
    bytes
      .extend(<_ as TranscriptReprTrait<<Bn254KzgEngine as Engine>::GE>>::to_transcript_bytes(&y));
    bytes.push(u8::from(is_infinity));
    bytes
  }
}

impl CommitmentTrait<Bn254KzgEngine> for KzgCommitment {}

fn map_debug_err(err: impl core::fmt::Debug) -> SpartanError {
  SpartanError::InternalError {
    reason: format!("Nova HyperKZG error: {err:?}"),
  }
}
