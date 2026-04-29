// Standalone example: fold many SHA-256 circuits into one proof using NeutronNova.
//
// Run with:
//   RUST_LOG=info cargo run --example neutron_nova_sha256_example --release
//
// Adjust NUM_CIRCUITS and PREIMAGE_LEN to experiment with different batch sizes / input lengths.

use bellpepper::gadgets::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  sha256::sha256,
};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::Field;
use sha2::{Digest, Sha256};
use spartan2::{
  neutronnova_zk::NeutronNovaZkSNARK,
  provider::T256HyraxEngine,
  traits::{Engine, circuit::SpartanCircuit},
};
use std::time::Instant;
use tracing::{info, info_span};

// Constants controlling the number of circuits to fold and the SHA-256
// preimage length. This isn't a perfect example, since SHA-256 uses mostly
// 0/1 wire values with low fan-in gates and is faster per-gate than handwritten
// circuits.
const NUM_CIRCUITS: usize = 32;
const PREIMAGE_LEN: usize = 32 * 32;

#[derive(Clone, Debug)]
struct Sha256Circuit<E: Engine> {
  preimage: Vec<u8>,
  _p: PhantomData<E>,
}

impl<E: Engine> SpartanCircuit<E> for Sha256Circuit<E> {
  fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
    let hash = Sha256::digest(&self.preimage);
    let bits = hash
      .iter()
      .flat_map(|byte| (0..8u8).map(move |i| (byte >> i) & 1u8))
      .map(|b| {
        if b == 1 {
          E::Scalar::ONE
        } else {
          E::Scalar::ZERO
        }
      })
      .collect();
    Ok(bits)
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<E::Scalar>],
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    _shared: &[AllocatedNum<E::Scalar>],
    _precommitted: &[AllocatedNum<E::Scalar>],
    _challenges: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    // Decompose preimage bytes into bits (LSB first) and allocate them.
    let preimage_bits = self
      .preimage
      .iter()
      .enumerate()
      .flat_map(|(byte_i, &byte)| {
        (0..8u8).map(move |bit_i| ((byte >> bit_i) & 1u8 == 1u8, byte_i * 8 + bit_i as usize))
      })
      .map(|(bit, idx)| {
        AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {idx}")), Some(bit))
          .map(Boolean::from)
      })
      .collect::<Result<Vec<_>, _>>()?;

    // Compute SHA-256 inside the circuit and expose the 256 output bits as public inputs.
    let hash_bits = sha256(cs.namespace(|| "sha256"), &preimage_bits)?;

    for (i, bit) in hash_bits.iter().enumerate() {
      let n = AllocatedNum::alloc(cs.namespace(|| format!("hash out {i}")), || {
        bit
          .get_value()
          .map(|b| if b { E::Scalar::ONE } else { E::Scalar::ZERO })
          .ok_or(SynthesisError::AssignmentMissing)
      })?;
      n.inputize(cs.namespace(|| format!("inputize hash out {i}")))?;
    }

    Ok(())
  }
}

fn main() {
  let _ = tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  type E = T256HyraxEngine;

  let root_span = info_span!(
    "bench",
    num_circuits = NUM_CIRCUITS,
    preimage_len = PREIMAGE_LEN
  )
  .entered();
  info!(
    num_circuits = NUM_CIRCUITS,
    preimage_len = PREIMAGE_LEN,
    "starting NeutronNova benchmark"
  );

  // Use a dummy circuit of the right shape to derive the R1CS constraints and keys.
  let shape_circuit = Sha256Circuit::<E> {
    preimage: vec![0u8; PREIMAGE_LEN],
    _p: Default::default(),
  };

  let t0 = Instant::now();
  let (pk, vk) =
    NeutronNovaZkSNARK::<E>::setup(&shape_circuit, &shape_circuit, NUM_CIRCUITS).unwrap();
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");

  // Build the actual step circuits — each gets a distinct preimage byte.
  let t0 = Instant::now();
  let step_circuits: Vec<Sha256Circuit<E>> = (0..NUM_CIRCUITS)
    .map(|i| Sha256Circuit::<E> {
      preimage: vec![i as u8; PREIMAGE_LEN],
      _p: Default::default(),
    })
    .collect();
  info!(elapsed_ms = t0.elapsed().as_millis(), "generate_witness");

  // Use the first circuit as the core circuit (it connects the folded batch).
  let core_circuit = &step_circuits[0];

  let t0 = Instant::now();
  let prep = NeutronNovaZkSNARK::<E>::prep_prove(&pk, &step_circuits, core_circuit, true).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "prep_prove");

  let t0 = Instant::now();
  let (snark, _prep) =
    NeutronNovaZkSNARK::prove(&pk, &step_circuits, core_circuit, prep, true).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "prove");

  let t0 = Instant::now();
  let result = snark.verify(&vk, NUM_CIRCUITS).unwrap();
  let verify_ms = t0.elapsed().as_millis();
  let (public_values_step, _public_values_core): (Vec<_>, Vec<_>) = result;
  info!(elapsed_ms = verify_ms, "verify");

  info!(
    num_step_circuits = public_values_step.len(),
    "verification successful"
  );
  drop(root_span);
}
