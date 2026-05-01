use bellpepper::gadgets::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  sha256::sha256,
};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::Field;
use sha2::{Digest, Sha256};
use spartan2::traits::{Engine, circuit::SpartanCircuit};

#[derive(Clone, Debug)]
pub struct Sha256Circuit<E: Engine> {
  pub preimage: Vec<u8>,
  pub _p: PhantomData<E>,
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
