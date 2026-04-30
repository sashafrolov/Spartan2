use bellpepper_core::num::AllocatedNum;
use spartan2::traits::{Engine, circuit::SpartanCircuit};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct DummyCircuit<E: Engine>(PhantomData<E>);

impl<E: Engine> Default for DummyCircuit<E> {
  fn default() -> Self {
    Self(PhantomData)
  }
}

impl<E: Engine> SpartanCircuit<E> for DummyCircuit<E> {
  fn public_values(&self) -> Result<Vec<E::Scalar>, bellpepper_core::SynthesisError> {
    Ok(vec![])
  }

  fn shared<CS: bellpepper_core::ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, bellpepper_core::SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: bellpepper_core::ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<E::Scalar>],
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, bellpepper_core::SynthesisError> {
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: bellpepper_core::ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<E::Scalar>],
    _: &[AllocatedNum<E::Scalar>],
    _: Option<&[E::Scalar]>,
  ) -> Result<(), bellpepper_core::SynthesisError> {
    Ok(())
  }
}
