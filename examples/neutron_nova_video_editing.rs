// NeutronNova Freivalds editing. Fold a bunch of keyframe proofs together.
//
// Run with:
//   RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_video_editing --release
// The RUST_LOG is because the Spartan library has a bunch of unnecessary print statements for large
// circuits internally.

#![allow(non_snake_case)]
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use rand::{Rng, RngCore};
use spartan2::{
  neutronnova_zk::NeutronNovaZkSNARK,
  provider::T256HyraxEngine,
  traits::{Engine, circuit::SpartanCircuit},
};
use std::{marker::PhantomData, time::Instant};
use tracing::{info, info_span};

const KERNEL_SIZE: usize = 9;
const RADIUS: usize = KERNEL_SIZE / 2;
const BYTES_PER_FIELD_ELEMENT: usize = 30;
const NUM_CIRCUITS: usize = 4;
const IMAGE_DIMS: (usize, usize) = (1280, 720);

#[derive(Clone, Debug)]
struct DummyCircuit<E: Engine>(PhantomData<E>);

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

fn generate_random_vector<Scalar: PrimeField + PrimeFieldBits>(length: usize) -> Vec<Scalar> {
  let mut rng = rand::thread_rng();
  (0..length)
    .map(|_| Scalar::from_u128(rng.gen_range(0..((1u128 << 127) as u128))))
    .collect()
}

fn generate_random_image(dimensions: (usize, usize)) -> Vec<Vec<u8>> {
  let (height, width) = dimensions;
  let mut rng = rand::thread_rng();
  (0..height)
    .map(|_| (0..width).map(|_| rng.next_u32() as u8).collect())
    .collect()
}

#[derive(Clone, Debug)]
struct FreivaldsConvCircuit<Scalar: PrimeField> {
  image: Vec<Vec<u8>>,
  edited_image: Vec<Vec<u8>>,
  target_image: Vec<Vec<u8>>,
  r: Vec<Scalar>,
  s: Vec<Scalar>,
  logup_challenge: Scalar,
  polynomial_interpolation_challenge: Scalar,
  rTA: Vec<Scalar>,
  As: Vec<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> FreivaldsConvCircuit<Scalar> {
  fn new(image: Vec<Vec<u8>>) -> Self {
    let height = image.len();
    assert!(height > 0);
    let width = image[0].len();
    assert!(width > 0);

    let r = generate_random_vector(height);
    let s = generate_random_vector(width);
    let logup_challenge = generate_random_vector(1).remove(0);
    let polynomial_interpolation_challenge = generate_random_vector(1).remove(0);

    let edited_image = image.clone();
    let target_image = edited_image.clone();
    let rTA = r.clone();
    let As = s.clone();

    Self {
      image,
      edited_image,
      target_image,
      r,
      s,
      logup_challenge,
      polynomial_interpolation_challenge,
      rTA,
      As,
    }
  }
}

impl<E: Engine> SpartanCircuit<E> for FreivaldsConvCircuit<E::Scalar> {
  fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
    let height = self.image.len();
    assert!(height > 0);
    let width = self.image[0].len();
    assert!(width > 0);

    let mut public_vals = Vec::new();

    let flattened_edited_image: Vec<<E as Engine>::Scalar> = self
      .edited_image
      .clone()
      .into_iter()
      .map(|v| {
        v.into_iter()
          .map(|pixel| <E as Engine>::Scalar::from_u128(pixel as u128))
          .collect::<Vec<<E as Engine>::Scalar>>()
      })
      .flatten()
      .collect();

    public_vals.extend(flattened_edited_image);
    public_vals.extend(self.r.clone());
    public_vals.extend(self.s.clone());
    public_vals.extend(self.rTA.clone());
    public_vals.extend(self.As.clone());
    public_vals.push(self.logup_challenge);
    public_vals.push(self.polynomial_interpolation_challenge);

    Ok(public_vals)
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
    _: &[AllocatedNum<E::Scalar>],
    _: &[AllocatedNum<E::Scalar>],
    _: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    // 1. Allocate private input for the image
    let image_input_vars = self
      .image
      .clone()
      .into_iter()
      .enumerate()
      .map(|(i, row)| {
        row
          .into_iter()
          .enumerate()
          .map(|(j, val)| {
            AllocatedNum::alloc(
              cs.namespace(|| format!("Input image pixel {i},{j}")),
              || Ok(E::Scalar::from_u128(val as u128)),
            )
          })
          .collect::<Result<Vec<_>, _>>()
      })
      .collect::<Result<Vec<Vec<_>>, _>>()?;

    // 2. Allocate edited_image as private.
    let mut allocated_edited_image = Vec::new();
    for (i, row) in self.edited_image.clone().into_iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, pixel) in row.into_iter().enumerate() {
        let n = AllocatedNum::alloc(
          cs.namespace(|| format!("edited image entry {i} {j}")),
          || Ok(E::Scalar::from_u128(pixel as u128)),
        )?;
        row_vars.push(n);
      }
      allocated_edited_image.push(row_vars);
    }

    let mut allocated_target_image = Vec::new();
    for (i, row) in self.target_image.clone().into_iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, pixel) in row.into_iter().enumerate() {
        let n = AllocatedNum::alloc_input(
          cs.namespace(|| format!("target image entry {i} {j}")),
          || Ok(E::Scalar::from_u128(pixel as u128)),
        )?;
        row_vars.push(n);
      }
      allocated_target_image.push(row_vars);
    }

    let mut allocated_r = Vec::new();
    for (i, val) in self.r.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("r entry {i}")), || Ok(val))?;
      allocated_r.push(n);
    }

    let mut allocated_s = Vec::new();
    for (i, val) in self.s.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("s entry {i}")), || Ok(val))?;
      allocated_s.push(n);
    }

    let mut allocated_rTA = Vec::new();
    for (i, val) in self.rTA.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("rTA entry {i}")), || Ok(val))?;
      allocated_rTA.push(n);
    }

    let mut allocated_As = Vec::new();
    for (i, val) in self.As.clone().into_iter().enumerate() {
      let n = AllocatedNum::alloc_input(cs.namespace(|| format!("As entry {i}")), || Ok(val))?;
      allocated_As.push(n);
    }

    // 3. Compute LHS convolution (r^TA)I(As).
    let mut IAs = Vec::new();
    let mut IAs_felts = Vec::new();
    for (i, row) in image_input_vars.iter().enumerate() {
      let mut row_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
      let mut running_sum = E::Scalar::ZERO;

      for ((j, x), y) in row.iter().enumerate().zip(allocated_As.iter()) {
        running_sum = running_sum + E::Scalar::from_u128(self.image[i][j] as u128) * self.As[j];

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Row {i} IAs partial sum {j}")),
          || Ok(running_sum),
        )?;

        if j == 0 {
          cs.enforce(
            || format!("Row {i} IAs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable(),
          );
        } else {
          cs.enforce(
            || format!("Row {i} IAs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable() - row_partial_sums[j - 1].get_variable(),
          );
        }

        row_partial_sums.push(partial_sum_var);
      }

      IAs_felts.push(running_sum);
      IAs.push(row_partial_sums.pop().unwrap());
    }

    let mut lhs_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
    let mut lhs_running_sum = E::Scalar::ZERO;
    for (i, (x, y)) in IAs.iter().zip(allocated_rTA.iter()).enumerate() {
      lhs_running_sum = lhs_running_sum + self.rTA[i] * IAs_felts[i];
      let partial_sum_var =
        AllocatedNum::alloc(cs.namespace(|| format!("LHS partial sum {i}")), || {
          Ok(lhs_running_sum)
        })?;
      if i == 0 {
        cs.enforce(
          || format!("LHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("LHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable() - lhs_partial_sums[i - 1].get_variable(),
        );
      }
      lhs_partial_sums.push(partial_sum_var);
    }
    let rTAIAs = lhs_partial_sums.pop().unwrap();

    // 4. Compute RHS convolution (r^T)F(s).
    let mut Fs = Vec::new();
    let mut Fs_felts = Vec::new();
    for (i, row) in allocated_edited_image.iter().enumerate() {
      let mut row_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
      let mut running_sum = E::Scalar::ZERO;

      for ((j, x), y) in row.iter().enumerate().zip(allocated_s.iter()) {
        running_sum =
          running_sum + E::Scalar::from_u128(self.edited_image[i][j] as u128) * self.As[j];

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Row {i} Fs partial sum {j}")),
          || Ok(running_sum),
        )?;

        if j == 0 {
          cs.enforce(
            || format!("Row {i} Fs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable(),
          );
        } else {
          cs.enforce(
            || format!("Row {i} Fs partial sum constraint {j}"),
            |lc| lc + x.get_variable(),
            |lc| lc + y.get_variable(),
            |lc| lc + partial_sum_var.get_variable() - row_partial_sums[j - 1].get_variable(),
          );
        }

        row_partial_sums.push(partial_sum_var);
      }

      Fs_felts.push(running_sum);
      Fs.push(row_partial_sums.pop().unwrap());
    }

    let mut rhs_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
    let mut rhs_running_sum = E::Scalar::ZERO;
    for (i, (x, y)) in Fs.iter().zip(allocated_r.iter()).enumerate() {
      rhs_running_sum = rhs_running_sum + Fs_felts[i] * self.r[i];
      let partial_sum_var =
        AllocatedNum::alloc(cs.namespace(|| format!("RHS partial sum {i}")), || {
          Ok(rhs_running_sum)
        })?;
      if i == 0 {
        cs.enforce(
          || format!("RHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("RHS partial sum constraint {i}"),
          |lc| lc + x.get_variable(),
          |lc| lc + y.get_variable(),
          |lc| lc + partial_sum_var.get_variable() - rhs_partial_sums[i - 1].get_variable(),
        );
      }
      rhs_partial_sums.push(partial_sum_var);
    }
    let rTFs = rhs_partial_sums.pop().unwrap();

    // 5. Enforce equality among the two final felts from Freivalds.
    cs.enforce(
      || "Final Freivalds validity check",
      |lc| lc + CS::one(),
      |lc| lc + rTFs.get_variable(),
      |lc| lc + rTAIAs.get_variable(),
    );

    // 6. Various range checks needed throughout circuit via LogUp.
    let mut logup_multiplicities: Vec<u32> = vec![0u32; 256];
    let allocated_logup_challenge =
      AllocatedNum::alloc_input(cs.namespace(|| "logup_challenge"), || {
        Ok(self.logup_challenge)
      })?;

    let mut logup_prev: Option<AllocatedNum<E::Scalar>> = None;
    let mut logup_running_sum = E::Scalar::ZERO;
    for rep in 0..6 {
      for (i, row) in allocated_target_image.iter().enumerate() {
        for (j, target_pixel) in row.iter().enumerate() {
          let pixel_val = self.target_image[i][j];
          logup_multiplicities[pixel_val as usize] += 1;
          let denom_val = self.logup_challenge + E::Scalar::from_u128(pixel_val as u128);
          logup_running_sum = logup_running_sum + denom_val.invert().unwrap_or(E::Scalar::ZERO);

          let partial_sum_var = AllocatedNum::alloc(
            cs.namespace(|| format!("LogUp partial sum {rep} {i} {j}")),
            || Ok(logup_running_sum),
          )?;

          if let Some(prev) = &logup_prev {
            cs.enforce(
              || format!("LogUp partial sum constraint {rep} {i} {j}"),
              |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
              |lc| lc + allocated_logup_challenge.get_variable() + target_pixel.get_variable(),
              |lc| lc + CS::one(),
            );
          } else {
            cs.enforce(
              || format!("LogUp partial sum constraint {rep} {i} {j}"),
              |lc| lc + partial_sum_var.get_variable(),
              |lc| lc + allocated_logup_challenge.get_variable() + target_pixel.get_variable(),
              |lc| lc + CS::one(),
            );
          }

          logup_prev = Some(partial_sum_var);
        }
      }
    }
    let lhs_logup_sum = logup_prev.unwrap();

    let mut rhs_logup_prev: Option<AllocatedNum<E::Scalar>> = None;
    let mut rhs_logup_running_sum = E::Scalar::ZERO;
    for b in 0u128..256 {
      let mult = logup_multiplicities[b as usize] as u128;
      let denom_val = self.logup_challenge + E::Scalar::from_u128(b);
      rhs_logup_running_sum = rhs_logup_running_sum
        + denom_val.invert().unwrap_or(E::Scalar::ZERO) * E::Scalar::from_u128(mult);

      let mult_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS LogUp multiplicity {b}")),
        || Ok(E::Scalar::from_u128(mult)),
      )?;

      let partial_sum_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS LogUp partial sum {b}")),
        || Ok(rhs_logup_running_sum),
      )?;

      if let Some(prev) = &rhs_logup_prev {
        cs.enforce(
          || format!("RHS LogUp partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
          |lc| lc + allocated_logup_challenge.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("RHS LogUp partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable(),
          |lc| lc + allocated_logup_challenge.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      }

      rhs_logup_prev = Some(partial_sum_var);
    }
    let rhs_logup_sum = rhs_logup_prev.unwrap();

    cs.enforce(
      || "LogUp validity check",
      |lc| lc + CS::one(),
      |lc| lc + lhs_logup_sum.get_variable(),
      |lc| lc + rhs_logup_sum.get_variable(),
    );

    // 7. Do polynomial interpolation verification.
    let allocated_polynomial_interpolation_challenge = AllocatedNum::alloc_input(
      cs.namespace(|| "polynomial_interpolation_challenge"),
      || Ok(self.polynomial_interpolation_challenge),
    )?;

    // Pack image bytes into field elements, simulating some sort of PCS sig verification.
    let flat_image_vars: Vec<&AllocatedNum<E::Scalar>> =
      image_input_vars.iter().flatten().collect();
    let flat_image_vals: Vec<u8> = self.image.iter().flatten().copied().collect();

    let mut packed_lcs: Vec<LinearCombination<E::Scalar>> = Vec::new();
    let mut packed_scalars: Vec<E::Scalar> = Vec::new();

    for (chunk_vars, chunk_vals) in flat_image_vars
      .chunks(BYTES_PER_FIELD_ELEMENT)
      .zip(flat_image_vals.chunks(BYTES_PER_FIELD_ELEMENT))
    {
      let mut lc = LinearCombination::zero();
      let mut scalar = E::Scalar::ZERO;
      let mut coeff = E::Scalar::ONE;
      for (var, &val) in chunk_vars.iter().zip(chunk_vals.iter()) {
        lc = lc + (coeff, var.get_variable());
        scalar = scalar + coeff * E::Scalar::from_u128(val as u128);
        coeff = coeff * E::Scalar::from_u128(1u128 << 8);
      }
      packed_lcs.push(lc);
      packed_scalars.push(scalar);
    }

    // Evaluate packed_lcs as a polynomial at polynomial_interpolation_challenge using Horner's rule:
    let mut poly_eval_prev: Option<AllocatedNum<E::Scalar>> = None;
    let mut poly_eval_scalar = E::Scalar::ZERO;

    for (k, (lc, scalar)) in packed_lcs.iter().zip(packed_scalars.iter()).enumerate() {
      if let Some(prev) = &poly_eval_prev {
        poly_eval_scalar = poly_eval_scalar * self.polynomial_interpolation_challenge + scalar;

        let eval_var = AllocatedNum::alloc(cs.namespace(|| format!("poly eval {k}")), || {
          Ok(poly_eval_scalar)
        })?;

        cs.enforce(
          || format!("poly eval constraint {k}"),
          |lc_a| lc_a + prev.get_variable(),
          |lc_b| lc_b + allocated_polynomial_interpolation_challenge.get_variable(),
          |lc_c| lc_c + eval_var.get_variable() - lc,
        );

        poly_eval_prev = Some(eval_var);
      } else {
        poly_eval_scalar = *scalar;

        let eval_var = AllocatedNum::alloc(cs.namespace(|| format!("poly eval {k}")), || {
          Ok(poly_eval_scalar)
        })?;

        cs.enforce(
          || format!("poly eval constraint {k}"),
          |lc_a| lc_a + eval_var.get_variable(),
          |lc_b| lc_b + CS::one(),
          |lc_c| lc_c + lc,
        );

        poly_eval_prev = Some(eval_var);
      }
    }
    let _poly_eval = poly_eval_prev.unwrap();

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
    image_height = IMAGE_DIMS.0,
    image_width = IMAGE_DIMS.1,
  )
  .entered();
  info!(
    num_circuits = NUM_CIRCUITS,
    image_height = IMAGE_DIMS.0,
    image_width = IMAGE_DIMS.1,
    "starting NeutronNova video editing benchmark"
  );

  // Use a dummy circuit of the right shape to derive the R1CS constraints and keys.
  let shape_circuit =
    FreivaldsConvCircuit::<<E as Engine>::Scalar>::new(generate_random_image(IMAGE_DIMS));

  let t0 = Instant::now();
  let (pk, vk) =
    NeutronNovaZkSNARK::<E>::setup(&shape_circuit, &DummyCircuit::<E>::default(), NUM_CIRCUITS)
      .unwrap();
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");

  // Build the step circuits — each represents one video frame.
  let t0 = Instant::now();
  let step_circuits: Vec<FreivaldsConvCircuit<<E as Engine>::Scalar>> = (0..NUM_CIRCUITS)
    .map(|_| FreivaldsConvCircuit::<<E as Engine>::Scalar>::new(generate_random_image(IMAGE_DIMS)))
    .collect();
  info!(elapsed_ms = t0.elapsed().as_millis(), "generate_witness");

  let core_circuit = DummyCircuit::<E>::default();

  let t0 = Instant::now();
  let prep =
    NeutronNovaZkSNARK::<E>::prep_prove(&pk, &step_circuits, &core_circuit, false).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "prep_prove");

  let t0 = Instant::now();
  let (snark, _prep) =
    NeutronNovaZkSNARK::prove(&pk, &step_circuits, &core_circuit, prep, false).unwrap();
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
