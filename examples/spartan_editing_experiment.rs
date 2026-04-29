//! Generic circuit for verifying the performance of implementing convolution-
//! type transforms using Freivald's algorithm.
//!
//! Run with: `RUST_LOG=info cargo run --release --example spartan_editing_experiment`
#![allow(non_snake_case)]
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use itertools::Itertools;
use rand::{Rng, RngCore};
use spartan2::{
  provider::T256HyraxEngine,
  spartan::SpartanSNARK,
  traits::{Engine, circuit::SpartanCircuit, snark::R1CSSNARKTrait},
};
use std::{marker::PhantomData, time::Instant};
use tracing::{info, info_span};
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;

const KERNEL_SIZE: usize = 9;
const RADIUS: usize = KERNEL_SIZE / 2;
const LAYER_ONE_CHUNK_SIZE: usize = 100;

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
  // target_image: Vec<Vec<u8>>,
  r: Vec<Scalar>,
  s: Vec<Scalar>,
  // logup_challenge: Scalar,
  rTA: Vec<Scalar>,
  As: Vec<Scalar>,
  _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> FreivaldsConvCircuit<Scalar> {
  // This circuit verifies the convolution: A_{left}IA_{right} = J.
  // It does so by verifying that r^TA_{left}IA_{right}s = r^TJs.
  fn new(image: Vec<Vec<u8>>) -> Self {
    let height = image.len();
    assert!(height > 0);
    let width = image[0].len();
    assert!(width > 0);

    let r = generate_random_vector(height);
    let s = generate_random_vector(width);
    // let logup_challenge = generate_random_vector(1).remove(0);

    // For now, A_{left} and A_{right} are the identity matrix for respective
    // transformations, will swap these out when the zk part is ready.
    let edited_image = image.clone();
    // let target_image = edited_image.clone();
    let rTA = r.clone();
    let As = s.clone();

    Self {
      image,
      edited_image,
      // target_image,
      r,
      s,
      // logup_challenge,
      rTA,
      As,
      _p: PhantomData,
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
    // public_vals.push(self.logup_challenge);
    public_vals.extend(self.rTA.clone());
    public_vals.extend(self.As.clone());

    Ok(public_vals)
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    // No shared variables in this circuit
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<E::Scalar>], // shared variables, if any
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    // No precommitted variables in this circuit
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    // Circuit does not expect any challenges
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

    // 2. Allocate edited_image as public output.
    let mut allocated_edited_image = Vec::new();
    for (i, row) in self.edited_image.clone().into_iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, pixel) in row.into_iter().enumerate() {
        let n = AllocatedNum::alloc_input(
          cs.namespace(|| format!("edited image entry {i} {j}")),
          || Ok(E::Scalar::from_u128(pixel as u128)),
        )?;
        row_vars.push(n);
      }
      allocated_edited_image.push(row_vars);
    }

    // let mut allocated_target_image = Vec::new();
    // for (i, row) in self.target_image.clone().into_iter().enumerate() {
    //   let mut row_vars = Vec::new();
    //   for (j, pixel) in row.into_iter().enumerate() {
    //     let n = AllocatedNum::alloc_input(
    //       cs.namespace(|| format!("target image entry {i} {j}")),
    //       || Ok(E::Scalar::from_u128(pixel as u128)),
    //     )?;
    //     row_vars.push(n);
    //   }
    //   allocated_target_image.push(row_vars);
    // }

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
    // Compute I(As)
    // 2D for loop computing the matrix vector product I(As)
    let mut IAs = Vec::new();
    let mut IAs_felts = Vec::new();
    for (i, row) in image_input_vars.iter().enumerate() {
      let mut row_products = Vec::new();
      let mut row_product_values = Vec::new();
      for ((j, x), y) in row.iter().enumerate().zip(allocated_As.iter()) {
        let product = x.mul(cs.namespace(|| format!("IAs multiplication {i} {j}")), y)?;
        row_products.push(product);
        row_product_values.push(E::Scalar::from_u128(self.image[i][j] as u128) * self.As[j]);
      }

      let mut level_one_lcs = Vec::new();
      let mut level_one_lc_values = Vec::new();
      let mut level_one_chunk_idx = 0;
      for chunk in row_products
        .iter()
        .zip(row_product_values.iter())
        .chunks(LAYER_ONE_CHUNK_SIZE)
        .into_iter()
      {
        let mut inner_lc = LinearCombination::zero();
        let mut inner_lc_val = E::Scalar::ZERO;
        for (product, product_value) in chunk {
          inner_lc = inner_lc.clone() + (<E as Engine>::Scalar::ONE, product.get_variable());
          inner_lc_val = inner_lc_val + product_value;
        }
        let inner_lc_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Row {i} IAs inner product {level_one_chunk_idx}")),
          || Ok(inner_lc_val),
        )?;

        cs.enforce(
          || format!("Row {i} intermediate linear combination {level_one_chunk_idx}"),
          |lc| lc + CS::one(),
          |lc| lc + &inner_lc,
          |lc| lc + inner_lc_var.get_variable(),
        );

        level_one_lcs.push(inner_lc_var);
        level_one_lc_values.push(inner_lc_val);
        level_one_chunk_idx += 1;
      }

      let mut level_two_lc = LinearCombination::zero();
      let mut level_two_lc_val = E::Scalar::ZERO;
      for (var, value) in level_one_lcs.iter().zip(level_one_lc_values.iter()) {
        level_two_lc = level_two_lc.clone() + (<E as Engine>::Scalar::ONE, var.get_variable());
        level_two_lc_val = level_two_lc_val + value;
      }

      let inner_product_var = AllocatedNum::alloc(
        cs.namespace(|| format!("Row {i} IAs inner product")),
        || Ok(level_two_lc_val),
      )?;
      cs.enforce(
        || format!("Row {i} IAs inner product LC"),
        |lc| lc + CS::one(),
        |lc| lc + &level_two_lc,
        |lc| lc + inner_product_var.get_variable(),
      );

      IAs.push(inner_product_var);
      IAs_felts.push(level_two_lc_val);
    }

    // 1D for loop computing the vector vector product (r^TA)(I(As))
    let mut lhs_level_one_lcs = Vec::new();
    let mut lhs_level_one_lc_values = Vec::new();
    let mut lhs_level_one_chunk_idx = 0;
    let lhs_products: Vec<_> = IAs
      .iter()
      .enumerate()
      .zip(allocated_rTA.iter())
      .map(|((i, x), y)| {
        let product = x.mul(cs.namespace(|| format!("rTIAs multiplication {i}")), y)?;
        let val = self.rTA[i] * IAs_felts[i];
        Ok((product, val))
      })
      .collect::<Result<_, SynthesisError>>()?;
    for chunk in lhs_products.iter().chunks(LAYER_ONE_CHUNK_SIZE).into_iter() {
      let mut inner_lc = LinearCombination::zero();
      let mut inner_lc_val = E::Scalar::ZERO;
      for (product, val) in chunk {
        inner_lc = inner_lc.clone() + (<E as Engine>::Scalar::ONE, product.get_variable());
        inner_lc_val = inner_lc_val + val;
      }
      let inner_lc_var = AllocatedNum::alloc(
        cs.namespace(|| format!("LHS inner product {lhs_level_one_chunk_idx}")),
        || Ok(inner_lc_val),
      )?;
      cs.enforce(
        || format!("LHS intermediate linear combination {lhs_level_one_chunk_idx}"),
        |lc| lc + CS::one(),
        |lc| lc + &inner_lc,
        |lc| lc + inner_lc_var.get_variable(),
      );
      lhs_level_one_lcs.push(inner_lc_var);
      lhs_level_one_lc_values.push(inner_lc_val);
      lhs_level_one_chunk_idx += 1;
    }
    let mut lhs_sum_lc = LinearCombination::zero();
    let mut lhs_sum = E::Scalar::ZERO;
    for (var, value) in lhs_level_one_lcs.iter().zip(lhs_level_one_lc_values.iter()) {
      lhs_sum_lc = lhs_sum_lc.clone() + (<E as Engine>::Scalar::ONE, var.get_variable());
      lhs_sum = lhs_sum + value;
    }
    let rTAIAs = AllocatedNum::alloc(cs.namespace(|| format!("Freivalds LHS Result")), || {
      Ok(lhs_sum)
    })?;
    cs.enforce(
      || format!("Freivalds LHS constraint"),
      |lc| lc + CS::one(),
      |lc| lc + &lhs_sum_lc,
      |lc| lc + rTAIAs.get_variable(),
    );

    // 4. Compute RHS convolution (r^T)F(s).
    let mut Fs = Vec::new();
    let mut Fs_felts = Vec::new();
    for (i, row) in allocated_edited_image.iter().enumerate() {
      let mut row_products = Vec::new();
      let mut row_product_values = Vec::new();
      for ((j, x), y) in row.iter().enumerate().zip(allocated_s.iter()) {
        let product = x.mul(cs.namespace(|| format!("Fs multiplication {i} {j}")), y)?;
        row_products.push(product);
        row_product_values.push(E::Scalar::from_u128(self.edited_image[i][j] as u128) * self.As[j]);
      }

      let mut level_one_lcs = Vec::new();
      let mut level_one_lc_values = Vec::new();
      let mut level_one_chunk_idx = 0;
      for chunk in row_products
        .iter()
        .zip(row_product_values.iter())
        .chunks(LAYER_ONE_CHUNK_SIZE)
        .into_iter()
      {
        let mut inner_lc = LinearCombination::zero();
        let mut inner_lc_val = E::Scalar::ZERO;
        for (product, product_value) in chunk {
          inner_lc = inner_lc.clone() + (<E as Engine>::Scalar::ONE, product.get_variable());
          inner_lc_val = inner_lc_val + product_value;
        }
        let inner_lc_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Row {i} Fs inner product {level_one_chunk_idx}")),
          || Ok(inner_lc_val),
        )?;

        cs.enforce(
          || format!("Row {i} Fs intermediate linear combination {level_one_chunk_idx}"),
          |lc| lc + CS::one(),
          |lc| lc + &inner_lc,
          |lc| lc + inner_lc_var.get_variable(),
        );

        level_one_lcs.push(inner_lc_var);
        level_one_lc_values.push(inner_lc_val);
        level_one_chunk_idx += 1;
      }

      let mut level_two_lc = LinearCombination::zero();
      let mut level_two_lc_val = E::Scalar::ZERO;
      for (var, value) in level_one_lcs.iter().zip(level_one_lc_values.iter()) {
        level_two_lc = level_two_lc.clone() + (<E as Engine>::Scalar::ONE, var.get_variable());
        level_two_lc_val = level_two_lc_val + value;
      }

      let inner_product_var =
        AllocatedNum::alloc(cs.namespace(|| format!("Row {i} Fs inner product")), || {
          Ok(level_two_lc_val)
        })?;
      cs.enforce(
        || format!("Row {i} Fs inner product LC"),
        |lc| lc + CS::one(),
        |lc| lc + &level_two_lc,
        |lc| lc + inner_product_var.get_variable(),
      );

      Fs.push(inner_product_var);
      Fs_felts.push(level_two_lc_val);
    }

    let mut rhs_level_one_lcs = Vec::new();
    let mut rhs_level_one_lc_values = Vec::new();
    let mut rhs_level_one_chunk_idx = 0;
    let rhs_products: Vec<_> = Fs
      .iter()
      .enumerate()
      .zip(allocated_r.iter())
      .map(|((i, x), y)| {
        let product = x.mul(cs.namespace(|| format!("rTFAs multiplication {i}")), y)?;
        let val = Fs_felts[i] * self.r[i];
        Ok((product, val))
      })
      .collect::<Result<_, SynthesisError>>()?;
    for chunk in rhs_products.iter().chunks(LAYER_ONE_CHUNK_SIZE).into_iter() {
      let mut inner_lc = LinearCombination::zero();
      let mut inner_lc_val = E::Scalar::ZERO;
      for (product, val) in chunk {
        inner_lc = inner_lc.clone() + (<E as Engine>::Scalar::ONE, product.get_variable());
        inner_lc_val = inner_lc_val + val;
      }
      let inner_lc_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS inner product {rhs_level_one_chunk_idx}")),
        || Ok(inner_lc_val),
      )?;
      cs.enforce(
        || format!("RHS intermediate linear combination {rhs_level_one_chunk_idx}"),
        |lc| lc + CS::one(),
        |lc| lc + &inner_lc,
        |lc| lc + inner_lc_var.get_variable(),
      );
      rhs_level_one_lcs.push(inner_lc_var);
      rhs_level_one_lc_values.push(inner_lc_val);
      rhs_level_one_chunk_idx += 1;
    }
    let mut rhs_sum_lc = LinearCombination::zero();
    let mut rhs_sum = E::Scalar::ZERO;
    for (var, value) in rhs_level_one_lcs.iter().zip(rhs_level_one_lc_values.iter()) {
      rhs_sum_lc = rhs_sum_lc.clone() + (<E as Engine>::Scalar::ONE, var.get_variable());
      rhs_sum = rhs_sum + value;
    }
    let rTFs = AllocatedNum::alloc(cs.namespace(|| format!("Freivalds RHS Result")), || {
      Ok(rhs_sum)
    })?;
    cs.enforce(
      || format!("Freivalds RHS constraint"),
      |lc| lc + CS::one(),
      |lc| lc + &rhs_sum_lc,
      |lc| lc + rTFs.get_variable(),
    );

    // 5. Enforce equality among the two final felts from Freivalds.
    cs.enforce(
      || format!("Final Freivalds validity check"),
      |lc| lc + CS::one(),
      |lc| lc + rTFs.get_variable(),
      |lc| lc + rTAIAs.get_variable(),
    );

    // 6. Range check the outputs.
    // let logup_multiplicities: Vec<u32> = vec![0u32; 256];

    // let _allocated_logup_challenge =
    //   AllocatedNum::alloc_input(cs.namespace(|| "logup_challenge"), || {
    //     Ok(self.logup_challenge)
    //   })?;

    Ok(())
  }
}

fn main() {
  tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)                // no bold colour codes
    .with_env_filter(EnvFilter::from_default_env())
    .init();

  // let image_dimensions_list = vec![(240, 320), (720, 1280)];
  let image_dims = (720usize, 1280usize);

  let test_image = generate_random_image(image_dims);

  // Message lengths: 2^10 … 2^11 bytes.
  let circuit = FreivaldsConvCircuit::<<E as Engine>::Scalar>::new(test_image);

  let root_span = info_span!("bench", "image").entered();
  info!(
    "======= image_size is = {} x {} pixels =======",
    image_dims.0, image_dims.1
  );

  // SETUP
  let t0 = Instant::now();
  let (pk, vk) = SpartanSNARK::<E>::setup(circuit.clone()).expect("setup failed");
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");
  info!("Constraint count is: {}", pk.sizes()[0]);

  // PREPARE
  let t0 = Instant::now();
  let prep_snark =
    SpartanSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
  let prep_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prep_ms, "prep_prove");

  // PROVE
  let t0 = Instant::now();
  let (proof, _prep_snark) =
    SpartanSNARK::<E>::prove(&pk, circuit.clone(), prep_snark, false).expect("prove failed");
  let prove_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prove_ms, "prove");

  // VERIFY
  let t0 = Instant::now();
  proof.verify(&vk).expect("verify errored");
  let verify_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = verify_ms, "verify");

  // Summary
  info!(
    "SUMMARY dims={}x{}, setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
    image_dims.0, image_dims.1, setup_ms, prep_ms, prove_ms, verify_ms
  );
  drop(root_span);
}
