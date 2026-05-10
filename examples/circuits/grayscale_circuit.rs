#![allow(non_snake_case)]

use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use spartan2::traits::{Engine, circuit::SpartanCircuit};

// How many bytes to store in a field element. We could store 31 but 3 divides 30 evenly.
pub const BYTES_PER_FIELD_ELEMENT: usize = 30;
pub const BYTES_PER_PIXEL: usize = 3;

pub fn generate_random_vector<Scalar: PrimeField + PrimeFieldBits>(length: usize, seed: u64) -> Vec<Scalar> {
  let mut rng = StdRng::seed_from_u64(seed);
  (0..length)
    .map(|_| Scalar::from_u128(rng.gen_range(0..((1u128 << 127) as u128))))
    .collect()
}

pub fn generate_random_image(dimensions: (usize, usize), seed: u64) -> Vec<Vec<u8>> {
  let (height, width) = dimensions;
  let mut rng = StdRng::seed_from_u64(seed);
  (0..height)
    .map(|_| (0..width).map(|_| rng.next_u32() as u8).collect())
    .collect()
}

#[derive(Clone, Debug)]
pub struct GrayscaleCircuit<Scalar: PrimeField> {
  image: Vec<Vec<(u8, u8, u8)>>,
  edited_image: Vec<Vec<u8>>,
  target_image: Vec<Vec<u8>>,
  jnd_map: Vec<Vec<u8>>,
  logup_challenge_1: Scalar,
  logup_challenge_2: Scalar,
  input_polynomial_interpolation_challenge: Scalar,
  output_polynomial_interpolation_challenge: Scalar,
  public_input_poly_eval: Scalar,
  public_output_poly_eval: Scalar,
}

impl<Scalar: PrimeField + PrimeFieldBits> ExampleVideoEditCircuit<Scalar> {
  pub fn new(image: Vec<Vec<u8>>, index: u64) -> Self {
    let height = image.len();
    assert!(height > 0);
    let width = image[0].len();
    assert!(width > 0);

    // The randomness generation feature in Spartan2 was kind of broken at the time of writing.
    // generating challenges like this for now, this has the same performance profile, but would need to be fixed.
    let base = (1u64 << 32) + 4 * index;
    let logup_challenge_1 = generate_random_vector(1, base + 2).remove(0);
    let logup_challenge_2 = generate_random_vector(1, base + 3).remove(0);
    let input_polynomial_interpolation_challenge = generate_random_vector(1, base + 1).remove(0);
    let output_polynomial_interpolation_challenge = generate_random_vector(1, base + 2).remove(0);

    // Evaluate the input image polynomial interpolation.
    let flat_image_vals: Vec<(u8, u8, u8)> = image.iter().flatten().copied().collect();
    let mut packed_scalars: Vec<Scalar> = Vec::new();
    for chunk_vals in flat_image_vals.chunks(BYTES_PER_FIELD_ELEMENT / BYTES_PER_PIXEL) {
      let mut scalar = Scalar::ZERO;
      let mut coeff = Scalar::ONE;
      for &(val0, val1, val2) in chunk_vals.iter() {
        scalar = scalar + coeff * Scalar::from_u128(val0 as u128);
        coeff = coeff * Scalar::from_u128(1u128 << 8);
        scalar = scalar + coeff * Scalar::from_u128(val1 as u128);
        coeff = coeff * Scalar::from_u128(1u128 << 8);
        scalar = scalar + coeff * Scalar::from_u128(val2 as u128);
        coeff = coeff * Scalar::from_u128(1u128 << 8);
      }
      packed_scalars.push(scalar);
    }
    let public_input_poly_eval = packed_scalars
      .iter()
      .skip(1)
      .fold(packed_scalars[0], |acc, s| {
        acc * input_polynomial_interpolation_challenge + s
      });

    let edited_image = image.clone();

    // Evaluate the output image output interpolation. Note: this is a bit of a hack,
    // it turns out that having large public outputs leads to some bottlenecks
    // for verification (a large serial hash and evaluating the MLEs of large vectors).
    let flat_edited_vals: Vec<u8> = edited_image.iter().flatten().copied().collect();
    let mut packed_output_scalars: Vec<Scalar> = Vec::new();
    for chunk_vals in flat_edited_vals.chunks(BYTES_PER_FIELD_ELEMENT) {
      let mut scalar = Scalar::ZERO;
      let mut coeff = Scalar::ONE;
      for &val in chunk_vals.iter() {
        scalar = scalar + coeff * Scalar::from_u128(val as u128);
        coeff = coeff * Scalar::from_u128(1u128 << 8);
      }
      packed_output_scalars.push(scalar);
    }
    let public_output_poly_eval = packed_output_scalars
      .iter()
      .skip(1)
      .fold(packed_output_scalars[0], |acc, s| {
        acc * output_polynomial_interpolation_challenge + s
      });
    let target_image = edited_image.clone();

    let jnd_map = vec![vec![8u8; width]; height];

    Self {
      image,
      edited_image,
      target_image,
      jnd_map,
      logup_challenge_1,
      logup_challenge_2,
      input_polynomial_interpolation_challenge,
      output_polynomial_interpolation_challenge,
      public_input_poly_eval,
      public_output_poly_eval,
    }
  }
}

impl<E: Engine> SpartanCircuit<E> for ExampleVideoEditCircuit<E::Scalar> {
  fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
    let height = self.image.len();
    assert!(height > 0);
    let width = self.image[0].len();
    assert!(width > 0);

    let mut public_vals = Vec::new();

    public_vals.push(self.logup_challenge_1);
    public_vals.push(self.input_polynomial_interpolation_challenge);
    public_vals.push(self.public_input_poly_eval);
    public_vals.push(self.output_polynomial_interpolation_challenge);
    public_vals.push(self.public_output_poly_eval);

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
    0 // again a consequence of this feature being kind of broken in the version of Sparatn at time of writing.
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
          .map(|(j, (val0, val1, val2))| {
            let n0 = AllocatedNum::alloc(
              cs.namespace(|| format!("Input image pixel {i},{j} channel 0")),
              || Ok(E::Scalar::from_u128(val0 as u128)),
            )?;
            let n1 = AllocatedNum::alloc(
              cs.namespace(|| format!("Input image pixel {i},{j} channel 1")),
              || Ok(E::Scalar::from_u128(val1 as u128)),
            )?;
            let n2 = AllocatedNum::alloc(
              cs.namespace(|| format!("Input image pixel {i},{j} channel 2")),
              || Ok(E::Scalar::from_u128(val2 as u128)),
            )?;
            Ok((n0, n1, n2))
          })
          .collect::<Result<Vec<_>, _>>()
      })
      .collect::<Result<Vec<Vec<_>>, _>>()?;

    // 2. Allocate edited_image as private.
    let mut allocated_edited_image = Vec::new();
    for (i, row) in self.edited_image.clone().into_iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, val) in row.into_iter().enumerate() {
        let n = AllocatedNum::alloc(
          cs.namespace(|| format!("edited image entry {i} {j}")),
          || Ok(E::Scalar::from_u128(val as u128)),
        )?;
        row_vars.push(n);
      }
      allocated_edited_image.push(row_vars);
    }

    let mut allocated_target_image = Vec::new();
    for (i, row) in self.target_image.clone().into_iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, val) in row.into_iter().enumerate() {
        let n = AllocatedNum::alloc(
          cs.namespace(|| format!("target image entry {i} {j}")),
          || Ok(E::Scalar::from_u128(val as u128)),
        )?;
        row_vars.push(n);
      }
      allocated_target_image.push(row_vars);
    }

    // 3. Compute grayscale linear combinations.
    // We are doing this in fixed point with 1000 multiplying all values.
    // This is slightly more precise than VerITAS.
    const GRAYSCALE_R_COEFFICIENT: u32 = 299;
    const GRAYSCALE_G_COEFFICIENT: u32 = 587;
    const GRAYSCALE_B_COEFFICIENT: u32 = 114;

    // Plain weighted sums (numerator of fixed-point grayscale, divide by 1000 to get the pixel value).
    let grayscale_weighted_sums: Vec<Vec<u32>> = self.image
      .iter()
      .map(|row| {
        row.iter()
          .map(|&(r, g, b)| {
            r as u32 * GRAYSCALE_R_COEFFICIENT
              + g as u32 * GRAYSCALE_G_COEFFICIENT
              + b as u32 * GRAYSCALE_B_COEFFICIENT
          })
          .collect()
      })
      .collect();

    let grayscale_remainders: Vec<Vec<u32>> = grayscale_weighted_sums
      .iter()
      .map(|row| row.iter().map(|&s| s % 1000).collect())
      .collect();

    let allocated_grayscale_remainders: Vec<Vec<AllocatedNum<E::Scalar>>> = grayscale_remainders
      .iter()
      .enumerate()
      .map(|(i, row)| {
        row
          .iter()
          .enumerate()
          .map(|(j, &rem)| {
            AllocatedNum::alloc(
              cs.namespace(|| format!("grayscale remainder {i} {j}")),
              || Ok(E::Scalar::from(rem as u64)),
            )
          })
          .collect::<Result<Vec<_>, _>>()
      })
      .collect::<Result<Vec<Vec<_>>, _>>()?;

    // Constraint-system weighted sums: one LC per pixel combining the three channel variables.
    let grayscale_weighted_lcs: Vec<Vec<LinearCombination<E::Scalar>>> = image_input_vars
      .iter()
      .map(|row| {
        row.iter()
          .map(|(n0, n1, n2)| {
            LinearCombination::zero()
              + (E::Scalar::from(GRAYSCALE_R_COEFFICIENT as u64), n0.get_variable())
              + (E::Scalar::from(GRAYSCALE_G_COEFFICIENT as u64), n1.get_variable())
              + (E::Scalar::from(GRAYSCALE_B_COEFFICIENT as u64), n2.get_variable())
          })
          .collect()
      })
      .collect();

    // 4. LogUp range checks for the remainder. These are checks for 0 to 1000.
    let mut logup_multiplicities_1: Vec<u32> = vec![0u32; 1000];
    let allocated_logup_challenge_1 =
      AllocatedNum::alloc_input(cs.namespace(|| "LogUp challenge1"), || {
        Ok(self.logup_challenge_1)
      })?;

    let mut logup_prev_1: Option<AllocatedNum<E::Scalar>> = None;
    let mut logup_running_sum_1 = E::Scalar::ZERO;
    for (i, row) in allocated_grayscale_remainders.iter().enumerate() {
        for (j, remainder) in row.iter().enumerate() {
            let pixel_val = self.target_image[i][j];
            logup_multiplicities_1[pixel_val as usize] += 1;
            let denom_val = self.logup_challenge_1 + E::Scalar::from_u128(pixel_val as u128);
            logup_running_sum_1 = logup_running_sum_1 + denom_val.invert().unwrap_or(E::Scalar::ZERO);

            let partial_sum_var = AllocatedNum::alloc(
            cs.namespace(|| format!("LogUp remainder check partial sum {i} {j}")),
            || Ok(logup_running_sum_1),
            )?;

            if let Some(prev) = &logup_prev_1 {
            cs.enforce(
                || format!("LogUp remainder check partial sum constraint {i} {j}"),
                |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
                |lc| lc + allocated_logup_challenge_1.get_variable() + remainder.get_variable(),
                |lc| lc + CS::one(),
            );
            } else {
            cs.enforce(
                || format!("LogUp remainder check partial sum constraint {i} {j}"),
                |lc| lc + partial_sum_var.get_variable(),
                |lc| lc + allocated_logup_challenge_1.get_variable() + remainder.get_variable(),
                |lc| lc + CS::one(),
            );
            }

            logup_prev_1 = Some(partial_sum_var);
        }
    }
    let lhs_logup_sum_1 = logup_prev_1.unwrap();

    let mut rhs_logup_prev_1: Option<AllocatedNum<E::Scalar>> = None;
    let mut rhs_logup_running_sum_1 = E::Scalar::ZERO;
    for b in 0u128..1000 {
      let mult = logup_multiplicities_1[b as usize] as u128;
      let denom_val = self.logup_challenge_1 + E::Scalar::from_u128(b);
      rhs_logup_running_sum_1 = rhs_logup_running_sum_1
        + denom_val.invert().unwrap_or(E::Scalar::ZERO) * E::Scalar::from_u128(mult);

      let mult_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS Remainder LogUp multiplicity {b}")),
        || Ok(E::Scalar::from_u128(mult)),
      )?;

      let partial_sum_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS Remainder LogUp partial sum {b}")),
        || Ok(rhs_logup_running_sum_1),
      )?;

      if let Some(prev) = &rhs_logup_prev_1 {
        cs.enforce(
          || format!("RHS Remainder LogUp partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
          |lc| lc + allocated_logup_challenge_1.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("RHS Remainder LogUp partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable(),
          |lc| lc + allocated_logup_challenge_1.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      }

      rhs_logup_prev_1 = Some(partial_sum_var);
    }
    let rhs_logup_sum_1 = rhs_logup_prev_1.unwrap();

    cs.enforce(
      || "Remainder LogUp validity check",
      |lc| lc + CS::one(),
      |lc| lc + lhs_logup_sum_1.get_variable(),
      |lc| lc + rhs_logup_sum_1.get_variable(),
    );

    // 5. Do logup range checks for the input/output bytes (edited bytes are implicitly
    // range checked from the remainder range check/constraints).
    let mut logup_multiplicities_2: Vec<u32> = vec![0u32; 256];
    let allocated_logup_challenge_2 =
      AllocatedNum::alloc_input(cs.namespace(|| "LogUp challenge 2"), || {
        Ok(self.logup_challenge_2)
      })?;

    let mut logup_prev_2: Option<AllocatedNum<E::Scalar>> = None;
    let mut logup_running_sum_2 = E::Scalar::ZERO;
    for (i, row) in allocated_image.iter().enumerate() {
        for (j, (n0, n1, n2)) in row.iter().enumerate() {
            let (val0, val1, val2) = self.image[i][j];
            for (c, (channel_val, channel_var)) in [(val0, n0), (val1, n1), (val2, n2)].iter().enumerate() {
                logup_multiplicities_2[*channel_val as usize] += 1;
                let denom_val = self.logup_challenge_2 + E::Scalar::from_u128(*channel_val as u128);
                logup_running_sum_2 = logup_running_sum_2 + denom_val.invert().unwrap_or(E::Scalar::ZERO);

                let partial_sum_var = AllocatedNum::alloc(
                cs.namespace(|| format!("Byte Check LogUp partial sum {i} {j} {c}")),
                || Ok(logup_running_sum_2),
                )?;

                if let Some(prev) = &logup_prev_2 {
                cs.enforce(
                    || format!("Byte Check LogUp partial sum constraint {i} {j} {c}"),
                    |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
                    |lc| lc + allocated_logup_challenge_2.get_variable() + channel_var.get_variable(),
                    |lc| lc + CS::one(),
                );
                } else {
                cs.enforce(
                    || format!("Byte Check LogUp partial sum constraint {i} {j} {c}"),
                    |lc| lc + partial_sum_var.get_variable(),
                    |lc| lc + allocated_logup_challenge_2.get_variable() + channel_var.get_variable(),
                    |lc| lc + CS::one(),
                );
                }

                logup_prev_2 = Some(partial_sum_var);
            }
        }
    }
    for (i, row) in allocated_edited_image.iter().enumerate() {
        for (j, pixel_val) in row.iter().enumerate() {
            logup_multiplicities_2[pixel_val] += 1;
            let denom_val = self.logup_challenge_2 + E::Scalar::from_u128(pixel_val as u128);
            logup_running_sum_2 = logup_running_sum_2 + denom_val.invert().unwrap_or(E::Scalar::ZERO);

            let partial_sum_var = AllocatedNum::alloc(
            cs.namespace(|| format!("Byte Check LogUp partial sum {i} {j} edited")),
            || Ok(logup_running_sum_2),
            )?;

            if let Some(prev) = &logup_prev_2 {
            cs.enforce(
                || format!("Byte Check LogUp partial sum constraint {i} {j} edited"),
                |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
                |lc| lc + allocated_logup_challenge_2.get_variable() + channel_var.get_variable(),
                |lc| lc + CS::one(),
            );
            } else {
            cs.enforce(
                || format!("Byte Check LogUp partial sum constraint {i} {j} edited"),
                |lc| lc + partial_sum_var.get_variable(),
                |lc| lc + allocated_logup_challenge_2.get_variable() + channel_var.get_variable(),
                |lc| lc + CS::one(),
            );
            }

            logup_prev_2 = Some(partial_sum_var);
        }
    }
    let lhs_logup_sum_2 = logup_prev_2.unwrap();

    let mut rhs_logup_prev_2: Option<AllocatedNum<E::Scalar>> = None;
    let mut rhs_logup_running_sum_2 = E::Scalar::ZERO;
    for b in 0u128..256 {
      let mult = logup_multiplicities_2[b as usize] as u128;
      let denom_val = self.logup_challenge_2 + E::Scalar::from_u128(b);
      rhs_logup_running_sum_2 = rhs_logup_running_sum_2
        + denom_val.invert().unwrap_or(E::Scalar::ZERO) * E::Scalar::from_u128(mult);

      let mult_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS Byte Check LogUp multiplicity {b}")),
        || Ok(E::Scalar::from_u128(mult)),
      )?;

      let partial_sum_var = AllocatedNum::alloc(
        cs.namespace(|| format!("RHS Byte Check LogUp partial sum {b}")),
        || Ok(rhs_logup_running_sum_2),
      )?;

      if let Some(prev) = &rhs_logup_prev_2 {
        cs.enforce(
          || format!("RHS Byte Check LogUp partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
          |lc| lc + allocated_logup_challenge_2.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("RHS Byte Check LogUp partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable(),
          |lc| lc + allocated_logup_challenge_2.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      }

      rhs_logup_prev_2 = Some(partial_sum_var);
    }
    let rhs_logup_sum_2 = rhs_logup_prev_2.unwrap();

    cs.enforce(
      || "Byte Check LogUp validity check",
      |lc| lc + CS::one(),
      |lc| lc + lhs_logup_sum_2.get_variable(),
      |lc| lc + rhs_logup_sum_2.get_variable(),
    );

    // 6. Verify that the divisions were computed correctly.
    for (i, row) in allocated_grayscale_remainders.iter().enumerate() {
      for (j, remainder) in row.iter().enumerate() {
        cs.enforce(
          || format!("Grayscale division check {i} {j}"),
          |lc| lc + CS::one(),
          |lc| lc + grayscale_weighted_lcs[i][j].clone(),
          |lc| lc + (E::Scalar::from(1000u64), allocated_target_image[i][j].get_variable())
                   + remainder.get_variable(),
        );
      }
    }

    // 7. Do polynomial interpolation verification on the input.
    let allocated_input_polynomial_interpolation_challenge = AllocatedNum::alloc_input(
      cs.namespace(|| "input_polynomial_interpolation_challenge"),
      || Ok(self.input_polynomial_interpolation_challenge),
    )?;

    // Pack image bytes into field elements, simulating some sort of PCS sig verification.
    let flat_image_vars: Vec<[&AllocatedNum<E::Scalar>; 3]> = image_input_vars
      .iter()
      .flatten()
      .map(|(n0, n1, n2)| [n0, n1, n2])
      .collect();
    let flat_image_vals: Vec<(u8, u8, u8)> = self.image.iter().flatten().copied().collect();

    let mut packed_lcs: Vec<LinearCombination<E::Scalar>> = Vec::new();
    let mut packed_scalars: Vec<E::Scalar> = Vec::new();

    for (chunk_vars, chunk_vals) in flat_image_vars
      .chunks(BYTES_PER_FIELD_ELEMENT / BYTES_PER_PIXEL)
      .zip(flat_image_vals.chunks(BYTES_PER_FIELD_ELEMENT / BYTES_PER_PIXEL))
    {
      let mut lc = LinearCombination::zero();
      let mut scalar = E::Scalar::ZERO;
      let mut coeff = E::Scalar::ONE;
      for (vars, &(val0, val1, val2)) in chunk_vars.iter().zip(chunk_vals.iter()) {
        lc = lc + (coeff, vars[0].get_variable());
        scalar = scalar + coeff * E::Scalar::from_u128(val0 as u128);
        coeff = coeff * E::Scalar::from_u128(1u128 << 8);
        lc = lc + (coeff, vars[1].get_variable());
        scalar = scalar + coeff * E::Scalar::from_u128(val1 as u128);
        coeff = coeff * E::Scalar::from_u128(1u128 << 8);
        lc = lc + (coeff, vars[2].get_variable());
        scalar = scalar + coeff * E::Scalar::from_u128(val2 as u128);
        coeff = coeff * E::Scalar::from_u128(1u128 << 8);
      }
      packed_lcs.push(lc);
      packed_scalars.push(scalar);
    }

    // Evaluate packed_lcs as a polynomial at input_polynomial_interpolation_challenge using Horner's rule:
    let mut input_poly_eval_prev: Option<AllocatedNum<E::Scalar>> = None;
    let mut input_poly_eval_scalar = E::Scalar::ZERO;

    for (k, (lc, scalar)) in packed_lcs.iter().zip(packed_scalars.iter()).enumerate() {
      if let Some(prev) = &input_poly_eval_prev {
        input_poly_eval_scalar = input_poly_eval_scalar * self.input_polynomial_interpolation_challenge + scalar;

        let input_eval_var = AllocatedNum::alloc(cs.namespace(|| format!("input poly eval {k}")), || {
          Ok(input_poly_eval_scalar)
        })?;

        cs.enforce(
          || format!("input poly eval constraint {k}"),
          |lc_a| lc_a + prev.get_variable(),
          |lc_b| lc_b + allocated_input_polynomial_interpolation_challenge.get_variable(),
          |lc_c| lc_c + input_eval_var.get_variable() - lc,
        );

        input_poly_eval_prev = Some(input_eval_var);
      } else {
        input_poly_eval_scalar = *scalar;

        let input_eval_var = AllocatedNum::alloc(cs.namespace(|| format!("input poly eval {k}")), || {
          Ok(input_poly_eval_scalar)
        })?;

        cs.enforce(
          || format!("input poly eval constraint {k}"),
          |lc_a| lc_a + input_eval_var.get_variable(),
          |lc_b| lc_b + CS::one(),
          |lc_c| lc_c + lc,
        );

        input_poly_eval_prev = Some(input_eval_var);
      }
    }
    let input_poly_eval = input_poly_eval_prev.unwrap();
    let public_input_poly_eval = AllocatedNum::alloc_input(
      cs.namespace(|| "public_input_poly_eval"),
      || Ok(self.public_input_poly_eval),
    )?;
    cs.enforce(
      || "public_input_poly_eval equality",
      |lc| lc + CS::one(),
      |lc| lc + input_poly_eval.get_variable(),
      |lc| lc + public_input_poly_eval.get_variable(),
    );

    // 8. Do polynomial interpolation verification on the output.
    // This is a bit of a hack. This NeutronNova implementation has some costs which scale kind of poorly
    // in the size of the public inputs (the public transcript hashing is almost entirely serial), so this decreases those costs.
    // Alternative solution could be to make a parallel `Transcript` implementation.
    let allocated_output_polynomial_interpolation_challenge = AllocatedNum::alloc_input(
      cs.namespace(|| "output_polynomial_interpolation_challenge"),
      || Ok(self.output_polynomial_interpolation_challenge),
    )?;

    let flat_edited_vars: Vec<&AllocatedNum<E::Scalar>> =
      allocated_edited_image.iter().flatten().collect();
    let flat_edited_vals: Vec<u8> = self.edited_image.iter().flatten().copied().collect();

    let mut output_packed_lcs: Vec<LinearCombination<E::Scalar>> = Vec::new();
    let mut output_packed_scalars: Vec<E::Scalar> = Vec::new();

    for (chunk_vars, chunk_vals) in flat_edited_vars
      .chunks(BYTES_PER_FIELD_ELEMENT)
      .zip(flat_edited_vals.chunks(BYTES_PER_FIELD_ELEMENT))
    {
      let mut lc = LinearCombination::zero();
      let mut scalar = E::Scalar::ZERO;
      let mut coeff = E::Scalar::ONE;
      for (var, &val) in chunk_vars.iter().zip(chunk_vals.iter()) {
        lc = lc + (coeff, var.get_variable());
        scalar = scalar + coeff * E::Scalar::from_u128(val as u128);
        coeff = coeff * E::Scalar::from_u128(1u128 << 8);
      }
      output_packed_lcs.push(lc);
      output_packed_scalars.push(scalar);
    }

    let mut output_poly_eval_prev: Option<AllocatedNum<E::Scalar>> = None;
    let mut output_poly_eval_scalar = E::Scalar::ZERO;

    for (k, (lc, scalar)) in output_packed_lcs.iter().zip(output_packed_scalars.iter()).enumerate() {
      if let Some(prev) = &output_poly_eval_prev {
        output_poly_eval_scalar = output_poly_eval_scalar * self.output_polynomial_interpolation_challenge + scalar;

        let output_eval_var = AllocatedNum::alloc(cs.namespace(|| format!("output poly eval {k}")), || {
          Ok(output_poly_eval_scalar)
        })?;

        cs.enforce(
          || format!("output poly eval constraint {k}"),
          |lc_a| lc_a + prev.get_variable(),
          |lc_b| lc_b + allocated_output_polynomial_interpolation_challenge.get_variable(),
          |lc_c| lc_c + output_eval_var.get_variable() - lc,
        );

        output_poly_eval_prev = Some(output_eval_var);
      } else {
        output_poly_eval_scalar = *scalar;

        let output_eval_var = AllocatedNum::alloc(cs.namespace(|| format!("output poly eval {k}")), || {
          Ok(output_poly_eval_scalar)
        })?;

        cs.enforce(
          || format!("output poly eval constraint {k}"),
          |lc_a| lc_a + output_eval_var.get_variable(),
          |lc_b| lc_b + CS::one(),
          |lc_c| lc_c + lc,
        );

        output_poly_eval_prev = Some(output_eval_var);
      }
    }
    let output_poly_eval = output_poly_eval_prev.unwrap();
    let public_output_poly_eval = AllocatedNum::alloc_input(
      cs.namespace(|| "public_output_poly_eval"),
      || Ok(self.public_output_poly_eval),
    )?;
    cs.enforce(
      || "public_output_poly_eval equality",
      |lc| lc + CS::one(),
      |lc| lc + output_poly_eval.get_variable(),
      |lc| lc + public_output_poly_eval.get_variable(),
    );

    // 9. Do JND difference checking.
    let mut jnd_map_variables: Vec<Vec<AllocatedNum<E::Scalar>>> = Vec::new();
    for (i, row) in self.jnd_map.iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, &val) in row.iter().enumerate() {
        let n = AllocatedNum::alloc(
          cs.namespace(|| format!("jnd map entry {i} {j}")),
          || Ok(E::Scalar::from_u128(val as u128)),
        )?;
        row_vars.push(n);
      }
      jnd_map_variables.push(row_vars);
    }

    


    Ok(())
  }
}
