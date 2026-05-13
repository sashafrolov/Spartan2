#![allow(non_snake_case)]

#[path = "utils.rs"]
mod utils;
use utils::{
  read_mono_png,
  create_gblur_matrix, create_gblur_matrix_u64,
  matrix_matrix_product_band_left_u64, matrix_matrix_product_band_right_u64,
  vector_matrix_product, matrix_vector_product,
  SIGMA, GBLUR_RADIUS,
};

use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use spartan2::traits::{Engine, circuit::SpartanCircuit};

pub const BYTES_PER_FIELD_ELEMENT: usize = 30;

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
pub struct GaussianBlurCircuit<Scalar: PrimeField> {
  image: Vec<Vec<u8>>,
  edited_image: Vec<Vec<u8>>,
  target_image: Vec<Vec<u8>>,
  r: Vec<Scalar>,
  s: Vec<Scalar>,
  logup_challenge_1: Scalar,
  logup_challenge_2: Scalar,
  input_polynomial_interpolation_challenge: Scalar,
  output_polynomial_interpolation_challenge: Scalar,
  public_input_poly_eval: Scalar,
  public_output_poly_eval: Scalar,
  rTA: Vec<Scalar>,
  As: Vec<Scalar>,
  pub convolution_result: Vec<Vec<u64>>,
}

impl<Scalar: PrimeField + PrimeFieldBits> GaussianBlurCircuit<Scalar> {
  pub fn new(path_format: &str, channel_letter: &str, index: u64) -> Self {
    let image = read_mono_png(
      &path_format
        .replace("{channel}", channel_letter)
        .replace("{}", &format!("{:04}", index)),
    );

    let height = image.len();
    assert!(height > 0);
    let width = image[0].len();
    assert!(width > 0);

    // The randomness generation feature in Spartan2 was kind of broken at the time of writing.
    // generating challenges like this for now, this has the same performance profile, but would need to be fixed.
    let channel_offset = match channel_letter {
      "R" => 0u64,
      "G" => 1u64,
      "B" => 2u64,
      _ => panic!("channel_letter must be \"R\", \"G\", or \"B\", got {:?}", channel_letter),
    };
    let base = (1u64 << 32) + 12 * index + 4 * channel_offset;
    let r = generate_random_vector(height, base);
    let s = generate_random_vector(width, base + 1);
    let logup_challenge_1 = generate_random_vector(1, base + 2).remove(0);
    let logup_challenge_2 = generate_random_vector(1, base + 5).remove(0);
    let input_polynomial_interpolation_challenge = generate_random_vector(1, base + 3).remove(0);
    let output_polynomial_interpolation_challenge = generate_random_vector(1, base + 4).remove(0);

    // Evaluate the input image polynomial interpolation.
    let flat_image_vals: Vec<u8> = image.iter().flatten().copied().collect();
    let mut packed_scalars: Vec<Scalar> = Vec::new();
    for chunk_vals in flat_image_vals.chunks(BYTES_PER_FIELD_ELEMENT) {
      let mut scalar = Scalar::ZERO;
      let mut coeff = Scalar::ONE;
      for &val in chunk_vals.iter() {
        scalar = scalar + coeff * Scalar::from_u128(val as u128);
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

    // Compute gaussian blur via u64 band matrix multiplication then convert back to bytes.
    let image_u64: Vec<Vec<u64>> = image.iter()
      .map(|row| row.iter().map(|&v| v as u64).collect())
      .collect();
    let gblur_v_u64 = create_gblur_matrix_u64(height, SIGMA, GBLUR_RADIUS);
    let gblur_h_u64 = create_gblur_matrix_u64(width,  SIGMA, GBLUR_RADIUS);
    let row_wise = matrix_matrix_product_band_left_u64(&gblur_v_u64, &image_u64, GBLUR_RADIUS);
    let convolution_result = matrix_matrix_product_band_right_u64(&row_wise, &gblur_h_u64, GBLUR_RADIUS);

    // KERNEL_SCALE = 1<<16; two multiplications scale by (1<<16)^2 = 1<<32.
    let edited_image: Vec<Vec<u8>> = convolution_result.iter()
      .map(|row| row.iter().map(|&v| (v >> 32) as u8).collect())
      .collect();

    // Evaluate the output image polynomial interpolation.
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

    let gblur_v_f: Vec<Vec<Scalar>> = create_gblur_matrix(height, SIGMA, GBLUR_RADIUS);
    let gblur_h_f: Vec<Vec<Scalar>> = create_gblur_matrix(width,  SIGMA, GBLUR_RADIUS);
    let rTA = vector_matrix_product(&r, &gblur_v_f);
    let As  = matrix_vector_product(&gblur_h_f, &s);

    Self {
      image,
      edited_image,
      target_image,
      r,
      s,
      logup_challenge_1,
      logup_challenge_2,
      input_polynomial_interpolation_challenge,
      output_polynomial_interpolation_challenge,
      public_input_poly_eval,
      public_output_poly_eval,
      rTA,
      As,
      convolution_result,
    }
  }
}

impl<E: Engine> SpartanCircuit<E> for GaussianBlurCircuit<E::Scalar> {
  fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
    let height = self.image.len();
    assert!(height > 0);
    let width = self.image[0].len();
    assert!(width > 0);

    let mut public_vals = Vec::new();

    public_vals.extend(self.r.clone());
    public_vals.extend(self.s.clone());
    public_vals.extend(self.rTA.clone());
    public_vals.extend(self.As.clone());
    public_vals.push(self.logup_challenge_1);
    public_vals.push(self.logup_challenge_2);
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
        let n = AllocatedNum::alloc(
          cs.namespace(|| format!("target image entry {i} {j}")),
          || Ok(E::Scalar::from_u128(pixel as u128)),
        )?;
        row_vars.push(n);
      }
      allocated_target_image.push(row_vars);
    }

    let mut allocated_convolution_result = Vec::new();
    for (i, row) in self.convolution_result.clone().into_iter().enumerate() {
      let mut row_vars = Vec::new();
      for (j, val) in row.into_iter().enumerate() {
        let n = AllocatedNum::alloc(
          cs.namespace(|| format!("convolution result entry {i} {j}")),
          || Ok(E::Scalar::from(val)),
        )?;
        row_vars.push(n);
      }
      allocated_convolution_result.push(row_vars);
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
    for (i, row) in allocated_convolution_result.iter().enumerate() {
      let mut row_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
      let mut running_sum = E::Scalar::ZERO;

      for ((j, x), y) in row.iter().enumerate().zip(allocated_s.iter()) {
        running_sum =
          running_sum + E::Scalar::from(self.convolution_result[i][j]) * self.s[j];

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

    // 6. Range Check input/output bytes to be between 0 and 255.
    let mut logup_multiplicities_1: Vec<u32> = vec![0u32; 256];
    let allocated_logup_challenge_1 =
      AllocatedNum::alloc_input(cs.namespace(|| "byte check logup 1 challenge"), || {
        Ok(self.logup_challenge_1)
      })?;

    let mut logup_prev_1: Option<AllocatedNum<E::Scalar>> = None;
    let mut logup_running_sum_1 = E::Scalar::ZERO;
    for (i, row) in allocated_target_image.iter().enumerate() {
      for (j, target_pixel) in row.iter().enumerate() {
        let pixel_val = self.target_image[i][j];
        logup_multiplicities_1[pixel_val as usize] += 1;
        let denom_val = self.logup_challenge_1 + E::Scalar::from_u128(pixel_val as u128);
        logup_running_sum_1 = logup_running_sum_1 + denom_val.invert().unwrap_or(E::Scalar::ZERO);

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("byte check LogUp final image partial sum {i} {j}")),
          || Ok(logup_running_sum_1),
        )?;

        if let Some(prev) = &logup_prev_1 {
          cs.enforce(
            || format!("byte check LogUp final image partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
            |lc| lc + allocated_logup_challenge_1.get_variable() + target_pixel.get_variable(),
            |lc| lc + CS::one(),
          );
        } else {
          cs.enforce(
            || format!("byte check logup 1 final image partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable(),
            |lc| lc + allocated_logup_challenge_1.get_variable() + target_pixel.get_variable(),
            |lc| lc + CS::one(),
          );
        }

        logup_prev_1 = Some(partial_sum_var);
      }
    }
    for (i, row) in image_input_vars.iter().enumerate() {
      for (j, input_pixel) in row.iter().enumerate() {
        let pixel_val = self.image[i][j];
        logup_multiplicities_1[pixel_val as usize] += 1;
        let denom_val = self.logup_challenge_1 + E::Scalar::from_u128(pixel_val as u128);
        logup_running_sum_1 = logup_running_sum_1 + denom_val.invert().unwrap_or(E::Scalar::ZERO);

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("byte check LogUp input image partial sum {i} {j}")),
          || Ok(logup_running_sum_1),
        )?;

        if let Some(prev) = &logup_prev_1 {
          cs.enforce(
            || format!("byte check LogUp input image partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
            |lc| lc + allocated_logup_challenge_1.get_variable() + input_pixel.get_variable(),
            |lc| lc + CS::one(),
          );
        } else {
          cs.enforce(
            || format!("byte check logup 1 input image partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable(),
            |lc| lc + allocated_logup_challenge_1.get_variable() + input_pixel.get_variable(),
            |lc| lc + CS::one(),
          );
        }

        logup_prev_1 = Some(partial_sum_var);
      }
    }
    let lhs_logup_sum_1 = logup_prev_1.unwrap();

    let mut rhs_logup_prev_1: Option<AllocatedNum<E::Scalar>> = None;
    let mut rhs_logup_running_sum_1 = E::Scalar::ZERO;
    for b in 0u128..256 {
      let mult = logup_multiplicities_1[b as usize] as u128;
      let denom_val = self.logup_challenge_1 + E::Scalar::from_u128(b);
      rhs_logup_running_sum_1 = rhs_logup_running_sum_1
        + denom_val.invert().unwrap_or(E::Scalar::ZERO) * E::Scalar::from_u128(mult);

      let mult_var = AllocatedNum::alloc(
        cs.namespace(|| format!("byte check LogUp RHS multiplicity {b}")),
        || Ok(E::Scalar::from_u128(mult)),
      )?;

      let partial_sum_var = AllocatedNum::alloc(
        cs.namespace(|| format!("byte check LogUp RHS partial sum {b}")),
        || Ok(rhs_logup_running_sum_1),
      )?;

      if let Some(prev) = &rhs_logup_prev_1 {
        cs.enforce(
          || format!("byte check LogUp RHS partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
          |lc| lc + allocated_logup_challenge_1.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("byte check LogUp RHS partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable(),
          |lc| lc + allocated_logup_challenge_1.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      }

      rhs_logup_prev_1 = Some(partial_sum_var);
    }
    let rhs_logup_sum_1 = rhs_logup_prev_1.unwrap();

    cs.enforce(
      || "byte check LogUp validity check",
      |lc| lc + CS::one(),
      |lc| lc + lhs_logup_sum_1.get_variable(),
      |lc| lc + rhs_logup_sum_1.get_variable(),
    );

    // 7. Check the decomposition of the convolution results.
    // Split the chunks into u16's (largest thing we can reasonably range check with logup).
    let mut chunk_1: Vec<Vec<u16>> = Vec::new();
    let mut chunk_2: Vec<Vec<u16>> = Vec::new();
    let mut allocated_chunk_1 = Vec::new();
    let mut allocated_chunk_2 = Vec::new();
    for (i, row) in self.convolution_result.iter().enumerate() {
      let mut row_c1_vals = Vec::new();
      let mut row_c2_vals = Vec::new();
      let mut row_chunk_1 = Vec::new();
      let mut row_chunk_2 = Vec::new();
      for (j, &val) in row.iter().enumerate() {
        let c1 = (val & 0xFFFF) as u16;
        let c2 = ((val >> 16) & 0xFFFF) as u16;
        let n1 = AllocatedNum::alloc(
          cs.namespace(|| format!("convolution chunk_1 {i} {j}")),
          || Ok(E::Scalar::from(c1 as u64)),
        )?;
        let n2 = AllocatedNum::alloc(
          cs.namespace(|| format!("convolution chunk_2 {i} {j}")),
          || Ok(E::Scalar::from(c2 as u64)),
        )?;
        row_c1_vals.push(c1);
        row_c2_vals.push(c2);
        row_chunk_1.push(n1);
        row_chunk_2.push(n2);
      }
      chunk_1.push(row_c1_vals);
      chunk_2.push(row_c2_vals);
      allocated_chunk_1.push(row_chunk_1);
      allocated_chunk_2.push(row_chunk_2);
    }

    // Enforce that the right shift was correctly performed.
    let scale_2: E::Scalar = E::Scalar::from(1u64 << 16);
    let scale_3: E::Scalar = E::Scalar::from(1u64 << 32);
    for i in 0..allocated_convolution_result.len() {
      for j in 0..allocated_convolution_result[i].len() {
        cs.enforce(
          || format!("convolution decomposition {i} {j}"),
          |lc| lc + allocated_chunk_1[i][j].get_variable()
                  + (scale_2, allocated_chunk_2[i][j].get_variable())
                  + (scale_3, allocated_edited_image[i][j].get_variable()),
          |lc| lc + CS::one(),
          |lc| lc + allocated_convolution_result[i][j].get_variable(),
        );
      }
    }

    // Range check the remainders to be in [0, 65536)
    let mut logup_multiplicities_2: Vec<u32> = vec![0u32; 65536];
    let allocated_logup_challenge_2 =
      AllocatedNum::alloc_input(cs.namespace(|| "Remainder check logup 2 challenge"), || {
        Ok(self.logup_challenge_2)
      })?;

    let mut logup_prev_2: Option<AllocatedNum<E::Scalar>> = None;
    let mut logup_running_sum_2 = E::Scalar::ZERO;
    for (i, row) in allocated_chunk_1.iter().enumerate() {
      for (j, remainder) in row.iter().enumerate() {
        let remainder_val = chunk_1[i][j];
        logup_multiplicities_2[remainder_val as usize] += 1;
        let denom_val = self.logup_challenge_2 + E::Scalar::from_u128(remainder_val as u128);
        logup_running_sum_2 = logup_running_sum_2 + denom_val.invert().unwrap_or(E::Scalar::ZERO);

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Remainder check LogUp final image partial sum {i} {j}")),
          || Ok(logup_running_sum_2),
        )?;

        if let Some(prev) = &logup_prev_2 {
          cs.enforce(
            || format!("Remainder check LogUp final image partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
            |lc| lc + allocated_logup_challenge_2.get_variable() + remainder.get_variable(),
            |lc| lc + CS::one(),
          );
        } else {
          cs.enforce(
            || format!("Remainder check logup 1 final image partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable(),
            |lc| lc + allocated_logup_challenge_2.get_variable() + remainder.get_variable(),
            |lc| lc + CS::one(),
          );
        }

        logup_prev_2 = Some(partial_sum_var);
      }
    }
    for (i, row) in allocated_chunk_2.iter().enumerate() {
      for (j, remainder) in row.iter().enumerate() {
        let remainder_val = chunk_2[i][j];
        logup_multiplicities_2[remainder_val as usize] += 1;
        let denom_val = self.logup_challenge_2 + E::Scalar::from_u128(remainder_val as u128);
        logup_running_sum_2 = logup_running_sum_2 + denom_val.invert().unwrap_or(E::Scalar::ZERO);

        let partial_sum_var = AllocatedNum::alloc(
          cs.namespace(|| format!("Remainder check LogUp chunk_2 partial sum {i} {j}")),
          || Ok(logup_running_sum_2),
        )?;

        if let Some(prev) = &logup_prev_2 {
          cs.enforce(
            || format!("Remainder check LogUp chunk_2 partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
            |lc| lc + allocated_logup_challenge_2.get_variable() + remainder.get_variable(),
            |lc| lc + CS::one(),
          );
        } else {
          cs.enforce(
            || format!("Remainder check LogUp chunk_2 partial sum constraint {i} {j}"),
            |lc| lc + partial_sum_var.get_variable(),
            |lc| lc + allocated_logup_challenge_2.get_variable() + remainder.get_variable(),
            |lc| lc + CS::one(),
          );
        }

        logup_prev_2 = Some(partial_sum_var);
      }
    }
    let lhs_logup_sum_2 = logup_prev_2.unwrap();

    let mut rhs_logup_prev_2: Option<AllocatedNum<E::Scalar>> = None;
    let mut rhs_logup_running_sum_2 = E::Scalar::ZERO;
    for b in 0u128..65536 {
      let mult = logup_multiplicities_2[b as usize] as u128;
      let denom_val = self.logup_challenge_2 + E::Scalar::from_u128(b);
      rhs_logup_running_sum_2 = rhs_logup_running_sum_2
        + denom_val.invert().unwrap_or(E::Scalar::ZERO) * E::Scalar::from_u128(mult);

      let mult_var = AllocatedNum::alloc(
        cs.namespace(|| format!("logup 2 RHS multiplicity {b}")),
        || Ok(E::Scalar::from_u128(mult)),
      )?;

      let partial_sum_var = AllocatedNum::alloc(
        cs.namespace(|| format!("logup 2 RHS partial sum {b}")),
        || Ok(rhs_logup_running_sum_2),
      )?;

      if let Some(prev) = &rhs_logup_prev_2 {
        cs.enforce(
          || format!("logup 2 RHS partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable() - prev.get_variable(),
          |lc| lc + allocated_logup_challenge_2.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("logup 2 RHS partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable(),
          |lc| lc + allocated_logup_challenge_2.get_variable() + (E::Scalar::from_u128(b), CS::one()),
          |lc| lc + mult_var.get_variable(),
        );
      }

      rhs_logup_prev_2 = Some(partial_sum_var);
    }
    let rhs_logup_sum_2 = rhs_logup_prev_2.unwrap();

    cs.enforce(
      || "logup 2 validity check",
      |lc| lc + CS::one(),
      |lc| lc + lhs_logup_sum_2.get_variable(),
      |lc| lc + rhs_logup_sum_2.get_variable(),
    );

    // 8. Do polynomial interpolation verification on the input.
    let allocated_input_polynomial_interpolation_challenge = AllocatedNum::alloc_input(
      cs.namespace(|| "input_polynomial_interpolation_challenge"),
      || Ok(self.input_polynomial_interpolation_challenge),
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

    // 9. Do polynomial interpolation verification on the output.
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

    Ok(())
  }
}
