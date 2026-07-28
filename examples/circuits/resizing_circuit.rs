#![allow(non_snake_case)]

#[path = "utils.rs"]
mod utils;
use utils::{
  SparseMatrix, create_resizing_sparse, dense_sparse_matmul_u64, read_mono_png,
  sparse_dense_matmul_u64,
};

use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use spartan2::traits::{Engine, circuit::SpartanCircuit};

pub const BYTES_PER_FIELD_ELEMENT: usize = 30;

pub fn generate_random_vector<Scalar: PrimeField + PrimeFieldBits>(
  length: usize,
  seed: u64,
) -> Vec<Scalar> {
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

#[derive(Clone, Copy)]
enum ResizeProduct {
  MatrixVector,
  VectorMatrix,
}

/// Allocates one output variable per entry and binds it to a sparse resizing
/// matrix product with a single wide linear constraint.
fn allocate_resize_product<Scalar, CS>(
  cs: &mut CS,
  input_vars: &[AllocatedNum<Scalar>],
  input_values: &[Scalar],
  matrix: &SparseMatrix,
  num_columns: usize,
  product: ResizeProduct,
) -> Result<(Vec<AllocatedNum<Scalar>>, Vec<Scalar>), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  assert_eq!(input_vars.len(), input_values.len());

  let output_terms = match product {
    ResizeProduct::MatrixVector => {
      assert_eq!(input_vars.len(), num_columns);
      matrix.clone()
    }
    ResizeProduct::VectorMatrix => {
      assert_eq!(input_vars.len(), matrix.len());
      let mut transposed = vec![Vec::new(); num_columns];
      for (input_index, row) in matrix.iter().enumerate() {
        for &(output_index, coefficient) in row {
          assert!(output_index < num_columns);
          transposed[output_index].push((input_index, coefficient));
        }
      }
      transposed
    }
  };

  let mut output_vars = Vec::with_capacity(output_terms.len());
  let mut output_values = Vec::with_capacity(output_terms.len());
  for (output_index, terms) in output_terms.iter().enumerate() {
    let mut output_value = Scalar::ZERO;
    let mut output_lc = LinearCombination::zero();
    for &(input_index, coefficient_u64) in terms {
      assert!(input_index < input_vars.len());
      let coefficient = Scalar::from(coefficient_u64);
      output_value += coefficient * input_values[input_index];
      output_lc = output_lc + (coefficient, input_vars[input_index].get_variable());
    }

    let output_var = AllocatedNum::alloc(cs.namespace(|| format!("entry {output_index}")), || {
      Ok(output_value)
    })?;
    cs.enforce(
      || format!("computation {output_index}"),
      |lc| lc + &output_lc,
      |lc| lc + CS::one(),
      |lc| lc + output_var.get_variable(),
    );

    output_vars.push(output_var);
    output_values.push(output_value);
  }

  Ok((output_vars, output_values))
}

#[derive(Clone, Debug)]
pub struct ResizingCircuit<Scalar: PrimeField> {
  image: Vec<Vec<u8>>,
  edited_image: Vec<Vec<u8>>,
  target_image: Vec<Vec<u8>>,
  r: Vec<Scalar>,
  s: Vec<Scalar>,
  logup_challenge_1: Scalar,
  logup_challenge_2: Scalar,
  input_polynomial_interpolation_challenge: Scalar,
  public_input_poly_eval: Scalar,
  public_output_packed: Vec<Scalar>,
  pub convolution_result: Vec<Vec<u64>>,
}

impl<Scalar: PrimeField + PrimeFieldBits> ResizingCircuit<Scalar> {
  pub fn new(path_format: &str, channel_letter: &str, index: u64) -> Self {
    let image = read_mono_png(
      &path_format
        .replace("{channel}", channel_letter)
        .replace("{}", &format!("{:04}", index)),
    );

    // For now, just do a 2x resize on both dimensions.
    let height = image.len();
    assert!(height > 0);
    let width = image[0].len();
    assert!(width > 0);
    assert!(
      height % 2 == 0,
      "image height must be even for 2x downscaling"
    );
    assert!(
      width % 2 == 0,
      "image width must be even for 2x downscaling"
    );

    let channel_offset = match channel_letter {
      "R" => 0u64,
      "G" => 1u64,
      "B" => 2u64,
      _ => panic!(
        "channel_letter must be \"R\", \"G\", or \"B\", got {:?}",
        channel_letter
      ),
    };
    let base = (1u64 << 32) + 18 * index + 6 * channel_offset;
    let r = generate_random_vector(height / 2, base);
    let s = generate_random_vector(width / 2, base + 1);
    let logup_challenge_1 = generate_random_vector(1, base + 2).remove(0);
    let logup_challenge_2 = generate_random_vector(1, base + 5).remove(0);
    let input_polynomial_interpolation_challenge = generate_random_vector(1, base + 3).remove(0);

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

    // Compute 2x resized image (implemented with sparse matrix mul. for Freivald's reasons)
    let image_u64: Vec<Vec<u64>> = image
      .iter()
      .map(|row| row.iter().map(|&v| v as u64).collect())
      .collect();
    let resize_v_sparse = create_resizing_sparse(height, height / 2, false);
    let resize_h_sparse = create_resizing_sparse(width, width / 2, true);
    let row_wise = sparse_dense_matmul_u64(&resize_v_sparse, &image_u64);
    let convolution_result = dense_sparse_matmul_u64(&row_wise, &resize_h_sparse, width / 2);

    // Both sides of the multiplication are in fixed point and add a 2^16 scaling factor, remove it.
    let edited_image: Vec<Vec<u8>> = convolution_result
      .iter()
      .map(|row| row.iter().map(|&v| (v >> 32) as u8).collect())
      .collect();

    // Pack the edited image into field elements. These packed values are themselves the
    // public output rather than a Horner evaluation of them: an evaluation at a challenge
    // the prover picks binds nothing, so the verifier has to receive the packed values
    // directly. Packing keeps that ~30x smaller than raw pixel values.
    let flat_edited_vals: Vec<u8> = edited_image.iter().flatten().copied().collect();
    let mut public_output_packed: Vec<Scalar> = Vec::new();
    for chunk_vals in flat_edited_vals.chunks(BYTES_PER_FIELD_ELEMENT) {
      let mut scalar = Scalar::ZERO;
      let mut coeff = Scalar::ONE;
      for &val in chunk_vals.iter() {
        scalar = scalar + coeff * Scalar::from_u128(val as u128);
        coeff = coeff * Scalar::from_u128(1u128 << 8);
      }
      public_output_packed.push(scalar);
    }
    let target_image = edited_image.clone();

    Self {
      image,
      edited_image,
      target_image,
      r,
      s,
      logup_challenge_1,
      logup_challenge_2,
      input_polynomial_interpolation_challenge,
      public_input_poly_eval,
      public_output_packed,
      convolution_result,
    }
  }
}

impl<E: Engine> SpartanCircuit<E> for ResizingCircuit<E::Scalar> {
  fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
    let height = self.image.len();
    assert!(height > 0);
    let width = self.image[0].len();
    assert!(width > 0);

    let mut public_vals = Vec::new();

    public_vals.extend(self.r.clone());
    public_vals.extend(self.s.clone());
    public_vals.push(self.logup_challenge_1);
    public_vals.push(self.logup_challenge_2);
    public_vals.push(self.input_polynomial_interpolation_challenge);
    public_vals.push(self.public_input_poly_eval);
    public_vals.extend(self.public_output_packed.clone());

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
    // 1. Allocate private input for the (full-resolution) image.
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

    // 2. Allocate edited_image (height/2 × width/2) as private.
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

    // convolution_result is (height/2) x (width/2). Intermediate values before right shifting.
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

    // A_v is (height / 2) x height and A_h is width x (width / 2).
    // Materialize r^T A_v and A_h s once, binding every output entry with one
    // wide linear constraint over only the sparse resize coefficients.
    let height = image_input_vars.len();
    let width = image_input_vars[0].len();
    let resize_v_sparse = create_resizing_sparse(height, height / 2, false);
    let resize_h_sparse = create_resizing_sparse(width, width / 2, true);
    let (allocated_rTA, rTA_values) = allocate_resize_product(
      &mut cs.namespace(|| "compute rTA"),
      &allocated_r,
      &self.r,
      &resize_v_sparse,
      height,
      ResizeProduct::VectorMatrix,
    )?;
    let (allocated_As, As_values) = allocate_resize_product(
      &mut cs.namespace(|| "compute As"),
      &allocated_s,
      &self.s,
      &resize_h_sparse,
      width / 2,
      ResizeProduct::MatrixVector,
    )?;

    // 3. Compute LHS of Freivalds: (r^T A_v) I (A_h s).
    let mut IAs = Vec::new();
    let mut IAs_felts = Vec::new();
    for (i, row) in image_input_vars.iter().enumerate() {
      let mut row_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
      let mut running_sum = E::Scalar::ZERO;

      for ((j, x), y) in row.iter().enumerate().zip(allocated_As.iter()) {
        running_sum = running_sum + E::Scalar::from_u128(self.image[i][j] as u128) * As_values[j];

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
      lhs_running_sum = lhs_running_sum + rTA_values[i] * IAs_felts[i];
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

    // 4. Compute RHS of Freivalds: r^T F s.
    let mut Fs = Vec::new();
    let mut Fs_felts = Vec::new();
    for (i, row) in allocated_convolution_result.iter().enumerate() {
      let mut row_partial_sums: Vec<AllocatedNum<E::Scalar>> = Vec::new();
      let mut running_sum = E::Scalar::ZERO;

      for ((j, x), y) in row.iter().enumerate().zip(allocated_s.iter()) {
        running_sum = running_sum + E::Scalar::from(self.convolution_result[i][j]) * self.s[j];

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
          |lc| {
            lc + allocated_logup_challenge_1.get_variable() + (E::Scalar::from_u128(b), CS::one())
          },
          |lc| lc + mult_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("byte check LogUp RHS partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable(),
          |lc| {
            lc + allocated_logup_challenge_1.get_variable() + (E::Scalar::from_u128(b), CS::one())
          },
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
          |lc| {
            lc + allocated_chunk_1[i][j].get_variable()
              + (scale_2, allocated_chunk_2[i][j].get_variable())
              + (scale_3, allocated_edited_image[i][j].get_variable())
          },
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
          |lc| {
            lc + allocated_logup_challenge_2.get_variable() + (E::Scalar::from_u128(b), CS::one())
          },
          |lc| lc + mult_var.get_variable(),
        );
      } else {
        cs.enforce(
          || format!("logup 2 RHS partial sum constraint {b}"),
          |lc| lc + partial_sum_var.get_variable(),
          |lc| {
            lc + allocated_logup_challenge_2.get_variable() + (E::Scalar::from_u128(b), CS::one())
          },
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

    let mut input_poly_eval_prev: Option<AllocatedNum<E::Scalar>> = None;
    let mut input_poly_eval_scalar = E::Scalar::ZERO;

    for (k, (lc, scalar)) in packed_lcs.iter().zip(packed_scalars.iter()).enumerate() {
      if let Some(prev) = &input_poly_eval_prev {
        input_poly_eval_scalar =
          input_poly_eval_scalar * self.input_polynomial_interpolation_challenge + scalar;

        let input_eval_var =
          AllocatedNum::alloc(cs.namespace(|| format!("input poly eval {k}")), || {
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

        let input_eval_var =
          AllocatedNum::alloc(cs.namespace(|| format!("input poly eval {k}")), || {
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
    let public_input_poly_eval =
      AllocatedNum::alloc_input(cs.namespace(|| "public_input_poly_eval"), || {
        Ok(self.public_input_poly_eval)
      })?;
    cs.enforce(
      || "public_input_poly_eval equality",
      |lc| lc + CS::one(),
      |lc| lc + input_poly_eval.get_variable(),
      |lc| lc + public_input_poly_eval.get_variable(),
    );

    // 9. Expose the packed edited image (height/2 × width/2) as the circuit's public output.
    // Each public value is constrained to equal a linear combination over BYTES_PER_FIELD_ELEMENT
    // of the private edited-image variables, so every output byte is bound by the proof. This
    // costs one public input per 30 pixels, which NeutronNova's largely serial transcript
    // hashing is sensitive to, but it is the price of the output actually being committed.
    let flat_edited_vars: Vec<&AllocatedNum<E::Scalar>> =
      allocated_edited_image.iter().flatten().collect();
    let flat_edited_vals: Vec<u8> = self.edited_image.iter().flatten().copied().collect();

    for (k, (chunk_vars, chunk_vals)) in flat_edited_vars
      .chunks(BYTES_PER_FIELD_ELEMENT)
      .zip(flat_edited_vals.chunks(BYTES_PER_FIELD_ELEMENT))
      .enumerate()
    {
      let mut lc = LinearCombination::zero();
      let mut scalar = E::Scalar::ZERO;
      let mut coeff = E::Scalar::ONE;
      for (var, &val) in chunk_vars.iter().zip(chunk_vals.iter()) {
        lc = lc + (coeff, var.get_variable());
        scalar = scalar + coeff * E::Scalar::from_u128(val as u128);
        coeff = coeff * E::Scalar::from_u128(1u128 << 8);
      }

      let public_output_packed_var = AllocatedNum::alloc_input(
        cs.namespace(|| format!("public_output_packed {k}")),
        || Ok(scalar),
      )?;

      cs.enforce(
        || format!("public_output_packed constraint {k}"),
        |lc_a| lc_a + public_output_packed_var.get_variable(),
        |lc_b| lc_b + CS::one(),
        |lc_c| lc_c + &lc,
      );
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use spartan2::{
    provider::T256HyraxEngine,
    traits::{Engine, circuit::SpartanCircuit},
  };

  type E = T256HyraxEngine;
  type Scalar = <E as Engine>::Scalar;

  fn scalar(value: u64) -> Scalar {
    Scalar::from_u128(value as u128)
  }

  fn allocate_public_vector(
    cs: &mut TestConstraintSystem<Scalar>,
    label: &str,
    values: &[Scalar],
  ) -> Vec<AllocatedNum<Scalar>> {
    values
      .iter()
      .enumerate()
      .map(|(index, &value)| {
        AllocatedNum::alloc_input(cs.namespace(|| format!("{label} {index}")), || Ok(value))
          .unwrap()
      })
      .collect()
  }

  fn packed_field_elements(bytes: &[u8]) -> Vec<Scalar> {
    bytes
      .chunks(BYTES_PER_FIELD_ELEMENT)
      .map(|chunk| {
        chunk
          .iter()
          .fold((Scalar::ZERO, Scalar::ONE), |(value, coefficient), byte| {
            (
              value + coefficient * scalar(*byte as u64),
              coefficient * scalar(1 << 8),
            )
          })
          .0
      })
      .collect()
  }

  fn polynomial_evaluation(bytes: &[u8], challenge: Scalar) -> Scalar {
    let packed = packed_field_elements(bytes);
    packed.iter().skip(1).fold(packed[0], |evaluation, value| {
      evaluation * challenge + value
    })
  }

  fn small_valid_circuit() -> ResizingCircuit<Scalar> {
    let image = vec![
      vec![1, 2, 3, 4, 5, 6],
      vec![7, 8, 9, 10, 11, 12],
      vec![13, 14, 15, 16, 17, 18],
      vec![19, 20, 21, 22, 23, 24],
    ];
    let image_u64: Vec<Vec<u64>> = image
      .iter()
      .map(|row| row.iter().map(|&pixel| pixel as u64).collect())
      .collect();
    let vertical = create_resizing_sparse(image.len(), image.len() / 2, false);
    let horizontal = create_resizing_sparse(image[0].len(), image[0].len() / 2, true);
    let row_wise = sparse_dense_matmul_u64(&vertical, &image_u64);
    let convolution_result = dense_sparse_matmul_u64(&row_wise, &horizontal, image[0].len() / 2);
    let edited_image: Vec<Vec<u8>> = convolution_result
      .iter()
      .map(|row| row.iter().map(|value| (value >> 32) as u8).collect())
      .collect();
    let input_challenge = scalar(37);

    ResizingCircuit {
      public_input_poly_eval: polynomial_evaluation(
        &image.iter().flatten().copied().collect::<Vec<_>>(),
        input_challenge,
      ),
      public_output_packed: packed_field_elements(
        &edited_image.iter().flatten().copied().collect::<Vec<_>>(),
      ),
      target_image: edited_image.clone(),
      image,
      edited_image,
      r: vec![scalar(11), scalar(13)],
      s: vec![scalar(17), scalar(19), scalar(23)],
      logup_challenge_1: scalar(1_000_000),
      logup_challenge_2: scalar(2_000_000),
      input_polynomial_interpolation_challenge: input_challenge,
      convolution_result,
    }
  }

  #[test]
  fn sparse_products_match_dense_rectangular_references_and_are_constrained() {
    use super::utils::{create_resizing_matrix, matrix_vector_product, vector_matrix_product};

    // Non-integral ratios exercise overlapping multi-term sparse rows and
    // make the two rectangular product orientations distinguishable.
    let vertical_src = 17;
    let vertical_dst = 7;
    let horizontal_src = 14;
    let horizontal_dst = 6;
    let r: Vec<Scalar> = (0..vertical_dst)
      .map(|i| scalar(3 * i as u64 + 1))
      .collect();
    let s: Vec<Scalar> = (0..horizontal_dst)
      .map(|i| scalar(5 * i as u64 + 2))
      .collect();

    let vertical_dense = create_resizing_matrix(vertical_src, vertical_dst, false);
    let horizontal_dense = create_resizing_matrix(horizontal_src, horizontal_dst, true);
    let vertical_sparse = create_resizing_sparse(vertical_src, vertical_dst, false);
    let horizontal_sparse = create_resizing_sparse(horizontal_src, horizontal_dst, true);
    let expected_rTA = vector_matrix_product(&r, &vertical_dense);
    let expected_As = matrix_vector_product(&horizontal_dense, &s);

    let mut cs = TestConstraintSystem::new();
    let allocated_r = allocate_public_vector(&mut cs, "r", &r);
    let allocated_s = allocate_public_vector(&mut cs, "s", &s);
    let (allocated_rTA, rTA_values) = allocate_resize_product(
      &mut cs.namespace(|| "compute rTA"),
      &allocated_r,
      &r,
      &vertical_sparse,
      vertical_src,
      ResizeProduct::VectorMatrix,
    )
    .unwrap();
    let (allocated_As, As_values) = allocate_resize_product(
      &mut cs.namespace(|| "compute As"),
      &allocated_s,
      &s,
      &horizontal_sparse,
      horizontal_dst,
      ResizeProduct::MatrixVector,
    )
    .unwrap();

    assert_eq!(rTA_values, expected_rTA);
    assert_eq!(As_values, expected_As);
    assert_eq!(
      allocated_rTA
        .iter()
        .map(|value| value.get_value().unwrap())
        .collect::<Vec<_>>(),
      expected_rTA,
    );
    assert_eq!(
      allocated_As
        .iter()
        .map(|value| value.get_value().unwrap())
        .collect::<Vec<_>>(),
      expected_As,
    );
    assert_eq!(cs.num_constraints(), vertical_src + horizontal_src);
    assert!(cs.is_satisfied());

    let rTA_path = "compute rTA/entry 0/num";
    let correct_rTA = cs.get(rTA_path);
    cs.set(rTA_path, correct_rTA + Scalar::ONE);
    assert_eq!(cs.which_is_unsatisfied(), Some("compute rTA/computation 0"));
    cs.set(rTA_path, correct_rTA);
    assert!(cs.is_satisfied());

    let As_path = "compute As/entry 0/num";
    let correct_As = cs.get(As_path);
    cs.set(As_path, correct_As + Scalar::ONE);
    assert_eq!(cs.which_is_unsatisfied(), Some("compute As/computation 0"));
  }

  #[test]
  fn exact_two_x_products_include_structural_zero_entries() {
    let source_size = 8;
    let destination_size = source_size / 2;
    let input_values = vec![scalar(2), scalar(3), scalar(5), scalar(7)];
    let sparse = create_resizing_sparse(source_size, destination_size, false);
    let mut cs = TestConstraintSystem::new();
    let allocated_input = allocate_public_vector(&mut cs, "input", &input_values);
    let (outputs, output_values) = allocate_resize_product(
      &mut cs,
      &allocated_input,
      &input_values,
      &sparse,
      source_size,
      ResizeProduct::VectorMatrix,
    )
    .unwrap();

    let scale = scalar(1 << 16);
    assert_eq!(outputs.len(), source_size);
    assert_eq!(
      output_values,
      vec![
        scale * scalar(2),
        Scalar::ZERO,
        scale * scalar(3),
        Scalar::ZERO,
        scale * scalar(5),
        Scalar::ZERO,
        scale * scalar(7),
        Scalar::ZERO,
      ],
    );
    assert_eq!(cs.num_constraints(), source_size);
    assert!(cs.is_satisfied());

    // Empty sparse rows are still explicitly bound to zero.
    cs.set("entry 1/num", Scalar::ONE);
    assert_eq!(cs.which_is_unsatisfied(), Some("computation 1"));
  }

  #[test]
  fn public_values_omit_derived_products() {
    let circuit = small_valid_circuit();
    let public_values =
      <ResizingCircuit<Scalar> as SpartanCircuit<E>>::public_values(&circuit).unwrap();

    let mut expected = vec![
      scalar(11),
      scalar(13),
      scalar(17),
      scalar(19),
      scalar(23),
      scalar(1_000_000),
      scalar(2_000_000),
      scalar(37),
      circuit.public_input_poly_eval,
    ];
    expected.extend(circuit.public_output_packed.clone());

    assert_eq!(public_values, expected);
    assert_eq!(
      public_values.len(),
      circuit.r.len() + circuit.s.len() + 4 + circuit.public_output_packed.len()
    );
  }

  #[test]
  fn complete_circuit_is_satisfied_with_derived_products() {
    let circuit = small_valid_circuit();
    let expected_public_values =
      <ResizingCircuit<Scalar> as SpartanCircuit<E>>::public_values(&circuit).unwrap();
    let mut cs = TestConstraintSystem::new();
    <ResizingCircuit<Scalar> as SpartanCircuit<E>>::synthesize(
      &circuit,
      &mut cs,
      &[],
      &[],
      Some(&[]),
    )
    .unwrap();

    assert!(cs.is_satisfied());
    assert!(cs.verify(&expected_public_values));
    let height = circuit.image.len();
    let width = circuit.image[0].len();
    let pixels = height * width;
    let output_height = height / 2;
    let output_width = width / 2;
    let output_pixels = output_height * output_width;
    let constraints_before_derived_products = 2 * pixels
      + 5 * output_pixels
      + height
      + output_height
      + pixels.div_ceil(BYTES_PER_FIELD_ELEMENT)
      + output_pixels.div_ceil(BYTES_PER_FIELD_ELEMENT)
      + 65_796;
    assert_eq!(
      cs.num_constraints(),
      constraints_before_derived_products + height + width,
    );
  }
}
