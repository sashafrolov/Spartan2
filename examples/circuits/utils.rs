use image::ImageReader;
use image::GrayImage;
use image::RgbImage;

use ff::{Field, PrimeField};
use rayon::prelude::*;

pub static SIGMA: f64 = 10.0;
pub static GBLUR_RADIUS: usize = 30;
static KERNEL_SCALE: u64 = 1u64 << 24;
static FILTER_BITS: usize = 16;

#[derive(Debug, Clone, Copy)]
pub enum MatrixType {
  Tridiagonal,
  Resizing,
  GBlur,
}

pub fn read_color_png(path: &str) -> Vec<Vec<(u8, u8, u8)>> {
  let img: RgbImage = ImageReader::open(path)
    .unwrap_or_else(|e| panic!("failed to open {path}: {e}"))
    .decode()
    .unwrap_or_else(|e| panic!("failed to decode {path}: {e}"))
    .into_rgb8();

  let (width, height) = img.dimensions();
  (0..height)
    .map(|y| (0..width).map(|x| { let p = img.get_pixel(x, y); (p[0], p[1], p[2]) }).collect())
    .collect()
}

pub fn read_mono_png(path: &str) -> Vec<Vec<u8>> {
  let img: GrayImage = ImageReader::open(path)
    .unwrap_or_else(|e| panic!("failed to open {path}: {e}"))
    .decode()
    .unwrap_or_else(|e| panic!("failed to decode {path}: {e}"))
    .into_luma8();

  let (width, height) = img.dimensions();
  (0..height)
    .map(|y| (0..width).map(|x| img.get_pixel(x, y)[0]).collect())
    .collect()
}

// Implement code for witness preparation for blurring. Concrete performance issue: doing F operations is slow,
// even in plain computation. We can make this 10-20x faster by using u64's to do witness preparation
// and just convert to field elements at the end.

pub fn gen_rand_scalar<F: Field>() -> F {
  let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
  F::random(&mut rng)
}

pub fn inner_product<F: PrimeField>(u: &[F], v: &[F]) -> F {
  let len = u.len();
  assert!(len > 0);
  assert_eq!(len, v.len(), "Vectors must have the same length");
  let mut result = F::ZERO;
  for i in 0..len {
    result += u[i] * v[i];
  }
  result
}

pub fn matrix_vector_product<F: PrimeField>(a: &[Vec<F>], v: &[F]) -> Vec<F> {
  let height = a.len();
  assert!(height > 0);
  let width = a[0].len();
  assert_eq!(width, v.len());
  let mut output = Vec::new();
  for i in 0..height {
    let mut inner_prod = F::ZERO;
    for j in 0..width {
      inner_prod += a[i][j] * v[j];
    }
    output.push(inner_prod);
  }
  output
}

pub fn vector_matrix_product<F: PrimeField>(v: &[F], a: &[Vec<F>]) -> Vec<F> {
  let height = a.len();
  assert!(height > 0);
  assert_eq!(height, v.len());
  let width = a[0].len();
  let mut output = vec![F::ZERO; width];
  for i in 0..height {
    for j in 0..width {
      output[j] += a[i][j] * v[i];
    }
  }
  output
}

pub fn matrix_matrix_product<F: PrimeField>(a: &[Vec<F>], b: &[Vec<F>]) -> Vec<Vec<F>> {
  let a_height = a.len();
  assert!(a_height > 0);
  let a_width = a[0].len();
  let b_height = b.len();
  assert!(b_height > 0);
  let b_width = b[0].len();
  assert_eq!(a_width, b_height, "Matrix dimensions incompatible for multiplication");

  a.par_iter()
    .map(|a_row| {
      let mut row = vec![F::ZERO; b_width];
      for j in 0..b_width {
        let mut inner_prod = F::ZERO;
        for k in 0..a_width {
          inner_prod += a_row[k] * b[k][j];
        }
        row[j] = inner_prod;
      }
      row
    })
    .collect()
}

pub fn matrix_matrix_product_band_left<F: PrimeField>(
  a: &[Vec<F>],
  b: &[Vec<F>],
  kernel_width: usize,
) -> Vec<Vec<F>> {
  let a_height = a.len();
  assert!(a_height > 0);
  let a_width = a[0].len();
  let b_height = b.len();
  assert!(b_height > 0);
  let b_width = b[0].len();
  assert_eq!(a_width, b_height, "Matrix dimensions incompatible for multiplication");

  a.par_iter()
    .enumerate()
    .map(|(i, a_row)| {
      let mut row = vec![F::ZERO; b_width];
      let k_start = i.saturating_sub(kernel_width);
      let k_end = (i + kernel_width + 1).min(a_width);
      for j in 0..b_width {
        let mut inner_prod = F::ZERO;
        for k in k_start..k_end {
          inner_prod += a_row[k] * b[k][j];
        }
        row[j] = inner_prod;
      }
      row
    })
    .collect()
}

pub fn matrix_matrix_product_band_right<F: PrimeField>(
  a: &[Vec<F>],
  b: &[Vec<F>],
  kernel_width: usize,
) -> Vec<Vec<F>> {
  let a_height = a.len();
  assert!(a_height > 0);
  let a_width = a[0].len();
  let b_height = b.len();
  assert!(b_height > 0);
  let b_width = b[0].len();
  assert_eq!(a_width, b_height, "Matrix dimensions incompatible for multiplication");

  a.par_iter()
    .map(|a_row| {
      let mut row = vec![F::ZERO; b_width];
      for j in 0..b_width {
        let mut inner_prod = F::ZERO;
        let k_start = j.saturating_sub(kernel_width);
        let k_end = (j + kernel_width + 1).min(b_height);
        for k in k_start..k_end {
          inner_prod += a_row[k] * b[k][j];
        }
        row[j] = inner_prod;
      }
      row
    })
    .collect()
}

pub fn create_tridiagonal_matrix<F: PrimeField>(size: usize) -> Vec<Vec<F>> {
  assert!(size > 0, "Matrix size must be positive");
  let mut matrix = vec![vec![F::ZERO; size]; size];
  for i in 0..size {
    matrix[i][i] = F::ONE;
    if i + 1 < size {
      matrix[i][i + 1] = F::ONE;
    }
    if i > 0 {
      matrix[i][i - 1] = F::ONE;
    }
  }
  matrix
}

pub fn create_resizing_matrix<F: PrimeField>(src_size: usize, dst_size: usize, for_horizontal: bool) -> Vec<Vec<F>> {
  let matrix = create_resize_matrix_impl(src_size, dst_size);
  if for_horizontal {
    transpose(matrix)
  } else {
    matrix
  }
}

fn create_resize_matrix_impl<F: PrimeField>(src_size: usize, dst_size: usize) -> Vec<Vec<F>> {
  let filter_size = 4;
  let mut matrix = vec![vec![F::ZERO; src_size]; dst_size];
  let x_inc = ((src_size << 16) / dst_size + 1) >> 1;
  for i in 0..dst_size {
    let src_pos = (i * x_inc) >> 15;
    let xx_inc = x_inc & 0xffff;
    let xx = (xx_inc * (1 << FILTER_BITS)) / x_inc;
    for j in 0..filter_size {
      let coeff_u64 = if j == 0 {
        (1u64 << FILTER_BITS) - (xx as u64)
      } else {
        xx as u64
      };
      let src_idx = src_pos + j;
      if src_idx < src_size {
        matrix[i][src_idx] = F::from(coeff_u64);
      }
    }
  }
  matrix
}

pub fn transpose<F: PrimeField>(matrix: Vec<Vec<F>>) -> Vec<Vec<F>> {
  let rows = matrix.len();
  if rows == 0 {
    return vec![];
  }
  let cols = matrix[0].len();
  let mut transposed = vec![vec![F::ZERO; rows]; cols];
  for i in 0..rows {
    for j in 0..cols {
      transposed[j][i] = matrix[i][j];
    }
  }
  transposed
}

fn gaussian_kernel1d(sigma: f64, radius: i32) -> Vec<f64> {
  let sigma2 = sigma * sigma;
  let x: Vec<f64> = (-radius..=radius).map(|i| i as f64).collect();
  let mut phi_x: Vec<f64> = x.iter().map(|&xi| (-0.5 / sigma2 * xi * xi).exp()).collect();
  let sum: f64 = phi_x.iter().sum();
  phi_x.iter_mut().for_each(|val| *val /= sum);
  phi_x
}

fn gaussian_kernel1d_fixed_point<F: PrimeField>(sigma: f64, radius: i32) -> Vec<F> {
  let fp_kernel = gaussian_kernel1d(sigma, radius);
  fp_kernel
    .iter()
    .map(|&x| F::from((x * KERNEL_SCALE as f64) as u64))
    .collect()
}

pub fn create_gblur_matrix<F: PrimeField>(size: usize, sigma: f64, radius: usize) -> Vec<Vec<F>> {
  assert!(size > 0, "Matrix size must be positive");
  assert!(radius > 0, "Kernel radius must be positive");
  assert!(sigma > 0.0, "Sigma must be positive");

  let mut matrix = vec![vec![F::ZERO; size]; size];
  let kernel: Vec<F> = gaussian_kernel1d_fixed_point(sigma, radius as i32);
  let kernel_len = kernel.len();
  assert_eq!(kernel_len, 2 * radius + 1, "Kernel length mismatch");

  for i in 0..size {
    let left_overflow = if i < radius { radius - i } else { 0 };
    let right_overflow = if i + radius >= size { i + radius - size + 1 } else { 0 };

    let left_mass: F = (0..left_overflow).fold(F::ZERO, |acc, j| acc + kernel[j]);
    let right_mass: F = (kernel_len - right_overflow..kernel_len).fold(F::ZERO, |acc, j| acc + kernel[j]);

    for (k_idx, j) in (i.saturating_sub(radius)..=(i + radius).min(size - 1)).enumerate() {
      matrix[i][j] = kernel[left_overflow + k_idx];
    }

    if left_overflow > 0 {
      matrix[i][0] = matrix[i][0] + left_mass;
    }
    if right_overflow > 0 {
      matrix[i][size - 1] = matrix[i][size - 1] + right_mass;
    }
  }

  matrix
}

pub fn create_matrix<F: PrimeField>(matrix_type: MatrixType, size: usize, need_transpose: bool) -> Vec<Vec<F>> {
  match matrix_type {
    MatrixType::Tridiagonal => create_tridiagonal_matrix(size),
    MatrixType::Resizing => create_resizing_matrix(size, size / 2, need_transpose),
    MatrixType::GBlur => create_gblur_matrix(size, SIGMA, GBLUR_RADIUS),
  }
}

fn gaussian_kernel1d_fixed_point_u64(sigma: f64, radius: i32) -> Vec<u64> {
  gaussian_kernel1d(sigma, radius)
    .iter()
    .map(|&x| (x * KERNEL_SCALE as f64) as u64)
    .collect()
}

pub fn create_gblur_matrix_u64(size: usize, sigma: f64, radius: usize) -> Vec<Vec<u64>> {
  assert!(size > 0, "Matrix size must be positive");
  assert!(radius > 0, "Kernel radius must be positive");
  assert!(sigma > 0.0, "Sigma must be positive");

  let mut matrix = vec![vec![0u64; size]; size];
  let kernel = gaussian_kernel1d_fixed_point_u64(sigma, radius as i32);
  let kernel_len = kernel.len();
  assert_eq!(kernel_len, 2 * radius + 1, "Kernel length mismatch");

  for i in 0..size {
    let left_overflow = if i < radius { radius - i } else { 0 };
    let right_overflow = if i + radius >= size { i + radius - size + 1 } else { 0 };

    let left_mass: u64 = (0..left_overflow).map(|j| kernel[j]).sum();
    let right_mass: u64 = (kernel_len - right_overflow..kernel_len).map(|j| kernel[j]).sum();

    for (k_idx, j) in (i.saturating_sub(radius)..=(i + radius).min(size - 1)).enumerate() {
      matrix[i][j] = kernel[left_overflow + k_idx];
    }

    if left_overflow > 0 {
      matrix[i][0] = matrix[i][0].wrapping_add(left_mass);
    }
    if right_overflow > 0 {
      matrix[i][size - 1] = matrix[i][size - 1].wrapping_add(right_mass);
    }
  }

  matrix
}

pub fn matrix_matrix_product_band_left_u64(
  a: &[Vec<u64>],
  b: &[Vec<u64>],
  kernel_width: usize,
) -> Vec<Vec<u64>> {
  let a_height = a.len();
  assert!(a_height > 0);
  let a_width = a[0].len();
  let b_height = b.len();
  assert!(b_height > 0);
  let b_width = b[0].len();
  assert_eq!(a_width, b_height, "Matrix dimensions incompatible for multiplication");

  a.iter()
    .enumerate()
    .map(|(i, a_row)| {
      let mut row = vec![0u64; b_width];
      let k_start = i.saturating_sub(kernel_width);
      let k_end = (i + kernel_width + 1).min(a_width);
      for j in 0..b_width {
        let mut inner_prod = 0u64;
        for k in k_start..k_end {
          inner_prod = inner_prod.wrapping_add(a_row[k].wrapping_mul(b[k][j]));
        }
        row[j] = inner_prod;
      }
      row
    })
    .collect()
}

pub fn inner_product_u64(u: &[u64], v: &[u64]) -> u64 {
  assert!(!u.is_empty());
  assert_eq!(u.len(), v.len(), "Vectors must have the same length");
  u.iter().zip(v.iter()).fold(0u64, |acc, (&a, &b)| acc.wrapping_add(a.wrapping_mul(b)))
}

pub fn matrix_vector_product_u64(a: &[Vec<u64>], v: &[u64]) -> Vec<u64> {
  let height = a.len();
  assert!(height > 0);
  assert_eq!(a[0].len(), v.len());
  a.iter()
    .map(|row| row.iter().zip(v.iter()).fold(0u64, |acc, (&a, &b)| acc.wrapping_add(a.wrapping_mul(b))))
    .collect()
}

pub fn vector_matrix_product_u64(v: &[u64], a: &[Vec<u64>]) -> Vec<u64> {
  let height = a.len();
  assert!(height > 0);
  assert_eq!(height, v.len());
  let width = a[0].len();
  let mut output = vec![0u64; width];
  for i in 0..height {
    for j in 0..width {
      output[j] = output[j].wrapping_add(a[i][j].wrapping_mul(v[i]));
    }
  }
  output
}

pub fn matrix_matrix_product_u64(a: &[Vec<u64>], b: &[Vec<u64>]) -> Vec<Vec<u64>> {
  let a_height = a.len();
  assert!(a_height > 0);
  let a_width = a[0].len();
  let b_height = b.len();
  assert!(b_height > 0);
  let b_width = b[0].len();
  assert_eq!(a_width, b_height, "Matrix dimensions incompatible for multiplication");

  a.iter()
    .map(|a_row| {
      let mut row = vec![0u64; b_width];
      for j in 0..b_width {
        let mut inner_prod = 0u64;
        for k in 0..a_width {
          inner_prod = inner_prod.wrapping_add(a_row[k].wrapping_mul(b[k][j]));
        }
        row[j] = inner_prod;
      }
      row
    })
    .collect()
}

pub fn matrix_matrix_product_band_right_u64(
  a: &[Vec<u64>],
  b: &[Vec<u64>],
  kernel_width: usize,
) -> Vec<Vec<u64>> {
  let a_height = a.len();
  assert!(a_height > 0);
  let a_width = a[0].len();
  let b_height = b.len();
  assert!(b_height > 0);
  let b_width = b[0].len();
  assert_eq!(a_width, b_height, "Matrix dimensions incompatible for multiplication");

  a.iter()
    .map(|a_row| {
      let mut row = vec![0u64; b_width];
      for j in 0..b_width {
        let mut inner_prod = 0u64;
        let k_start = j.saturating_sub(kernel_width);
        let k_end = (j + kernel_width + 1).min(b_height);
        for k in k_start..k_end {
          inner_prod = inner_prod.wrapping_add(a_row[k].wrapping_mul(b[k][j]));
        }
        row[j] = inner_prod;
      }
      row
    })
    .collect()
}

pub fn create_tridiagonal_matrix_u64(size: usize) -> Vec<Vec<u64>> {
  assert!(size > 0, "Matrix size must be positive");
  let mut matrix = vec![vec![0u64; size]; size];
  for i in 0..size {
    matrix[i][i] = 1;
    if i + 1 < size { matrix[i][i + 1] = 1; }
    if i > 0       { matrix[i][i - 1] = 1; }
  }
  matrix
}

pub fn create_resizing_matrix_u64(src_size: usize, dst_size: usize, for_horizontal: bool) -> Vec<Vec<u64>> {
  let matrix = create_resize_matrix_impl_u64(src_size, dst_size);
  if for_horizontal { transpose_u64(matrix) } else { matrix }
}

fn create_resize_matrix_impl_u64(src_size: usize, dst_size: usize) -> Vec<Vec<u64>> {
  let filter_size = 4;
  let mut matrix = vec![vec![0u64; src_size]; dst_size];
  let x_inc = ((src_size << 16) / dst_size + 1) >> 1;
  for i in 0..dst_size {
    let src_pos = (i * x_inc) >> 15;
    let xx_inc = x_inc & 0xffff;
    let xx = (xx_inc * (1 << FILTER_BITS)) / x_inc;
    for j in 0..filter_size {
      let coeff = if j == 0 { (1u64 << FILTER_BITS) - xx as u64 } else { xx as u64 };
      let src_idx = src_pos + j;
      if src_idx < src_size {
        matrix[i][src_idx] = coeff;
      }
    }
  }
  matrix
}

pub fn transpose_u64(matrix: Vec<Vec<u64>>) -> Vec<Vec<u64>> {
  let rows = matrix.len();
  if rows == 0 { return vec![]; }
  let cols = matrix[0].len();
  let mut transposed = vec![vec![0u64; rows]; cols];
  for i in 0..rows {
    for j in 0..cols {
      transposed[j][i] = matrix[i][j];
    }
  }
  transposed
}

pub fn create_matrix_u64(matrix_type: MatrixType, size: usize, need_transpose: bool) -> Vec<Vec<u64>> {
  match matrix_type {
    MatrixType::Tridiagonal => create_tridiagonal_matrix_u64(size),
    MatrixType::Resizing => create_resizing_matrix_u64(size, size / 2, need_transpose),
    MatrixType::GBlur => create_gblur_matrix_u64(size, SIGMA, GBLUR_RADIUS),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::RngCore;
  use spartan2::provider::T256HyraxEngine;
  use spartan2::traits::Engine;
  use std::time::Instant;

  type F = <T256HyraxEngine as Engine>::Scalar;

  const IMAGE_HEIGHT: usize = 720;
  const IMAGE_WIDTH: usize = 1280;

  #[test]
  #[ignore]
  fn perf_gblur_band_left() {
    let mut rng = rand::thread_rng();
    let image: Vec<Vec<F>> = (0..IMAGE_HEIGHT)
      .map(|_| (0..IMAGE_WIDTH).map(|_| F::from(rng.next_u32() as u8 as u64)).collect())
      .collect();

    let gblur_matrix: Vec<Vec<F>> = create_gblur_matrix(IMAGE_HEIGHT, SIGMA, GBLUR_RADIUS);

    let t0 = Instant::now();
    let result = matrix_matrix_product_band_left(&gblur_matrix, &image, GBLUR_RADIUS);
    let elapsed = t0.elapsed();

    assert_eq!(result.len(), IMAGE_HEIGHT);
    assert_eq!(result[0].len(), IMAGE_WIDTH);
    println!("matrix_matrix_product_band_left ({IMAGE_HEIGHT}x{IMAGE_HEIGHT} gblur) x ({IMAGE_HEIGHT}x{IMAGE_WIDTH} image): {elapsed:?}");
  }

  #[test]
  #[ignore]
  fn perf_gblur_full_flow_u64() {
    let mut rng = rand::thread_rng();

    // Shared inputs — not included in either timing window
    let image_u64: Vec<Vec<u64>> = (0..IMAGE_HEIGHT)
      .map(|_| (0..IMAGE_WIDTH).map(|_| rng.next_u32() as u8 as u64).collect())
      .collect();
    let r: Vec<F> = (0..IMAGE_HEIGHT).map(|_| gen_rand_scalar::<F>()).collect();
    let s: Vec<F> = (0..IMAGE_WIDTH).map(|_| gen_rand_scalar::<F>()).collect();

    // --- u64-accelerated workflow ---
    let t0 = Instant::now();

    // Image products in u64
    let gblur_v_u64 = create_gblur_matrix_u64(IMAGE_HEIGHT, SIGMA, GBLUR_RADIUS);
    let gblur_h_u64 = create_gblur_matrix_u64(IMAGE_WIDTH,  SIGMA, GBLUR_RADIUS);
    let row_wise_u64 = matrix_matrix_product_band_left_u64(&gblur_v_u64, &image_u64, GBLUR_RADIUS);
    let edited_u64   = matrix_matrix_product_band_right_u64(&row_wise_u64, &gblur_h_u64, GBLUR_RADIUS);

    // Convert to F for Freivalds
    let image_f: Vec<Vec<F>> = image_u64.iter()
      .map(|row| row.iter().map(|&v| F::from(v)).collect())
      .collect();
    let edited_f: Vec<Vec<F>> = edited_u64.iter()
      .map(|row| row.iter().map(|&v| F::from(v)).collect())
      .collect();

    // Freivalds in F
    let gblur_v_f: Vec<Vec<F>> = create_gblur_matrix(IMAGE_HEIGHT, SIGMA, GBLUR_RADIUS);
    let gblur_h_f: Vec<Vec<F>> = create_gblur_matrix(IMAGE_WIDTH,  SIGMA, GBLUR_RADIUS);
    let rTA         = vector_matrix_product(&r, &gblur_v_f);
    let As          = matrix_vector_product(&gblur_h_f, &s);
    let rTAI        = vector_matrix_product(&rTA, &image_f);
    let rTAIAs      = inner_product(&rTAI, &As);
    let rTF         = vector_matrix_product(&r, &edited_f);
    let rTFs        = inner_product(&rTF, &s);

    let elapsed_u64 = t0.elapsed();

    // --- Pure F workflow ---
    let t0 = Instant::now();

    let gblur_v_f2: Vec<Vec<F>> = create_gblur_matrix(IMAGE_HEIGHT, SIGMA, GBLUR_RADIUS);
    let gblur_h_f2: Vec<Vec<F>> = create_gblur_matrix(IMAGE_WIDTH,  SIGMA, GBLUR_RADIUS);
    let image_f2: Vec<Vec<F>> = image_u64.iter()
      .map(|row| row.iter().map(|&v| F::from(v)).collect())
      .collect();
    let row_wise_f2  = matrix_matrix_product_band_left(&gblur_v_f2, &image_f2, GBLUR_RADIUS);
    let edited_f2    = matrix_matrix_product_band_right(&row_wise_f2, &gblur_h_f2, GBLUR_RADIUS);
    let rTA_f        = vector_matrix_product(&r, &gblur_v_f2);
    let As_f         = matrix_vector_product(&gblur_h_f2, &s);
    let rTAI_f       = vector_matrix_product(&rTA_f, &image_f2);
    let rTAIAs_f     = inner_product(&rTAI_f, &As_f);
    let rTF_f        = vector_matrix_product(&r, &edited_f2);
    let rTFs_f       = inner_product(&rTF_f, &s);

    let elapsed_f = t0.elapsed();

    println!("u64-accelerated: {elapsed_u64:?}  |  LHS={rTAIAs:?}  RHS={rTFs:?}");
    println!("pure F:          {elapsed_f:?}  |  LHS={rTAIAs_f:?}  RHS={rTFs_f:?}");

    // Consistency checks
    for i in 0..IMAGE_HEIGHT {
      for j in 0..IMAGE_WIDTH {
        assert_eq!(edited_f[i][j], edited_f2[i][j], "edited image mismatch at ({i}, {j})");
      }
    }
    assert_eq!(rTAIAs, rTAIAs_f, "Freivalds LHS mismatch");
    assert_eq!(rTFs,   rTFs_f,   "Freivalds RHS mismatch");
  }
}
