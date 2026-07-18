//! Estimate sparse matrix-vector circuit costs for a list of configurations.
//!
//! Edit `CONFIGURATIONS` below, then run:
//!   cargo run --example sparse_mv_cost_estimates

#[allow(dead_code)]
#[path = "circuits/sparse_matrix_vector_product_circuit.rs"]
mod sparse_matrix_vector_product_circuit;

use sparse_matrix_vector_product_circuit::SparseProductConfig;

/// One circuit shape and the per-pixel work performed by its larger context.
/// Here, one modeled pixel is one nonzero-delta entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CostEstimateConfig {
  name: &'static str,
  image_height: usize,
  image_width: usize,
  max_delta_length: usize,
  batch_size: usize,
  /// Additional constraints per pixel, such as constraints for rounding.
  additional_per_pixel_work: usize,
}

/// Add or edit configurations here.
const CONFIGURATIONS: &[CostEstimateConfig] = &[
  CostEstimateConfig {
    name: "720p example, batch size 1, 20% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 184320, // 20% of pixels have changes
    batch_size: 1,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation.
  },
  CostEstimateConfig {
    name: "720p example, batch size 1, 10% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 92160, // 10% of pixels have changes
    batch_size: 1,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
  CostEstimateConfig {
    name: "720p example, batch size 1, 5% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 46080, // 5% of pixels have changes
    batch_size: 1,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
  CostEstimateConfig {
    name: "720p example, batch size 3, 20% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 61440, // 20% of pixels have changes
    batch_size: 3,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
  CostEstimateConfig {
    name: "720p example, batch size 3, 10% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 30720, // 10% of pixels have changes
    batch_size: 3,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
  CostEstimateConfig {
    name: "720p example, batch size 3, 5% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 15360, // 5% of pixels have changes
    batch_size: 3,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
  CostEstimateConfig {
    name: "720p example, batch size 10, 20% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 18432, // 20% of pixels have changes
    batch_size: 10,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
  CostEstimateConfig {
    name: "720p example, batch size 10, 10% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 9216, // 10% of pixels have changes
    batch_size: 10,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
  CostEstimateConfig {
    name: "720p example, batch size 10, 5% of pixels, blurring type rounding",
    image_height: 720,
    image_width: 1280,
    max_delta_length: 4608, // 5% of pixels have changes
    batch_size: 10,
    additional_per_pixel_work: 5, // Additional per-pixel work for authentication/rounding similar to gblur implementation
  },
];

#[derive(Clone, Copy, Debug, PartialEq)]
struct CostEstimate {
  image_pixel_count: usize,
  nonzero_delta_entry_count: usize,
  sparse_constraint_count: usize,
  additional_constraint_count: usize,
  total_constraint_count: usize,
  sparse_constraints_per_nonzero_entry: f64,
  total_constraints_per_nonzero_entry: f64,
}

fn estimate(config: CostEstimateConfig) -> CostEstimate {
  let sparse_product = SparseProductConfig::new(
    config.image_height,
    config.image_width,
    config.max_delta_length,
    config.batch_size,
  );
  let image_pixel_count = sparse_product.image_height * sparse_product.image_width;
  let nonzero_delta_entry_count = sparse_product.max_delta_length * sparse_product.batch_size;
  let sparse_constraint_count = sparse_product.expected_num_constraints();
  let additional_constraint_count = nonzero_delta_entry_count * config.additional_per_pixel_work;
  let total_constraint_count = sparse_constraint_count + additional_constraint_count;

  CostEstimate {
    image_pixel_count,
    nonzero_delta_entry_count,
    sparse_constraint_count,
    additional_constraint_count,
    total_constraint_count,
    sparse_constraints_per_nonzero_entry: sparse_constraint_count as f64
      / nonzero_delta_entry_count as f64,
    total_constraints_per_nonzero_entry: total_constraint_count as f64
      / nonzero_delta_entry_count as f64,
  }
}

fn main() {
  for (index, config) in CONFIGURATIONS.iter().copied().enumerate() {
    if index > 0 {
      println!();
    }

    println!("{}:", config.name);
    println!("  image_height: {}", config.image_height);
    println!("  image_width: {}", config.image_width);
    println!("  max_delta_length: {}", config.max_delta_length);
    println!("  batch_size: {}", config.batch_size);
    println!(
      "  additional_per_pixel_work: {}",
      config.additional_per_pixel_work
    );

    let cost = estimate(config);
    println!("  image_pixel_count: {}", cost.image_pixel_count);
    println!(
      "  nonzero_delta_entry_count: {}",
      cost.nonzero_delta_entry_count
    );
    println!(
      "  sparse_constraint_count: {}",
      cost.sparse_constraint_count
    );
    println!(
      "  additional_constraint_count: {}",
      cost.additional_constraint_count
    );
    println!("  total_constraint_count: {}", cost.total_constraint_count);
    println!(
      "  sparse_constraints_per_nonzero_entry: {:.6}",
      cost.sparse_constraints_per_nonzero_entry
    );
    println!(
      "  total_constraints_per_nonzero_entry: {:.6}",
      cost.total_constraints_per_nonzero_entry
    );
  }
}