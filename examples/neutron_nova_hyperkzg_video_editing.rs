// NeutronNova video editing with the non-streaming version and BN254 HyperKZG commitments.
// This mirrors neutron_nova_video_editing.rs, but uses the experimental transparent
// HyperKZG engine instead of T256 Hyrax.
//
// Run with:
//   RUST_LOG=neutron_nova_hyperkzg_video_editing=info,spartan2::neutronnova_zk_ram_optimized=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_hyperkzg_video_editing --release
// Optionally override the Powers-of-Tau file:
//   SPARTAN2_HYPERKZG_PTAU=video_data/ppot_0080_24.ptau
// The RUST_LOG is because the Spartan library has a bunch of unnecessary print statements for large
// circuits internally.

#![allow(non_snake_case)]
#[path = "circuits/dummy_circuit.rs"]
mod dummy_circuit;
#[path = "circuits/example_freivalds_edit_circuit.rs"]
mod example_freivalds_edit_circuit;

use dummy_circuit::DummyCircuit;
use example_freivalds_edit_circuit::{ExampleVideoEditCircuit, generate_random_image};
use rayon::prelude::*;
use spartan2::{
  bellpepper::{r1cs::SpartanShape, shape_cs::ShapeCS},
  neutronnova_zk_ram_optimized::NeutronNovaZkSNARK,
  provider::Bn254KzgEngine,
  traits::Engine,
};
use std::{env, time::Instant};
use tracing::{info, info_span};

const DEFAULT_NUM_CIRCUITS: usize = 4;
const DEFAULT_IMAGE_DIMS: (usize, usize) = (1280, 720);

fn parse_usize_env(name: &str, default: usize) -> usize {
  env::var(name)
    .ok()
    .and_then(|value| value.parse().ok())
    .unwrap_or(default)
}

fn main() {
  let _ = tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  type E = Bn254KzgEngine;

  let num_circuits = parse_usize_env("NN_HYPERKZG_NUM_CIRCUITS", DEFAULT_NUM_CIRCUITS);
  let image_dims = (
    parse_usize_env("NN_HYPERKZG_IMAGE_HEIGHT", DEFAULT_IMAGE_DIMS.0),
    parse_usize_env("NN_HYPERKZG_IMAGE_WIDTH", DEFAULT_IMAGE_DIMS.1),
  );

  let root_span = info_span!(
    "bench",
    num_circuits,
    image_height = image_dims.0,
    image_width = image_dims.1,
  )
  .entered();
  info!(
    num_circuits,
    image_height = image_dims.0,
    image_width = image_dims.1,
    "starting NeutronNova HyperKZG video editing benchmark"
  );

  // Use a dummy circuit of the right shape to derive the R1CS constraints and keys.
  let shape_circuit =
    ExampleVideoEditCircuit::<<E as Engine>::Scalar>::new(generate_random_image(image_dims, 0), 0);
  let [
    num_cons_unpadded,
    num_shared_unpadded,
    num_precommitted_unpadded,
    num_rest_unpadded,
    num_cons,
    num_shared,
    num_precommitted,
    num_rest,
    num_public,
    num_challenges,
  ] = <ShapeCS<E> as SpartanShape<E>>::r1cs_shape(&shape_circuit)
    .unwrap()
    .sizes();
  info!(
    num_cons_unpadded,
    num_shared_unpadded,
    num_precommitted_unpadded,
    num_rest_unpadded,
    num_cons,
    num_shared,
    num_precommitted,
    num_rest,
    num_public,
    num_challenges,
    "shape_circuit"
  );

  let t0 = Instant::now();
  let (pk, vk) =
    NeutronNovaZkSNARK::<E>::setup(&shape_circuit, &DummyCircuit::<E>::default(), num_circuits)
      .unwrap();
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");

  // Build the step circuits — each represents one video frame.
  let t0 = Instant::now();
  let step_circuits: Vec<ExampleVideoEditCircuit<<E as Engine>::Scalar>> = (0..num_circuits)
    .into_par_iter()
    .map(|i| {
      ExampleVideoEditCircuit::<<E as Engine>::Scalar>::new(
        generate_random_image(image_dims, i as u64),
        i as u64,
      )
    })
    .collect();
  info!(elapsed_ms = t0.elapsed().as_millis(), "generate_witness");

  let core_circuit = DummyCircuit::<E>::default();

  let t0 = Instant::now();
  let snark = NeutronNovaZkSNARK::prove(&pk, &step_circuits, &core_circuit, false).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "prove");

  let t0 = Instant::now();
  let result = snark.verify(&vk, num_circuits).unwrap();
  let verify_ms = t0.elapsed().as_millis();
  let (public_values_step, public_values_core): (Vec<_>, Vec<_>) = result;
  info!(elapsed_ms = verify_ms, "verify");

  let snark_bytes = bincode::serialize(&snark).unwrap().len();
  info!(bytes = snark_bytes, "snark_size");
  let public_values_bytes =
    bincode::serialize(&(public_values_step.as_slice(), public_values_core.as_slice()))
      .unwrap()
      .len();
  info!(bytes = public_values_bytes, "public_values_size");

  info!(
    num_step_circuits = public_values_step.len(),
    "verification successful"
  );
  drop(root_span);
}
