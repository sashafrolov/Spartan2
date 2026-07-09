// NeutronNova Freivalds editing. Fold a bunch of keyframe proofs together.
//
// Run with:
//   RUST_LOG=neutron_nova_streaming_video_editing=info,spartan2::neutronnova_zk_streaming=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_video_editing --release
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
  neutronnova_zk_streaming::NeutronNovaZkSNARK,
  provider::T256HyraxEngine,
  traits::Engine,
};
use std::time::Instant;
use tracing::{info, info_span};

const KERNEL_SIZE: usize = 9;
const RADIUS: usize = KERNEL_SIZE / 2;
const NUM_CIRCUITS: usize = 4;
const IMAGE_DIMS: (usize, usize) = (1280, 720);

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
    ExampleVideoEditCircuit::<<E as Engine>::Scalar>::new(generate_random_image(IMAGE_DIMS, 0), 0);
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
    NeutronNovaZkSNARK::<E>::setup(&shape_circuit, &DummyCircuit::<E>::default(), NUM_CIRCUITS)
      .unwrap();
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");

  // Build the step circuits — each represents one video frame.
  let t0 = Instant::now();
  let step_circuits: Vec<ExampleVideoEditCircuit<<E as Engine>::Scalar>> = (0..NUM_CIRCUITS)
    .into_par_iter()
    .map(|i| {
      ExampleVideoEditCircuit::<<E as Engine>::Scalar>::new(
        generate_random_image(IMAGE_DIMS, i as u64),
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
  let result = snark.verify(&vk, NUM_CIRCUITS).unwrap();
  let verify_ms = t0.elapsed().as_millis();
  let (public_values_step, _public_values_core): (Vec<_>, Vec<_>) = result;
  info!(elapsed_ms = verify_ms, "verify");

  let snark_bytes = bincode::serialize(&snark).unwrap().len();
  info!(bytes = snark_bytes, "snark_size");

  info!(
    num_step_circuits = public_values_step.len(),
    "verification successful"
  );
  drop(root_span);
}
