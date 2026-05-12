// NeutronNova grayscaling with the non streaming version. Fold a bunch of keyframe proofs together.
// This is meant to give a baseline of the best possible throughput (generally for 128 instances on a 256 GB machine)
// attainable from just using RAM. This is the best you can do if you care a little less about succinctness.
//
// Run with:
//   RUST_LOG=neutron_nova_grayscaling=info,spartan2::neutronnova_zk_ram_optimized=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_grayscaling --release

#![allow(non_snake_case)]
#[path = "circuits/grayscale_circuit.rs"]
mod grayscale_circuit;
#[path = "circuits/dummy_circuit.rs"]
mod dummy_circuit;

use dummy_circuit::DummyCircuit;
use grayscale_circuit::GrayscaleCircuit;
use spartan2::{
  neutronnova_zk_ram_optimized::NeutronNovaZkSNARK,
  provider::T256HyraxEngine,
  traits::Engine,
};
use rayon::prelude::*;
use std::time::Instant;
use std::env;
use tracing::{info, info_span};

const NUM_CIRCUITS: usize = 4;
const IMAGE_DIMS: (usize, usize) = (1280, 720);

fn main() {
  let _ = tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  type E = T256HyraxEngine;

  let frame_path_format = env::var("FRAME_PATH_FORMAT")
    .unwrap_or_else(|_| "video_data/decomposed_frames/frame_{}.png".to_string());

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
    "starting NeutronNova grayscaling benchmark"
  );

  // Use a dummy circuit of the right shape to derive the R1CS constraints and keys.
  let shape_circuit =
    GrayscaleCircuit::<<E as Engine>::Scalar>::new(&frame_path_format, 1);

  let t0 = Instant::now();
  let (pk, vk) =
    NeutronNovaZkSNARK::<E>::setup(&shape_circuit, &DummyCircuit::<E>::default(), NUM_CIRCUITS)
      .unwrap();
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");

  // Build the step circuits — each represents one video frame.
  let frame_offset: u64 = env::var("SNARK_EDITING_FRAME_OFFSET")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);
  let t0 = Instant::now();
  let step_circuits: Vec<GrayscaleCircuit<<E as Engine>::Scalar>> = (0..NUM_CIRCUITS)
    .into_par_iter()
    .map(|i| GrayscaleCircuit::<<E as Engine>::Scalar>::new(&frame_path_format, (i+1) as u64 + frame_offset))
    .collect();
  info!(elapsed_ms = t0.elapsed().as_millis(), "generate_witness");

  let core_circuit = DummyCircuit::<E>::default();

  let t0 = Instant::now();
  let snark =
    NeutronNovaZkSNARK::prove(&pk, &step_circuits, &core_circuit, false).unwrap();
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
