// NeutronNova gaussian blurring (streaming). Folds proofs for each channel (R/G/B) of each frame.
//
// Run with:
//   RUST_LOG=neutron_nova_streaming_blurring=info,spartan2::neutronnova_zk_streaming=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_blurring --release

#![allow(non_snake_case)]
#[path = "circuits/dummy_circuit.rs"]
mod dummy_circuit;
#[path = "circuits/gaussian_blur_circuit.rs"]
mod gaussian_blur_circuit;

use dummy_circuit::DummyCircuit;
use gaussian_blur_circuit::GaussianBlurCircuit;
use rayon::prelude::*;
use spartan2::{
  bellpepper::{r1cs::SpartanShape, shape_cs::ShapeCS},
  neutronnova_zk_streaming::NeutronNovaZkSNARK,
  provider::Bn254KzgEngine,
  traits::Engine,
};
use std::{env, time::Instant};
use tracing::{info, info_span};

const CHANNELS: [&str; 3] = ["R", "G", "B"];
const NUM_FRAMES: usize = 4;
const NUM_CIRCUITS: usize = NUM_FRAMES * 3;
const IMAGE_DIMS: (usize, usize) = (1280, 720);

fn main() {
  let _ = tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  type E = Bn254KzgEngine;

  let channel_path_format = env::var("CHANNEL_PATH_FORMAT")
    .unwrap_or_else(|_| "video_data/decomposed_frame_channels/{channel}_{}.png".to_string());

  let root_span = info_span!(
    "bench",
    num_circuits = NUM_CIRCUITS,
    num_frames = NUM_FRAMES,
    image_height = IMAGE_DIMS.0,
    image_width = IMAGE_DIMS.1,
  )
  .entered();
  info!(
    num_circuits = NUM_CIRCUITS,
    num_frames = NUM_FRAMES,
    image_height = IMAGE_DIMS.0,
    image_width = IMAGE_DIMS.1,
    "starting NeutronNova streaming blurring benchmark"
  );

  // Use a dummy circuit of the right shape to derive the R1CS constraints and keys.
  let shape_circuit =
    GaussianBlurCircuit::<<E as Engine>::Scalar>::new(&channel_path_format, "R", 1);
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

  // Build the step circuits — each represents one channel of one video frame.
  // Ordering: (frame 1, R), (frame 1, G), (frame 1, B), (frame 2, R), ...
  let frame_offset: u64 = env::var("SNARK_EDITING_FRAME_OFFSET")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);
  let t0 = Instant::now();
  let step_circuits: Vec<GaussianBlurCircuit<<E as Engine>::Scalar>> = (0..NUM_CIRCUITS)
    .into_par_iter()
    .map(|i| {
      let frame_idx = (i / 3) as u64 + 1 + frame_offset;
      let channel = CHANNELS[i % 3];
      GaussianBlurCircuit::<<E as Engine>::Scalar>::new(&channel_path_format, channel, frame_idx)
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
