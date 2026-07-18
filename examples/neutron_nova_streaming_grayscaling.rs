// NeutronNova grayscaling with the streaming version. Fold a bunch of keyframe proofs together.
//
// Run with:
//   RUST_LOG=neutron_nova_streaming_grayscaling=info,spartan2::neutronnova_zk_streaming=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_grayscaling --release

#![allow(non_snake_case)]
#[path = "circuits/dummy_circuit.rs"]
mod dummy_circuit;
#[path = "circuits/grayscale_circuit.rs"]
mod grayscale_circuit;

use dummy_circuit::DummyCircuit;
use grayscale_circuit::GrayscaleCircuit;
use rayon::prelude::*;
use spartan2::{
  bellpepper::{r1cs::SpartanShape, shape_cs::ShapeCS},
  neutronnova_zk_streaming::NeutronNovaZkSNARK,
  provider::Bn254KzgEngine,
  traits::Engine,
};
use std::{env, time::Instant};
use tracing::{info, info_span};

const NUM_CIRCUITS: usize = 4;
const IMAGE_DIMS: (usize, usize) = (1280, 720);

fn main() {
  let _ = tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  type E = Bn254KzgEngine;

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
    "starting NeutronNova streaming grayscaling benchmark"
  );

  // Use a dummy circuit of the right shape to derive the R1CS constraints and keys.
  let shape_circuit = GrayscaleCircuit::<<E as Engine>::Scalar>::new(&frame_path_format, 1);
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
  let frame_offset: u64 = env::var("SNARK_EDITING_FRAME_OFFSET")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);
  let t0 = Instant::now();
  let step_circuits: Vec<GrayscaleCircuit<<E as Engine>::Scalar>> = (0..NUM_CIRCUITS)
    .into_par_iter()
    .map(|i| {
      GrayscaleCircuit::<<E as Engine>::Scalar>::new(
        &frame_path_format,
        (i + 1) as u64 + frame_offset,
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
