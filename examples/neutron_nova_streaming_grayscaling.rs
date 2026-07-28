// NeutronNova grayscaling with the streaming version. Fold a bunch of keyframe proofs together.
//
// Run with:
//   RUST_LOG=neutron_nova_streaming_grayscaling=info,spartan2::neutronnova_zk_streaming=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_grayscaling --release
//
// Verification is measured repeatedly across a fixed ladder of rayon thread counts (the default
// pool, then 16, 8, 4, and 1) to show how the verifier scales. Setup, witness generation, and prove
// always use the global pool, so only the verifier's scaling is isolated.

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
/// Thread counts verification is benchmarked at. `None` is rayon's default global pool.
const VERIFY_THREAD_LADDER: [Option<usize>; 5] = [None, Some(16), Some(8), Some(4), Some(1)];

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

  // Untimed warm-up so the first measured entry in the ladder below is not charged for one-time
  // costs (page faults, lazy initialization) that later entries avoid. It runs on the default
  // global pool, matching the ladder's `None` entry.
  let (public_values_step, public_values_core): (Vec<_>, Vec<_>) =
    snark.verify(&vk, NUM_CIRCUITS).unwrap();

  for threads in VERIFY_THREAD_LADDER {
    // The pool is built outside the timed region so spawning its workers is not charged to
    // verification. `install` makes it the current pool for the closure, so the verifier's
    // nested rayon work (and arkworks', which is compiled with its `parallel` feature) runs on
    // these threads rather than the global pool.
    let pool = threads.map(|thread_count| {
      rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .expect("failed to build verification thread pool")
    });
    let thread_count = pool
      .as_ref()
      .map_or_else(rayon::current_num_threads, |pool| {
        pool.current_num_threads()
      });

    let t0 = Instant::now();
    match &pool {
      Some(pool) => pool.install(|| snark.verify(&vk, NUM_CIRCUITS)),
      None => snark.verify(&vk, NUM_CIRCUITS),
    }
    .unwrap();
    let verify_ms = t0.elapsed().as_millis();

    info!(
      elapsed_ms = verify_ms,
      threads = thread_count,
      default_pool = threads.is_none(),
      "verify"
    );
  }

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
