// Standalone example: fold many SHA-256 circuits into one proof using streaming NeutronNova.
//
// Run with:
//   RUST_LOG=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_sha256_example --release
//
// Adjust NUM_CIRCUITS and PREIMAGE_LEN to experiment with different batch sizes / input lengths.
//
// Verification is measured repeatedly across a fixed ladder of rayon thread counts (the default
// pool, then 16, 8, 4, and 1) to show how the verifier scales. Setup, witness generation, and prove
// always use the global pool, so only the verifier's scaling is isolated.

#[path = "circuits/sha256_circuit.rs"]
mod sha256_circuit;

use sha256_circuit::Sha256Circuit;
use spartan2::{neutronnova_zk_streaming::NeutronNovaZkSNARK, provider::Bn254KzgEngine};
use std::time::Instant;
use tracing::{info, info_span};

const NUM_CIRCUITS: usize = 32;
const PREIMAGE_LEN: usize = 32 * 32;
/// Thread counts verification is benchmarked at. `None` is rayon's default global pool.
const VERIFY_THREAD_LADDER: [Option<usize>; 5] = [None, Some(16), Some(8), Some(4), Some(1)];

fn main() {
  let _ = tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  type E = Bn254KzgEngine;

  let root_span = info_span!(
    "bench",
    num_circuits = NUM_CIRCUITS,
    preimage_len = PREIMAGE_LEN
  )
  .entered();
  info!(
    num_circuits = NUM_CIRCUITS,
    preimage_len = PREIMAGE_LEN,
    "starting NeutronNova streaming benchmark"
  );

  // Use a dummy circuit of the right shape to derive the R1CS constraints and keys.
  let shape_circuit = Sha256Circuit::<E> {
    preimage: vec![0u8; PREIMAGE_LEN],
    _p: Default::default(),
  };

  let t0 = Instant::now();
  let (pk, vk) =
    NeutronNovaZkSNARK::<E>::setup(&shape_circuit, &shape_circuit, NUM_CIRCUITS).unwrap();
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");

  // Build the actual step circuits — each gets a distinct preimage byte.
  let t0 = Instant::now();
  let step_circuits: Vec<Sha256Circuit<E>> = (0..NUM_CIRCUITS)
    .map(|i| Sha256Circuit::<E> {
      preimage: vec![i as u8; PREIMAGE_LEN],
      _p: Default::default(),
    })
    .collect();
  info!(elapsed_ms = t0.elapsed().as_millis(), "generate_witness");

  // Use the first circuit as the core circuit (it connects the folded batch).
  let core_circuit = &step_circuits[0];

  let t0 = Instant::now();
  let snark = NeutronNovaZkSNARK::prove(&pk, &step_circuits, core_circuit, true).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "prove");

  // Untimed warm-up so the first measured entry in the ladder below is not charged for one-time
  // costs (page faults, lazy initialization) that later entries avoid. It runs on the default
  // global pool, matching the ladder's `None` entry.
  let (public_values_step, _public_values_core): (Vec<_>, Vec<_>) =
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

  info!(
    num_step_circuits = public_values_step.len(),
    "verification successful"
  );
  drop(root_span);
}
