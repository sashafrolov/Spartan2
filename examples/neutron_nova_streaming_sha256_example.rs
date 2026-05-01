// Standalone example: fold many SHA-256 circuits into one proof using streaming NeutronNova.
//
// Run with:
//   RUST_LOG=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_sha256_example --release
//
// Adjust NUM_CIRCUITS and PREIMAGE_LEN to experiment with different batch sizes / input lengths.

#[path = "circuits/sha256_circuit.rs"]
mod sha256_circuit;

use sha256_circuit::Sha256Circuit;
use spartan2::{
  neutronnova_zk_streaming::NeutronNovaZkSNARK,
  provider::T256HyraxEngine,
};
use std::time::Instant;
use tracing::{info, info_span};

const NUM_CIRCUITS: usize = 32;
const PREIMAGE_LEN: usize = 32 * 32;

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
  let prep = NeutronNovaZkSNARK::<E>::prep_prove(&pk, &step_circuits, core_circuit, true).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "prep_prove");

  let t0 = Instant::now();
  let (snark, _prep) =
    NeutronNovaZkSNARK::prove(&pk, &step_circuits, core_circuit, prep, true).unwrap();
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
