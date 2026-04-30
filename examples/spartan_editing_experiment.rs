//! Generic circuit for verifying the performance of implementing convolution-
//! type transforms using Freivald's algorithm.
//!
//! Run with: `RUST_LOG=info cargo run --release --example spartan_editing_experiment`
#![allow(non_snake_case)]
#[path = "circuits/freivalds_conv_circuit.rs"]
mod freivalds_conv_circuit;

use freivalds_conv_circuit::{ExampleVideoEditCircuit, generate_random_image};
use spartan2::{
  provider::T256HyraxEngine,
  spartan::SpartanSNARK,
  traits::{Engine, snark::R1CSSNARKTrait},
};
use std::time::Instant;
use tracing::{info, info_span};
use tracing_subscriber::EnvFilter;

type E = T256HyraxEngine;

const KERNEL_SIZE: usize = 9;
const RADIUS: usize = KERNEL_SIZE / 2;

fn main() {
  tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(EnvFilter::from_default_env())
    .init();

  let image_dims = (720usize, 1280usize);

  let test_image = generate_random_image(image_dims, 0);
  let circuit = ExampleVideoEditCircuit::<<E as Engine>::Scalar>::new(test_image, 0);

  let root_span = info_span!("bench", "image").entered();
  info!(
    "======= image_size is = {} x {} pixels =======",
    image_dims.0, image_dims.1
  );

  // SETUP
  let t0 = Instant::now();
  let (pk, vk) = SpartanSNARK::<E>::setup(circuit.clone()).expect("setup failed");
  let setup_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = setup_ms, "setup");
  info!("Constraint count is: {}", pk.sizes()[0]);

  // PREPARE
  let t0 = Instant::now();
  let prep_snark =
    SpartanSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
  let prep_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prep_ms, "prep_prove");

  // PROVE
  let t0 = Instant::now();
  let (proof, _prep_snark) =
    SpartanSNARK::<E>::prove(&pk, circuit.clone(), prep_snark, false).expect("prove failed");
  let prove_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = prove_ms, "prove");

  // VERIFY
  let t0 = Instant::now();
  proof.verify(&vk).expect("verify errored");
  let verify_ms = t0.elapsed().as_millis();
  info!(elapsed_ms = verify_ms, "verify");

  // Summary
  info!(
    "SUMMARY dims={}x{}, setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
    image_dims.0, image_dims.1, setup_ms, prep_ms, prove_ms, verify_ms
  );
  drop(root_span);
}
