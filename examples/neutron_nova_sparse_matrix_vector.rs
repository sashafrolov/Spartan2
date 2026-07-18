// NeutronNova example for the sparse vector-matrix-vector circuit.
//
// Run with:
//   RUST_LOG=neutron_nova_sparse_matrix_vector=info,\
//   spartan2::neutronnova_zk_ram_optimized=info \
//   RUSTFLAGS="-C target-cpu=native" \
//   cargo run --example neutron_nova_sparse_matrix_vector --release

#[path = "circuits/dummy_circuit.rs"]
mod dummy_circuit;
#[path = "circuits/sparse_matrix_vector_product_circuit.rs"]
mod sparse_matrix_vector_product_circuit;

use std::time::Instant;

use dummy_circuit::DummyCircuit;
use ff::PrimeField;
use rand::{Rng, SeedableRng, rngs::StdRng};
use sparse_matrix_vector_product_circuit::{
  SparseMatrixEntry, SparseProductConfig, SparseVectorMatrixVectorCircuit,
};
use spartan2::{
  bellpepper::{r1cs::SpartanShape, shape_cs::ShapeCS},
  neutronnova_zk_ram_optimized::NeutronNovaZkSNARK,
  provider::T256HyraxEngine,
  traits::Engine,
};
use tracing::{info, info_span};

// Constants controlling the circuit shape and the number of circuits to fold.
const NUM_CIRCUITS: usize = 2;
const IMAGE_DIMS: (usize, usize) = (3, 5);
const MAX_DELTA_LENGTH: usize = 4;
const BATCH_SIZE: usize = 3;
const INPUT_SEED_BASE: u64 = 0x5a17_0000;
const CHALLENGE_SEED_BASE: u64 = 0x5a17_1000;

fn indexed_seed(base: u64, index: usize) -> u64 {
  base
    .checked_add(u64::try_from(index).expect("circuit index does not fit in u64"))
    .expect("challenge seed overflow")
}

fn random_scalar<Scalar: PrimeField>(rng: &mut StdRng) -> Scalar {
  Scalar::from_u128(rng.gen_range(1..(1u128 << 127)))
}

fn generate_random_circuit<Scalar: PrimeField>(
  config: SparseProductConfig,
  input_seed: u64,
  challenge_seed: u64,
) -> SparseVectorMatrixVectorCircuit<Scalar> {
  let mut rng = StdRng::seed_from_u64(input_seed);

  let left_vector = (0..config.image_height)
    .map(|_| random_scalar(&mut rng))
    .collect();
  let right_vector = (0..config.image_width)
    .map(|_| random_scalar(&mut rng))
    .collect();

  // Each group of BATCH_SIZE entries shares a row, matching the circuit's
  // row-local batch encoding. Filling every slot makes the generated workload
  // scale as MAX_DELTA_LENGTH * BATCH_SIZE.
  let mut entries = Vec::with_capacity(config.num_nonzero_entries());
  for _ in 0..config.max_delta_length {
    let row = rng.gen_range(0..config.image_height);
    for _ in 0..config.batch_size {
      entries.push(SparseMatrixEntry::new(
        row,
        rng.gen_range(0..config.image_width),
        random_scalar(&mut rng),
      ));
    }
  }

  SparseVectorMatrixVectorCircuit::from_entries(
    config,
    entries,
    left_vector,
    right_vector,
    challenge_seed,
  )
  .unwrap()
}

fn main() {
  let _ = tracing_subscriber::fmt()
    .with_target(false)
    .with_ansi(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  type E = T256HyraxEngine;
  type Scalar = <E as Engine>::Scalar;

  assert!(NUM_CIRCUITS > 0);
  let config = SparseProductConfig::new(IMAGE_DIMS.0, IMAGE_DIMS.1, MAX_DELTA_LENGTH, BATCH_SIZE);

  let root_span = info_span!(
    "bench",
    num_circuits = NUM_CIRCUITS,
    image_height = IMAGE_DIMS.0,
    image_width = IMAGE_DIMS.1,
    max_delta_length = MAX_DELTA_LENGTH,
    batch_size = BATCH_SIZE,
  )
  .entered();
  info!(
    num_circuits = NUM_CIRCUITS,
    image_height = IMAGE_DIMS.0,
    image_width = IMAGE_DIMS.1,
    max_delta_length = MAX_DELTA_LENGTH,
    batch_size = BATCH_SIZE,
    "starting NeutronNova sparse matrix-vector benchmark"
  );

  // Use a circuit of the configured shape to derive the R1CS constraints and keys.
  let shape_circuit =
    generate_random_circuit::<Scalar>(config, INPUT_SEED_BASE, CHALLENGE_SEED_BASE);
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
  info!(elapsed_ms = t0.elapsed().as_millis(), "setup");

  let t0 = Instant::now();
  let step_circuits: Vec<SparseVectorMatrixVectorCircuit<Scalar>> = (0..NUM_CIRCUITS)
    .map(|index| {
      generate_random_circuit::<Scalar>(
        config,
        indexed_seed(INPUT_SEED_BASE, index),
        indexed_seed(CHALLENGE_SEED_BASE, index),
      )
    })
    .collect();
  info!(elapsed_ms = t0.elapsed().as_millis(), "generate_witness");

  let core_circuit = DummyCircuit::<E>::default();

  let t0 = Instant::now();
  let snark = NeutronNovaZkSNARK::<E>::prove(&pk, &step_circuits, &core_circuit, false).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "prove");

  let t0 = Instant::now();
  let (public_values_step, _public_values_core): (Vec<Vec<Scalar>>, Vec<Scalar>) =
    snark.verify(&vk, NUM_CIRCUITS).unwrap();
  info!(elapsed_ms = t0.elapsed().as_millis(), "verify");

  // Bind the proof's public IO to the generated sparse-product statements.
  for (index, actual) in public_values_step.iter().enumerate() {
    assert_eq!(actual, &step_circuits[index].expected_public_values());
  }

  let snark_bytes = bincode::serialize(&snark).unwrap().len();
  info!(bytes = snark_bytes, "snark_size");
  info!(
    num_step_circuits = public_values_step.len(),
    "verification successful"
  );
  drop(root_span);
}
