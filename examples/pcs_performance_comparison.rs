use ff::Field;
use spartan2::{
  provider::{Bn254Engine, Bn254KzgEngine, T256HyraxEngine, pcs::kzg_pc::KzgPCS},
  traits::{Engine, pcs::PCSEngineTrait},
};
use std::{
  env,
  hint::black_box,
  time::{Duration, Instant},
};

const HYRAX_WIDTH: usize = 2048;
const DEFAULT_PTAU_PATH: &str = "video_data/ppot_0080_24.ptau";
const DEFAULT_SIZES: &[usize] = &[1 << 12, 1 << 14, 1 << 16, 1 << 18];
const DEFAULT_WARMUPS: usize = 1;
const DEFAULT_RUNS: usize = 5;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let sizes = parse_sizes();
  let hyrax_width = parse_hyrax_width()?;
  let warmups = parse_usize_env("PCS_BENCH_WARMUPS", DEFAULT_WARMUPS);
  let runs = parse_usize_env("PCS_BENCH_RUNS", DEFAULT_RUNS);
  let ptau_path = env::var("PCS_BENCH_PTAU").unwrap_or_else(|_| DEFAULT_PTAU_PATH.to_string());

  println!("PCS commitment benchmark");
  println!("sizes={sizes:?}, hyrax_width={hyrax_width}, warmups={warmups}, runs={runs}");
  println!("ptau_path={ptau_path}");
  println!(
    "{:<14} {:>10} {:>10} {:>12} {:>12} {:>14}",
    "engine", "n", "setup_ms", "avg_ms", "best_ms", "evals/sec"
  );

  for n in sizes {
    bench_hyperkzg(&ptau_path, n, warmups, runs)?;
    bench_engine::<Bn254Engine>("bn254-hyrax", n, hyrax_width, warmups, runs)?;
    bench_engine_unblinded::<Bn254Engine>("bn254-hyrax-raw", n, hyrax_width, warmups, runs)?;
    bench_engine::<T256HyraxEngine>("t256-hyrax", n, hyrax_width, warmups, runs)?;
    bench_engine_unblinded::<T256HyraxEngine>("t256-hyrax-raw", n, hyrax_width, warmups, runs)?;
  }

  Ok(())
}

fn bench_hyperkzg(
  ptau_path: &str,
  n: usize,
  warmups: usize,
  runs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
  type E = Bn254KzgEngine;

  let mut rng = rand::thread_rng();
  let poly = (0..n)
    .map(|_| <E as Engine>::Scalar::random(&mut rng))
    .collect::<Vec<_>>();

  let setup_start = Instant::now();
  let (ck, _vk) = KzgPCS::<E>::setup_from_ptau_file(ptau_path, b"pcs_bench_ck", n)?;
  let setup_elapsed = setup_start.elapsed();

  let blind = <E as Engine>::PCS::blind(&ck, n);

  for _ in 0..warmups {
    let comm = <E as Engine>::PCS::commit(&ck, &poly, &blind, false)?;
    black_box(comm);
  }

  let mut total = Duration::ZERO;
  let mut best: Option<Duration> = None;
  for _ in 0..runs {
    let start = Instant::now();
    let comm = <E as Engine>::PCS::commit(&ck, &poly, &blind, false)?;
    black_box(comm);
    let elapsed = start.elapsed();
    total += elapsed;
    best = Some(best.map_or(elapsed, |current| current.min(elapsed)));
  }

  let avg_secs = total.as_secs_f64() / runs as f64;
  let evals_per_sec = n as f64 / avg_secs;
  println!(
    "{:<14} {:>10} {:>10.3} {:>12.3} {:>12.3} {:>14.0}",
    "bn254-hyperkzg",
    n,
    millis(setup_elapsed),
    avg_secs * 1_000.0,
    millis(best.unwrap_or_default()),
    evals_per_sec
  );

  Ok(())
}

fn bench_engine<E: Engine>(
  name: &str,
  n: usize,
  width: usize,
  warmups: usize,
  runs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
  let mut rng = rand::thread_rng();
  let poly = (0..n)
    .map(|_| E::Scalar::random(&mut rng))
    .collect::<Vec<_>>();

  let setup_start = Instant::now();
  let (ck, _vk) = E::PCS::setup(b"pcs_bench_ck", n, width);
  E::PCS::precompute_ck(&ck);
  let setup_elapsed = setup_start.elapsed();

  let blind = E::PCS::blind(&ck, n);

  for _ in 0..warmups {
    let comm = E::PCS::commit(&ck, &poly, &blind, false)?;
    black_box(comm);
  }

  let mut total = Duration::ZERO;
  let mut best: Option<Duration> = None;
  for _ in 0..runs {
    let start = Instant::now();
    let comm = E::PCS::commit(&ck, &poly, &blind, false)?;
    black_box(comm);
    let elapsed = start.elapsed();
    total += elapsed;
    best = Some(best.map_or(elapsed, |current| current.min(elapsed)));
  }

  let avg_secs = total.as_secs_f64() / runs as f64;
  let evals_per_sec = n as f64 / avg_secs;
  println!(
    "{:<14} {:>10} {:>10.3} {:>12.3} {:>12.3} {:>14.0}",
    name,
    n,
    millis(setup_elapsed),
    avg_secs * 1_000.0,
    millis(best.unwrap_or_default()),
    evals_per_sec
  );

  Ok(())
}

fn bench_engine_unblinded<E: Engine>(
  name: &str,
  n: usize,
  width: usize,
  warmups: usize,
  runs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
  let mut rng = rand::thread_rng();
  let poly = (0..n)
    .map(|_| E::Scalar::random(&mut rng))
    .collect::<Vec<_>>();

  let setup_start = Instant::now();
  let (ck, _vk) = E::PCS::setup(b"pcs_bench_ck", n, width);
  E::PCS::precompute_ck(&ck);
  let setup_elapsed = setup_start.elapsed();

  for _ in 0..warmups {
    let comm = E::PCS::commit_without_blind(&ck, &poly, false)?;
    black_box(comm);
  }

  let mut total = Duration::ZERO;
  let mut best: Option<Duration> = None;
  for _ in 0..runs {
    let start = Instant::now();
    let comm = E::PCS::commit_without_blind(&ck, &poly, false)?;
    black_box(comm);
    let elapsed = start.elapsed();
    total += elapsed;
    best = Some(best.map_or(elapsed, |current| current.min(elapsed)));
  }

  let avg_secs = total.as_secs_f64() / runs as f64;
  let evals_per_sec = n as f64 / avg_secs;
  println!(
    "{:<14} {:>10} {:>10.3} {:>12.3} {:>12.3} {:>14.0}",
    name,
    n,
    millis(setup_elapsed),
    avg_secs * 1_000.0,
    millis(best.unwrap_or_default()),
    evals_per_sec
  );

  Ok(())
}

fn parse_sizes() -> Vec<usize> {
  env::var("PCS_BENCH_SIZES")
    .ok()
    .map(|raw| {
      raw
        .split(',')
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .collect::<Vec<_>>()
    })
    .filter(|sizes| !sizes.is_empty())
    .unwrap_or_else(|| DEFAULT_SIZES.to_vec())
}

fn parse_usize_env(name: &str, default: usize) -> usize {
  env::var(name)
    .ok()
    .and_then(|raw| raw.parse::<usize>().ok())
    .filter(|value| *value > 0)
    .unwrap_or(default)
}

fn parse_hyrax_width() -> Result<usize, Box<dyn std::error::Error>> {
  let width = parse_usize_env("PCS_BENCH_HYRAX_WIDTH", HYRAX_WIDTH);
  Ok(width)
}

fn millis(duration: Duration) -> f64 {
  duration.as_secs_f64() * 1_000.0
}
