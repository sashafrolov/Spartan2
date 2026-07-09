//! Benchmark PCS authentication for decomposed video frame channels.
//!
//! Run with:
//!   RUSTFLAGS="-C target-cpu=native" cargo run --release --example video_pcs_authentication_benchmark
//!
//! Useful environment variables:
//!   VIDEO_CHANNEL_DIR=video_data/decomposed_frame_channels
//!   VIDEO_PCS_MAX_FILES=30
//!   VIDEO_PCS_COMMITMENT_WIDTH=2048
//!   VIDEO_PCS_PRINT_PER_CHANNEL=1

use ff::PrimeField;
use image::ImageReader;
use rand::{Rng, SeedableRng, rngs::StdRng};
use spartan2::{
  provider::T256HyraxEngine,
  traits::{Engine, pcs::PCSEngineTrait, transcript::TranscriptEngineTrait},
};
use std::{
  env,
  error::Error,
  fmt::Write as _,
  fs,
  hint::black_box,
  io,
  path::{Path, PathBuf},
  time::{Duration, Instant},
};

const DEFAULT_CHANNEL_DIR: &str = "video_data/decomposed_frame_channels";
const BYTES_PER_FIELD_ELEMENT: usize = 30;
const DEFAULT_COMMITMENT_WIDTH: usize = 2048;
const CIRCUIT_INPUT_CHALLENGE_OFFSET: u64 = 3;
// The circuits use the offset above for their single Horner interpolation
// challenge. The PCS API opens multilinear polynomials, so this benchmark uses
// a separate deterministic full MLE point for opening proofs.
const PCS_OPENING_POINT_OFFSET: u64 = 7;

type Commitment<E> = <<E as Engine>::PCS as PCSEngineTrait<E>>::Commitment;
type Blind<E> = <<E as Engine>::PCS as PCSEngineTrait<E>>::Blind;
type EvaluationArgument<E> = <<E as Engine>::PCS as PCSEngineTrait<E>>::EvaluationArgument;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Channel {
  R,
  G,
  B,
}

impl Channel {
  fn parse(value: &str) -> Option<Self> {
    match value {
      "R" => Some(Self::R),
      "G" => Some(Self::G),
      "B" => Some(Self::B),
      _ => None,
    }
  }

  fn as_str(self) -> &'static str {
    match self {
      Self::R => "R",
      Self::G => "G",
      Self::B => "B",
    }
  }

  fn sort_index(self) -> u8 {
    match self {
      Self::R => 0,
      Self::G => 1,
      Self::B => 2,
    }
  }

  fn seed_offset(self) -> u64 {
    self.sort_index() as u64
  }
}

#[derive(Clone, Debug)]
struct BenchmarkConfig {
  channel_dir: PathBuf,
  max_files: Option<usize>,
  requested_commitment_width: usize,
  print_per_channel: bool,
}

#[derive(Clone, Debug)]
struct ChannelFile {
  path: PathBuf,
  frame_index: u64,
  channel: Channel,
}

#[derive(Debug)]
struct ChannelPolynomial<Scalar: PrimeField> {
  file: ChannelFile,
  width: u32,
  height: u32,
  coeffs: Vec<Scalar>,
  padded_coeffs: Vec<Scalar>,
  circuit_challenge: Scalar,
  pcs_opening_point: Vec<Scalar>,
}

#[derive(Debug)]
struct CommitmentRecord<E: Engine> {
  commitment: Commitment<E>,
  blind: Blind<E>,
}

#[derive(Debug)]
struct OpeningRecord<E: Engine> {
  eval: E::Scalar,
  eval_blind: Blind<E>,
  eval_commitment: Commitment<E>,
  argument: EvaluationArgument<E>,
}

#[derive(Default)]
struct PhaseTotals {
  load_and_pack: Duration,
  setup: Duration,
  commit_blind: Duration,
  commit: Duration,
  circuit_horner_eval: Duration,
  prover_mle_eval: Duration,
  eval_blind: Duration,
  eval_commit: Duration,
  open: Duration,
  verifier_mle_eval: Duration,
  verifier_eval_commit: Duration,
  verify: Duration,
}

fn main() -> Result<(), Box<dyn Error>> {
  let _ = rayon::ThreadPoolBuilder::new()
    .num_threads(1)
    .build_global();

  let config = BenchmarkConfig::from_env()?;
  run_benchmark::<T256HyraxEngine>(config)
}

impl BenchmarkConfig {
  fn from_env() -> Result<Self, Box<dyn Error>> {
    Ok(Self {
      channel_dir: PathBuf::from(
        env::var("VIDEO_CHANNEL_DIR").unwrap_or_else(|_| DEFAULT_CHANNEL_DIR.to_string()),
      ),
      max_files: optional_env_usize("VIDEO_PCS_MAX_FILES")?,
      requested_commitment_width: env_usize(
        "VIDEO_PCS_COMMITMENT_WIDTH",
        DEFAULT_COMMITMENT_WIDTH,
      )?,
      print_per_channel: env_flag("VIDEO_PCS_PRINT_PER_CHANNEL"),
    })
  }
}

fn run_benchmark<E: Engine>(config: BenchmarkConfig) -> Result<(), Box<dyn Error>> {
  let wall_start = Instant::now();
  let mut totals = PhaseTotals::default();

  let mut files = discover_channel_files(&config.channel_dir)?;
  if let Some(max_files) = config.max_files {
    files.truncate(max_files);
  }
  if files.is_empty() {
    return Err(
      invalid_input(format!(
        "no R/G/B PNG channel files found in {}",
        config.channel_dir.display()
      ))
      .into(),
    );
  }

  let mut polynomials = Vec::with_capacity(files.len());
  for file in files {
    let t0 = Instant::now();
    let poly = read_channel_polynomial::<E::Scalar>(file)?;
    totals.load_and_pack += t0.elapsed();
    polynomials.push(poly);
  }

  let min_coeffs = polynomials.iter().map(|p| p.coeffs.len()).min().unwrap();
  let max_coeffs = polynomials.iter().map(|p| p.coeffs.len()).max().unwrap();
  let min_padded = polynomials
    .iter()
    .map(|p| p.padded_coeffs.len())
    .min()
    .unwrap();
  let max_padded = polynomials
    .iter()
    .map(|p| p.padded_coeffs.len())
    .max()
    .unwrap();

  let commitment_width = config.requested_commitment_width.min(min_padded);
  if commitment_width == 0 || !commitment_width.is_power_of_two() {
    return Err(
      invalid_input(format!(
        "VIDEO_PCS_COMMITMENT_WIDTH must resolve to a positive power of two, got {commitment_width}"
      ))
      .into(),
    );
  }

  let t0 = Instant::now();
  let (ck, vk) = E::PCS::setup(b"video_pcs_auth_poly", max_padded, commitment_width);
  E::PCS::precompute_ck(&ck);
  let (ck_eval, _) = E::PCS::setup(b"video_pcs_auth_eval", 1, 1);
  E::PCS::precompute_ck(&ck_eval);
  totals.setup = t0.elapsed();

  let mut commitments: Vec<CommitmentRecord<E>> = Vec::with_capacity(polynomials.len());
  let mut total_commitment_bytes = 0usize;
  for poly in &polynomials {
    let t0 = Instant::now();
    let blind = E::PCS::blind(&ck, poly.padded_coeffs.len());
    totals.commit_blind += t0.elapsed();

    let t0 = Instant::now();
    let commitment = E::PCS::commit(
      &ck,
      black_box(&poly.padded_coeffs),
      black_box(&blind),
      false,
    )?;
    totals.commit += t0.elapsed();
    total_commitment_bytes += bincode::serialize(&commitment)?.len();

    commitments.push(CommitmentRecord { commitment, blind });
  }

  let mut circuit_evals = Vec::with_capacity(polynomials.len());
  for poly in &polynomials {
    let t0 = Instant::now();
    let eval = evaluate_circuit_horner(black_box(&poly.coeffs), black_box(&poly.circuit_challenge));
    totals.circuit_horner_eval += t0.elapsed();
    circuit_evals.push(black_box(eval));
  }

  let mut openings: Vec<OpeningRecord<E>> = Vec::with_capacity(polynomials.len());
  let mut prover_mle_evals = Vec::with_capacity(polynomials.len());
  let mut total_opening_bytes = 0usize;
  for (poly, record) in polynomials.iter().zip(commitments.iter()) {
    let t0 = Instant::now();
    let eval = evaluate_mle(
      black_box(&poly.padded_coeffs),
      black_box(&poly.pcs_opening_point),
    );
    totals.prover_mle_eval += t0.elapsed();
    prover_mle_evals.push(black_box(eval));

    let t0 = Instant::now();
    let eval_blind = E::PCS::blind(&ck_eval, 1);
    totals.eval_blind += t0.elapsed();

    let t0 = Instant::now();
    let eval_commitment = E::PCS::commit(&ck_eval, &[eval], &eval_blind, false)?;
    totals.eval_commit += t0.elapsed();

    let mut transcript = E::TE::new(b"video_pcs_auth_opening");
    let t0 = Instant::now();
    let argument = E::PCS::prove(
      &ck,
      &ck_eval,
      &mut transcript,
      &record.commitment,
      black_box(&poly.padded_coeffs),
      &record.blind,
      &poly.pcs_opening_point,
      &eval_commitment,
      &eval_blind,
    )?;
    totals.open += t0.elapsed();
    total_opening_bytes += bincode::serialize(&eval)?.len();
    total_opening_bytes += bincode::serialize(&eval_blind)?.len();
    total_opening_bytes += bincode::serialize(&argument)?.len();

    openings.push(OpeningRecord {
      eval,
      eval_blind,
      eval_commitment,
      argument,
    });
  }

  for ((poly, commitment), opening) in polynomials
    .iter()
    .zip(commitments.iter())
    .zip(openings.iter())
  {
    let t0 = Instant::now();
    let recomputed_eval = evaluate_mle(
      black_box(&poly.padded_coeffs),
      black_box(&poly.pcs_opening_point),
    );
    totals.verifier_mle_eval += t0.elapsed();
    if recomputed_eval != opening.eval {
      return Err(
        invalid_input(format!(
          "PCS evaluation mismatch for {}",
          poly.file.path.display()
        ))
        .into(),
      );
    }

    let t0 = Instant::now();
    let recomputed_eval_commitment =
      E::PCS::commit(&ck_eval, &[recomputed_eval], &opening.eval_blind, false)?;
    totals.verifier_eval_commit += t0.elapsed();
    if recomputed_eval_commitment != opening.eval_commitment {
      return Err(
        invalid_input(format!(
          "evaluation commitment mismatch for {}",
          poly.file.path.display()
        ))
        .into(),
      );
    }

    let mut transcript = E::TE::new(b"video_pcs_auth_opening");
    let t0 = Instant::now();
    E::PCS::verify(
      &vk,
      &ck_eval,
      &mut transcript,
      &commitment.commitment,
      &poly.pcs_opening_point,
      &recomputed_eval_commitment,
      &opening.argument,
    )?;
    totals.verify += t0.elapsed();
  }

  if config.print_per_channel {
    print_per_channel(&polynomials);
  }

  print_summary::<E>(
    &config,
    &polynomials,
    &totals,
    wall_start.elapsed(),
    commitment_width,
    min_coeffs,
    max_coeffs,
    min_padded,
    max_padded,
    total_commitment_bytes,
    total_opening_bytes,
    &circuit_evals,
    &prover_mle_evals,
  );

  Ok(())
}

fn discover_channel_files(dir: &Path) -> Result<Vec<ChannelFile>, Box<dyn Error>> {
  let mut files = Vec::new();
  for entry in fs::read_dir(dir)? {
    let path = entry?.path();
    if !path.is_file() || !has_png_extension(&path) {
      continue;
    }

    if let Some(file) = parse_channel_file(path)? {
      files.push(file);
    }
  }

  files.sort_by_key(|f| (f.frame_index, f.channel.sort_index()));
  Ok(files)
}

fn parse_channel_file(path: PathBuf) -> Result<Option<ChannelFile>, Box<dyn Error>> {
  let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
    return Ok(None);
  };
  let Some((channel_name, frame_name)) = stem.split_once('_') else {
    return Ok(None);
  };
  let Some(channel) = Channel::parse(channel_name) else {
    return Ok(None);
  };
  let frame_index = frame_name.parse::<u64>().map_err(|err| {
    invalid_input(format!(
      "failed to parse frame index from {}: {err}",
      path.display()
    ))
  })?;

  Ok(Some(ChannelFile {
    path,
    frame_index,
    channel,
  }))
}

fn read_channel_polynomial<Scalar: PrimeField>(
  file: ChannelFile,
) -> Result<ChannelPolynomial<Scalar>, Box<dyn Error>> {
  let image = ImageReader::open(&file.path)?.decode()?.into_luma8();
  let (width, height) = image.dimensions();
  if width == 0 || height == 0 {
    return Err(invalid_input(format!("empty image {}", file.path.display())).into());
  }

  let coeffs = pack_bytes_as_field_elements(image.as_raw());
  if coeffs.is_empty() {
    return Err(
      invalid_input(format!(
        "no polynomial coefficients for {}",
        file.path.display()
      ))
      .into(),
    );
  }

  let mut padded_coeffs = coeffs.clone();
  padded_coeffs.resize(coeffs.len().next_power_of_two(), Scalar::ZERO);

  let num_vars = padded_coeffs.len().trailing_zeros() as usize;
  let base_seed = circuit_seed_base(file.frame_index, file.channel);
  let circuit_challenge =
    deterministic_scalars(1, base_seed + CIRCUIT_INPUT_CHALLENGE_OFFSET).remove(0);
  let pcs_opening_point = deterministic_scalars(num_vars, base_seed + PCS_OPENING_POINT_OFFSET);

  Ok(ChannelPolynomial {
    file,
    width,
    height,
    coeffs,
    padded_coeffs,
    circuit_challenge,
    pcs_opening_point,
  })
}

fn pack_bytes_as_field_elements<Scalar: PrimeField>(bytes: &[u8]) -> Vec<Scalar> {
  let byte_base = Scalar::from_u128(1u128 << 8);
  bytes
    .chunks(BYTES_PER_FIELD_ELEMENT)
    .map(|chunk| {
      let mut scalar = Scalar::ZERO;
      let mut coeff = Scalar::ONE;
      for &byte in chunk {
        scalar += coeff * Scalar::from_u128(byte as u128);
        coeff *= byte_base;
      }
      scalar
    })
    .collect()
}

fn evaluate_circuit_horner<Scalar: PrimeField>(coeffs: &[Scalar], point: &Scalar) -> Scalar {
  let Some((&first, rest)) = coeffs.split_first() else {
    return Scalar::ZERO;
  };
  rest.iter().fold(first, |acc, coeff| acc * point + coeff)
}

fn evaluate_mle<Scalar: PrimeField>(evals: &[Scalar], point: &[Scalar]) -> Scalar {
  assert_eq!(evals.len(), 1usize << point.len());
  let mut work = evals.to_vec();
  let mut current_len = work.len();

  for r in point {
    let half = current_len / 2;
    for i in 0..half {
      let lo = work[i];
      let hi = work[half + i];
      work[i] = lo + *r * (hi - lo);
    }
    current_len = half;
  }

  work[0]
}

fn deterministic_scalars<Scalar: PrimeField>(length: usize, seed: u64) -> Vec<Scalar> {
  let mut rng = StdRng::seed_from_u64(seed);
  (0..length)
    .map(|_| Scalar::from_u128(rng.gen_range(0..(1u128 << 127))))
    .collect()
}

fn circuit_seed_base(frame_index: u64, channel: Channel) -> u64 {
  (1u64 << 32) + 18 * frame_index + 6 * channel.seed_offset()
}

fn has_png_extension(path: &Path) -> bool {
  path
    .extension()
    .and_then(|ext| ext.to_str())
    .is_some_and(|ext| ext.eq_ignore_ascii_case("png"))
}

fn optional_env_usize(name: &str) -> Result<Option<usize>, Box<dyn Error>> {
  match env::var(name) {
    Ok(value) if !value.trim().is_empty() => {
      Ok(Some(value.parse::<usize>().map_err(|err| {
        invalid_input(format!("{name} must be a usize, got {value:?}: {err}"))
      })?))
    }
    Ok(_) | Err(env::VarError::NotPresent) => Ok(None),
    Err(err) => Err(err.into()),
  }
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn Error>> {
  match env::var(name) {
    Ok(value) if !value.trim().is_empty() => value
      .parse::<usize>()
      .map_err(|err| invalid_input(format!("{name} must be a usize, got {value:?}: {err}")).into()),
    Ok(_) | Err(env::VarError::NotPresent) => Ok(default),
    Err(err) => Err(err.into()),
  }
}

fn env_flag(name: &str) -> bool {
  env::var(name)
    .map(|value| {
      matches!(
        value.as_str(),
        "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
      )
    })
    .unwrap_or(false)
}

fn print_per_channel<Scalar: PrimeField>(polynomials: &[ChannelPolynomial<Scalar>]) {
  println!("per_channel");
  println!("frame,channel,width,height,coeffs,padded_coeffs,path");
  for poly in polynomials {
    println!(
      "{},{},{},{},{},{},{}",
      poly.file.frame_index,
      poly.file.channel.as_str(),
      poly.width,
      poly.height,
      poly.coeffs.len(),
      poly.padded_coeffs.len(),
      poly.file.path.display()
    );
  }
}

#[allow(clippy::too_many_arguments)]
fn print_summary<E: Engine>(
  config: &BenchmarkConfig,
  polynomials: &[ChannelPolynomial<E::Scalar>],
  totals: &PhaseTotals,
  wall_time: Duration,
  commitment_width: usize,
  min_coeffs: usize,
  max_coeffs: usize,
  min_padded: usize,
  max_padded: usize,
  total_commitment_bytes: usize,
  total_opening_bytes: usize,
  circuit_evals: &[E::Scalar],
  prover_mle_evals: &[E::Scalar],
) {
  let n = polynomials.len();
  println!("video_pcs_authentication_benchmark");
  println!("engine={}", std::any::type_name::<E>());
  println!("pcs={}", std::any::type_name::<E::PCS>());
  println!("channel_dir={}", config.channel_dir.display());
  println!("channels={n}");
  println!("rayon_threads={}", rayon::current_num_threads());
  println!(
    "commitment_width={} requested_commitment_width={}",
    commitment_width, config.requested_commitment_width
  );
  println!("coefficients_min={min_coeffs} coefficients_max={max_coeffs}");
  println!("padded_coefficients_min={min_padded} padded_coefficients_max={max_padded}");
  println!("bytes_per_field_element={BYTES_PER_FIELD_ELEMENT}");
  println!("commitment_bytes_total={total_commitment_bytes}");
  println!("opening_bytes_total={total_opening_bytes}");
  println!(
    "circuit_horner_eval_checksum={}",
    scalar_checksum_prefix(circuit_evals)
  );
  println!(
    "pcs_mle_eval_checksum={}",
    scalar_checksum_prefix(prover_mle_evals)
  );
  println!("phase,total_ms,per_channel_ms");
  print_phase("load_and_pack", totals.load_and_pack, n);
  print_phase("setup", totals.setup, n);
  print_phase("commit_blind", totals.commit_blind, n);
  print_phase("commit", totals.commit, n);
  print_phase("circuit_horner_eval", totals.circuit_horner_eval, n);
  print_phase("prover_mle_eval", totals.prover_mle_eval, n);
  print_phase("eval_blind", totals.eval_blind, n);
  print_phase("eval_commit", totals.eval_commit, n);
  print_phase("open", totals.open, n);
  print_phase("verifier_mle_eval", totals.verifier_mle_eval, n);
  print_phase("verifier_eval_commit", totals.verifier_eval_commit, n);
  print_phase("verify", totals.verify, n);
  print_phase("wall", wall_time, n);
}

fn print_phase(name: &str, duration: Duration, channels: usize) {
  println!(
    "{name},{:.3},{:.3}",
    millis(duration),
    millis(duration) / channels as f64
  );
}

fn millis(duration: Duration) -> f64 {
  duration.as_secs_f64() * 1_000.0
}

fn scalar_checksum_prefix<Scalar: PrimeField>(values: &[Scalar]) -> String {
  let checksum = values
    .iter()
    .copied()
    .fold(Scalar::ZERO, |acc, value| acc + value);
  let repr = checksum.to_repr();
  let mut out = String::new();
  for byte in repr.as_ref().iter().take(8) {
    let _ = write!(&mut out, "{byte:02x}");
  }
  out
}

fn invalid_input(message: impl Into<String>) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
