//! Benchmark KZG10 authentication for video data packed into polynomials.
//!
//! The repository authenticates video with two different packing approaches, and this
//! benchmark measures both as separate phases:
//!   per_channel — each R/G/B channel PNG is packed into its own polynomial, mirroring
//!                 circuits/resizing_circuit.rs and circuits/gaussian_blur_circuit.rs
//!   per_frame   — the interleaved RGB pixel bytes of each full frame PNG are packed into
//!                 one polynomial, mirroring circuits/grayscale_circuit.rs and
//!                 circuits/mask_circuit.rs
//!
//! Run with:
//!   RUSTFLAGS="-C target-cpu=native" cargo run --release --example video_pcs_authentication_benchmark
//!
//! Useful environment variables:
//!   VIDEO_CHANNEL_DIR=video_data/decomposed_frame_channels
//!   VIDEO_FRAME_DIR=video_data/decomposed_frames
//!   VIDEO_PCS_MODE=both            # both | channel | frame
//!   VIDEO_PCS_MAX_FILES=30         # per phase: channel files (3 per frame) or frame files (1 per frame)
//!   VIDEO_PCS_PRINT_PER_CHANNEL=1
//!   PARALLEL_VERIFICATION=true
//!   RAYON_NUM_THREADS=8

use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_poly_commit::kzg10::{
  Commitment as KzgCommitment, KZG10, Powers, Proof, Randomness, UniversalParams, VerifierKey,
};
use ark_serialize::{CanonicalSerialize, Compress};
use image::ImageReader;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rayon::prelude::*;
use std::{
  borrow::Cow,
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
const DEFAULT_FRAME_DIR: &str = "video_data/decomposed_frames";
const BYTES_PER_FIELD_ELEMENT: usize = 30;
// Seed offset of `input_polynomial_interpolation_challenge` in the per-channel circuits
// (resizing_circuit.rs, gaussian_blur_circuit.rs).
const CHANNEL_INPUT_CHALLENGE_OFFSET: u64 = 3;
// Seed offset of `input_polynomial_interpolation_challenge` in the per-frame circuits
// (grayscale_circuit.rs, mask_circuit.rs).
const FRAME_INPUT_CHALLENGE_OFFSET: u64 = 1;
const KZG_SETUP_SEED: u64 = 0x5eed_c0de;

type UniPoly = DensePolynomial<Fr>;
type Kzg = KZG10<Bls12_381, UniPoly>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BenchmarkMode {
  Both,
  ChannelOnly,
  FrameOnly,
}

impl BenchmarkMode {
  fn from_env() -> Result<Self, Box<dyn Error>> {
    match env::var("VIDEO_PCS_MODE") {
      Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
        "" | "both" => Ok(Self::Both),
        "channel" | "per_channel" => Ok(Self::ChannelOnly),
        "frame" | "per_frame" => Ok(Self::FrameOnly),
        other => Err(
          invalid_input(format!(
            "VIDEO_PCS_MODE must be both|channel|frame, got {other:?}"
          ))
          .into(),
        ),
      },
      Err(env::VarError::NotPresent) => Ok(Self::Both),
      Err(err) => Err(err.into()),
    }
  }

  fn includes_channel_phase(self) -> bool {
    matches!(self, Self::Both | Self::ChannelOnly)
  }

  fn includes_frame_phase(self) -> bool {
    matches!(self, Self::Both | Self::FrameOnly)
  }
}

#[derive(Clone, Debug)]
struct BenchmarkConfig {
  channel_dir: PathBuf,
  frame_dir: PathBuf,
  mode: BenchmarkMode,
  max_files: Option<usize>,
  print_per_channel: bool,
  parallel_verification: bool,
}

#[derive(Clone, Debug)]
struct SourceFile {
  path: PathBuf,
  frame_index: u64,
  // Some(_) for per-channel packing, None for whole-frame RGB packing.
  channel: Option<Channel>,
}

impl SourceFile {
  fn channel_label(&self) -> &'static str {
    self.channel.map_or("RGB", Channel::as_str)
  }

  fn artifact_group_index(&self) -> usize {
    self.channel.map_or(3, |c| c.sort_index() as usize)
  }
}

#[derive(Debug)]
struct PackedPolynomial {
  file: SourceFile,
  width: u32,
  height: u32,
  coeffs: Vec<Fr>,
  polynomial: UniPoly,
  challenge: Fr,
}

#[derive(Debug)]
struct CommitmentRecord {
  commitment: KzgCommitment<Bls12_381>,
  randomness: Randomness<Fr, UniPoly>,
}

#[derive(Debug)]
struct OpeningRecord {
  eval: Fr,
  proof: Proof<Bls12_381>,
}

#[derive(Default)]
struct PhaseTotals {
  load_and_pack: Duration,
  setup: Duration,
  commit: Duration,
  horner_eval: Duration,
  pcs_eval: Duration,
  open: Duration,
  evaluate_interpolation: Duration,
  verify_pcs_openings: Duration,
}

fn main() -> Result<(), Box<dyn Error>> {
  let config = BenchmarkConfig::from_env()?;
  run_benchmark(config)
}

impl BenchmarkConfig {
  fn from_env() -> Result<Self, Box<dyn Error>> {
    Ok(Self {
      channel_dir: PathBuf::from(
        env::var("VIDEO_CHANNEL_DIR").unwrap_or_else(|_| DEFAULT_CHANNEL_DIR.to_string()),
      ),
      frame_dir: PathBuf::from(
        env::var("VIDEO_FRAME_DIR").unwrap_or_else(|_| DEFAULT_FRAME_DIR.to_string()),
      ),
      mode: BenchmarkMode::from_env()?,
      max_files: optional_env_usize("VIDEO_PCS_MAX_FILES")?,
      print_per_channel: env_flag("VIDEO_PCS_PRINT_PER_CHANNEL"),
      parallel_verification: env_flag("PARALLEL_VERIFICATION"),
    })
  }
}

fn run_benchmark(config: BenchmarkConfig) -> Result<(), Box<dyn Error>> {
  if config.mode.includes_channel_phase() {
    let files = discover_channel_files(&config.channel_dir)?;
    run_authentication_phase(
      "per_channel",
      &config.channel_dir,
      &config,
      files,
      read_channel_polynomial,
    )?;
  }

  if config.mode.includes_frame_phase() {
    if config.mode == BenchmarkMode::Both {
      println!();
    }
    let files = discover_frame_files(&config.frame_dir)?;
    run_authentication_phase(
      "per_frame",
      &config.frame_dir,
      &config,
      files,
      read_frame_polynomial,
    )?;
  }

  Ok(())
}

fn run_authentication_phase(
  phase: &str,
  source_dir: &Path,
  config: &BenchmarkConfig,
  mut files: Vec<SourceFile>,
  loader: fn(SourceFile) -> Result<PackedPolynomial, Box<dyn Error + Send + Sync>>,
) -> Result<(), Box<dyn Error>> {
  let wall_start = Instant::now();
  let mut totals = PhaseTotals::default();

  if let Some(max_files) = config.max_files {
    files.truncate(max_files);
  }
  if files.is_empty() {
    return Err(
      invalid_input(format!(
        "no input PNG files for {phase} authentication found in {}",
        source_dir.display()
      ))
      .into(),
    );
  }

  let t0 = Instant::now();
  let polynomials = files
    .into_par_iter()
    .map(loader)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|err| -> Box<dyn Error> { err })?;
  totals.load_and_pack = t0.elapsed();

  let min_coeffs = polynomials.iter().map(|p| p.coeffs.len()).min().unwrap();
  let max_coeffs = polynomials.iter().map(|p| p.coeffs.len()).max().unwrap();
  let max_degree = polynomials
    .iter()
    .map(|p| p.polynomial.degree())
    .max()
    .unwrap();
  let setup_degree = max_degree.max(1);

  let mut setup_rng = StdRng::seed_from_u64(KZG_SETUP_SEED);
  let t0 = Instant::now();
  let pp = Kzg::setup(setup_degree, false, &mut setup_rng)?;
  let (powers, vk) = trim_kzg_params(&pp, setup_degree)?;
  totals.setup = t0.elapsed();

  let t0 = Instant::now();
  let commit_results = polynomials
    .par_iter()
    .map(|poly| {
      let (commitment, randomness) = Kzg::commit(&powers, black_box(&poly.polynomial), None, None)?;
      let commitment_bytes = serialized_size(&commitment);
      Ok::<_, ark_poly_commit::Error>((
        CommitmentRecord {
          commitment,
          randomness,
        },
        commitment_bytes,
      ))
    })
    .collect::<Result<Vec<_>, _>>()?;
  totals.commit = t0.elapsed();
  let commitment_bytes_by_poly = commit_results
    .iter()
    .map(|(_, commitment_bytes)| *commitment_bytes)
    .collect::<Vec<_>>();
  let total_commitment_bytes = commitment_bytes_by_poly.iter().sum();
  let commitments = commit_results
    .into_iter()
    .map(|(record, _)| record)
    .collect::<Vec<_>>();

  let horner_evals = if config.parallel_verification {
    let t0 = Instant::now();
    let horner_evals = polynomials
      .par_iter()
      .map(|poly| evaluate_circuit_horner(black_box(&poly.coeffs), black_box(&poly.challenge)))
      .collect::<Vec<_>>();
    totals.horner_eval = t0.elapsed();
    horner_evals
  } else {
    let mut horner_evals = Vec::with_capacity(polynomials.len());
    for poly in &polynomials {
      let t0 = Instant::now();
      let eval = evaluate_circuit_horner(black_box(&poly.coeffs), black_box(&poly.challenge));
      totals.horner_eval += t0.elapsed();
      horner_evals.push(black_box(eval));
    }
    horner_evals
  };

  let mut pcs_evals = Vec::with_capacity(polynomials.len());
  for poly in &polynomials {
    let t0 = Instant::now();
    let eval = poly.polynomial.evaluate(black_box(&poly.challenge));
    totals.pcs_eval += t0.elapsed();
    if eval != horner_evals[pcs_evals.len()] {
      return Err(
        invalid_input(format!(
          "Horner and KZG polynomial evaluations disagree for {}",
          poly.file.path.display()
        ))
        .into(),
      );
    }
    pcs_evals.push(black_box(eval));
  }

  let t0 = Instant::now();
  let opening_results = polynomials
    .par_iter()
    .zip(commitments.par_iter())
    .zip(pcs_evals.par_iter())
    .map(|((poly, record), eval)| {
      let proof = Kzg::open(
        &powers,
        black_box(&poly.polynomial),
        poly.challenge,
        &record.randomness,
      )?;
      let opening_proof_bytes = serialized_size(&proof);
      Ok::<_, ark_poly_commit::Error>((OpeningRecord { eval: *eval, proof }, opening_proof_bytes))
    })
    .collect::<Result<Vec<_>, _>>()?;
  totals.open = t0.elapsed();
  let opening_proof_bytes_by_poly = opening_results
    .iter()
    .map(|(_, opening_proof_bytes)| *opening_proof_bytes)
    .collect::<Vec<_>>();
  let total_opening_proof_bytes = opening_proof_bytes_by_poly.iter().sum();
  let openings = opening_results
    .into_iter()
    .map(|(record, _)| record)
    .collect::<Vec<_>>();

  let mut verifier_evals = Vec::with_capacity(polynomials.len());
  for (poly, opening) in polynomials.iter().zip(openings.iter()) {
    let t0 = Instant::now();
    let recomputed_eval = poly.polynomial.evaluate(black_box(&poly.challenge));
    totals.evaluate_interpolation += t0.elapsed();
    if recomputed_eval != opening.eval {
      return Err(
        invalid_input(format!(
          "verifier-side KZG polynomial evaluation mismatch for {}",
          poly.file.path.display()
        ))
        .into(),
      );
    }
    verifier_evals.push(black_box(recomputed_eval));
  }

  if config.parallel_verification {
    let t0 = Instant::now();
    let verify_results = polynomials
      .par_iter()
      .zip(commitments.par_iter())
      .zip(openings.par_iter())
      .zip(verifier_evals.par_iter())
      .enumerate()
      .map(|(i, (((poly, commitment), opening), recomputed_eval))| {
        let verified = Kzg::check(
          &vk,
          &commitment.commitment,
          poly.challenge,
          *recomputed_eval,
          &opening.proof,
        )?;
        Ok::<_, ark_poly_commit::Error>((i, verified))
      })
      .collect::<Result<Vec<_>, _>>()?;
    totals.verify_pcs_openings = t0.elapsed();

    if let Some((i, _)) = verify_results.iter().find(|(_, verified)| !*verified) {
      return Err(
        invalid_input(format!(
          "KZG opening verification failed for {}",
          polynomials[*i].file.path.display()
        ))
        .into(),
      );
    }
  } else {
    for (((poly, commitment), opening), recomputed_eval) in polynomials
      .iter()
      .zip(commitments.iter())
      .zip(openings.iter())
      .zip(verifier_evals.iter())
    {
      let t0 = Instant::now();
      let verified = Kzg::check(
        &vk,
        &commitment.commitment,
        poly.challenge,
        *recomputed_eval,
        &opening.proof,
      )?;
      totals.verify_pcs_openings += t0.elapsed();
      if !verified {
        return Err(
          invalid_input(format!(
            "KZG opening verification failed for {}",
            poly.file.path.display()
          ))
          .into(),
        );
      }
    }
  }

  if config.print_per_channel {
    print_per_polynomial(
      &polynomials,
      &commitment_bytes_by_poly,
      &opening_proof_bytes_by_poly,
    );
  }

  print_summary(
    phase,
    source_dir,
    config,
    &polynomials,
    &totals,
    wall_start.elapsed(),
    setup_degree,
    min_coeffs,
    max_coeffs,
    total_commitment_bytes,
    total_opening_proof_bytes,
    &commitment_bytes_by_poly,
    &opening_proof_bytes_by_poly,
    &horner_evals,
    &pcs_evals,
  );

  Ok(())
}

fn trim_kzg_params(
  pp: &UniversalParams<Bls12_381>,
  supported_degree: usize,
) -> Result<(Powers<'static, Bls12_381>, VerifierKey<Bls12_381>), Box<dyn Error>> {
  if supported_degree >= pp.powers_of_g.len() {
    return Err(
      invalid_input(format!(
        "supported degree {supported_degree} exceeds KZG powers length {}",
        pp.powers_of_g.len()
      ))
      .into(),
    );
  }

  let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
  let powers_of_gamma_g = (0..=supported_degree)
    .map(|i| {
      pp.powers_of_gamma_g
        .get(&i)
        .copied()
        .ok_or_else(|| invalid_input(format!("missing gamma_g power {i}")))
    })
    .collect::<Result<Vec<_>, _>>()?;

  let powers = Powers {
    powers_of_g: Cow::Owned(powers_of_g),
    powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
  };
  let vk = VerifierKey {
    g: pp.powers_of_g[0],
    gamma_g: pp.powers_of_gamma_g[&0],
    h: pp.h,
    beta_h: pp.beta_h,
    prepared_h: pp.prepared_h.clone(),
    prepared_beta_h: pp.prepared_beta_h.clone(),
  };

  Ok((powers, vk))
}

fn discover_channel_files(dir: &Path) -> Result<Vec<SourceFile>, Box<dyn Error>> {
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

  files.sort_by_key(|f| (f.frame_index, f.artifact_group_index()));
  Ok(files)
}

fn discover_frame_files(dir: &Path) -> Result<Vec<SourceFile>, Box<dyn Error>> {
  let mut files = Vec::new();
  for entry in fs::read_dir(dir)? {
    let path = entry?.path();
    if !path.is_file() || !has_png_extension(&path) {
      continue;
    }

    if let Some(file) = parse_frame_file(path)? {
      files.push(file);
    }
  }

  files.sort_by_key(|f| f.frame_index);
  Ok(files)
}

fn parse_channel_file(path: PathBuf) -> Result<Option<SourceFile>, Box<dyn Error>> {
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

  Ok(Some(SourceFile {
    path,
    frame_index,
    channel: Some(channel),
  }))
}

fn parse_frame_file(path: PathBuf) -> Result<Option<SourceFile>, Box<dyn Error>> {
  let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
    return Ok(None);
  };
  let Some(frame_name) = stem.strip_prefix("frame_") else {
    return Ok(None);
  };
  let frame_index = frame_name.parse::<u64>().map_err(|err| {
    invalid_input(format!(
      "failed to parse frame index from {}: {err}",
      path.display()
    ))
  })?;

  Ok(Some(SourceFile {
    path,
    frame_index,
    channel: None,
  }))
}

fn read_channel_polynomial(
  file: SourceFile,
) -> Result<PackedPolynomial, Box<dyn Error + Send + Sync>> {
  let Some(channel) = file.channel else {
    return Err(
      invalid_input(format!(
        "channel loader called on frame file {}",
        file.path.display()
      ))
      .into(),
    );
  };

  let image = ImageReader::open(&file.path)?.decode()?.into_luma8();
  let (width, height) = image.dimensions();
  if width == 0 || height == 0 {
    return Err(invalid_input(format!("empty image {}", file.path.display())).into());
  }

  let coeffs = pack_bytes_as_field_elements(image.as_raw());
  let challenge = deterministic_challenge(
    channel_seed_base(file.frame_index, channel) + CHANNEL_INPUT_CHALLENGE_OFFSET,
  );

  build_packed_polynomial(file, width, height, coeffs, challenge)
}

fn read_frame_polynomial(
  file: SourceFile,
) -> Result<PackedPolynomial, Box<dyn Error + Send + Sync>> {
  let image = ImageReader::open(&file.path)?.decode()?.into_rgb8();
  let (width, height) = image.dimensions();
  if width == 0 || height == 0 {
    return Err(invalid_input(format!("empty image {}", file.path.display())).into());
  }

  // The raw buffer is the row-major interleaved R,G,B byte stream. Packing it 30 bytes
  // per field element is identical to the 10-pixels-per-scalar packing in
  // grayscale_circuit.rs / mask_circuit.rs.
  let coeffs = pack_bytes_as_field_elements(image.as_raw());
  let challenge =
    deterministic_challenge(frame_seed_base(file.frame_index) + FRAME_INPUT_CHALLENGE_OFFSET);

  build_packed_polynomial(file, width, height, coeffs, challenge)
}

fn build_packed_polynomial(
  file: SourceFile,
  width: u32,
  height: u32,
  coeffs: Vec<Fr>,
  challenge: Fr,
) -> Result<PackedPolynomial, Box<dyn Error + Send + Sync>> {
  if coeffs.is_empty() {
    return Err(
      invalid_input(format!(
        "no polynomial coefficients for {}",
        file.path.display()
      ))
      .into(),
    );
  }

  let ark_coeffs_little_endian = coeffs.iter().rev().copied().collect();
  let polynomial = UniPoly::from_coefficients_vec(ark_coeffs_little_endian);

  Ok(PackedPolynomial {
    file,
    width,
    height,
    coeffs,
    polynomial,
    challenge,
  })
}

fn pack_bytes_as_field_elements(bytes: &[u8]) -> Vec<Fr> {
  let byte_base = Fr::from(1u64 << 8);
  bytes
    .chunks(BYTES_PER_FIELD_ELEMENT)
    .map(|chunk| {
      let mut scalar = Fr::from(0u64);
      let mut coeff = Fr::from(1u64);
      for &byte in chunk {
        scalar += coeff * Fr::from(byte as u64);
        coeff *= byte_base;
      }
      scalar
    })
    .collect()
}

fn evaluate_circuit_horner(coeffs: &[Fr], point: &Fr) -> Fr {
  let Some((&first, rest)) = coeffs.split_first() else {
    return Fr::from(0u64);
  };
  rest.iter().fold(first, |acc, coeff| acc * point + coeff)
}

fn deterministic_challenge(seed: u64) -> Fr {
  let mut rng = StdRng::seed_from_u64(seed);
  Fr::from(rng.gen_range(0..(1u128 << 127)))
}

fn channel_seed_base(frame_index: u64, channel: Channel) -> u64 {
  (1u64 << 32) + 18 * frame_index + 6 * channel.seed_offset()
}

fn frame_seed_base(frame_index: u64) -> u64 {
  (1u64 << 32) + 5 * frame_index
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

fn print_per_polynomial(
  polynomials: &[PackedPolynomial],
  commitment_bytes_by_poly: &[usize],
  opening_proof_bytes_by_poly: &[usize],
) {
  println!("per_polynomial");
  println!("frame,channel,width,height,coeffs,degree,commitment_bytes,opening_proof_bytes,path");
  for ((poly, commitment_bytes), opening_proof_bytes) in polynomials
    .iter()
    .zip(commitment_bytes_by_poly.iter())
    .zip(opening_proof_bytes_by_poly.iter())
  {
    println!(
      "{},{},{},{},{},{},{},{},{}",
      poly.file.frame_index,
      poly.file.channel_label(),
      poly.width,
      poly.height,
      poly.coeffs.len(),
      poly.polynomial.degree(),
      commitment_bytes,
      opening_proof_bytes,
      poly.file.path.display()
    );
  }
}

#[allow(clippy::too_many_arguments)]
fn print_summary(
  phase: &str,
  source_dir: &Path,
  config: &BenchmarkConfig,
  polynomials: &[PackedPolynomial],
  totals: &PhaseTotals,
  wall_time: Duration,
  setup_degree: usize,
  min_coeffs: usize,
  max_coeffs: usize,
  total_commitment_bytes: usize,
  total_opening_proof_bytes: usize,
  commitment_bytes_by_poly: &[usize],
  opening_proof_bytes_by_poly: &[usize],
  horner_evals: &[Fr],
  pcs_evals: &[Fr],
) {
  let n = polynomials.len();
  println!("video_pcs_authentication_benchmark");
  println!("phase={phase}");
  println!("curve={}", std::any::type_name::<Bls12_381>());
  println!("pcs={}", std::any::type_name::<Kzg>());
  println!("source_dir={}", source_dir.display());
  println!("polynomials={n}");
  println!("rayon_threads={}", rayon::current_num_threads());
  println!("parallel_verification={}", config.parallel_verification);
  println!("setup_degree={setup_degree}");
  println!("coefficients_min={min_coeffs} coefficients_max={max_coeffs}");
  println!("bytes_per_field_element={BYTES_PER_FIELD_ELEMENT}");
  println!("commitment_bytes_total={total_commitment_bytes}");
  println!("opening_proof_bytes_total={total_opening_proof_bytes}");
  print_artifact_bytes_by_channel(
    polynomials,
    commitment_bytes_by_poly,
    opening_proof_bytes_by_poly,
  );
  println!(
    "horner_eval_checksum={}",
    scalar_checksum_prefix(horner_evals)
  );
  println!("pcs_eval_checksum={}", scalar_checksum_prefix(pcs_evals));
  println!("phase,total,per_polynomial");
  print_phase("load_and_pack", totals.load_and_pack, n);
  print_phase("setup", totals.setup, n);
  print_phase("commit", totals.commit, n);
  print_phase("horner_eval", totals.horner_eval, n);
  print_phase("pcs_eval", totals.pcs_eval, n);
  print_phase("open", totals.open, n);
  print_phase("evaluate_interpolation", totals.evaluate_interpolation, n);
  print_phase("verify_pcs_openings", totals.verify_pcs_openings, n);
  print_phase("wall", wall_time, n);
}

fn print_artifact_bytes_by_channel(
  polynomials: &[PackedPolynomial],
  commitment_bytes_by_poly: &[usize],
  opening_proof_bytes_by_poly: &[usize],
) {
  const GROUP_LABELS: [&str; 4] = ["R", "G", "B", "RGB"];
  let mut group_counts = [0usize; 4];
  let mut commitment_totals = [0usize; 4];
  let mut opening_proof_totals = [0usize; 4];

  for ((poly, commitment_bytes), opening_proof_bytes) in polynomials
    .iter()
    .zip(commitment_bytes_by_poly.iter())
    .zip(opening_proof_bytes_by_poly.iter())
  {
    let group_idx = poly.file.artifact_group_index();
    group_counts[group_idx] += 1;
    commitment_totals[group_idx] += commitment_bytes;
    opening_proof_totals[group_idx] += opening_proof_bytes;
  }

  println!("artifact_bytes_by_channel");
  println!("channel,commitment_bytes_total,opening_proof_bytes_total");
  for group_idx in 0..GROUP_LABELS.len() {
    if group_counts[group_idx] == 0 {
      continue;
    }
    println!(
      "{},{},{}",
      GROUP_LABELS[group_idx], commitment_totals[group_idx], opening_proof_totals[group_idx]
    );
  }
}

fn print_phase(name: &str, duration: Duration, polynomials: usize) {
  println!(
    "{name},{:.3} ms,{:.3} ms",
    millis(duration),
    millis(duration) / polynomials as f64
  );
}

fn millis(duration: Duration) -> f64 {
  duration.as_secs_f64() * 1_000.0
}

fn serialized_size<T: CanonicalSerialize>(value: &T) -> usize {
  value.serialized_size(Compress::Yes)
}

fn scalar_checksum_prefix(values: &[Fr]) -> String {
  let checksum = values
    .iter()
    .copied()
    .fold(Fr::from(0u64), |acc, value| acc + value);
  let mut bytes = Vec::new();
  checksum
    .serialize_compressed(&mut bytes)
    .expect("serializing field element into Vec cannot fail");

  let mut out = String::new();
  for byte in bytes.iter().take(8) {
    let _ = write!(&mut out, "{byte:02x}");
  }
  out
}

fn invalid_input(message: impl Into<String>) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
