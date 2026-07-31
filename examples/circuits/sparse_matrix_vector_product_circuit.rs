// Implementation of a sparse matrix-vector product circuit based on the zk-RAM approach
// of the paper "Two Shuffles Make a RAM" (https://eprint.iacr.org/2023/1115).

#![allow(non_snake_case)]

use std::{
  collections::BTreeMap,
  fmt,
  ops::Range,
};

use bellpepper_core::{
  ConstraintSystem, LinearCombination, SynthesisError,
  num::AllocatedNum,
};
use ff::{Field, PrimeField};
use rand::{Rng, SeedableRng, rngs::StdRng};
use spartan2::traits::{Engine, circuit::SpartanCircuit};

/// Public dimensions of the sparse matrix and its fixed-size encoding.
///
/// `max_delta_length` is the number of outer row-local batches, not the
/// maximum number of scalar entries. Each batch contains `batch_size` entries,
/// so the total non zero entry capacity is
/// `max_delta_length * batch_size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseProductConfig {
  pub image_height: usize,
  pub image_width: usize,
  pub max_delta_length: usize,
  pub batch_size: usize,
}

impl SparseProductConfig {
  pub fn new(
    image_height: usize,
    image_width: usize,
    max_delta_length: usize,
    batch_size: usize,
  ) -> Self {
    Self {
      image_height,
      image_width,
      max_delta_length,
      batch_size,
    }
  }

  pub fn num_nonzero_entries(&self) -> usize {
    self.max_delta_length * self.batch_size
  }

  /// Number of constraints emitted by this implementation.
  ///
  /// This count includes every multiplication by an allocated public random
  /// challenge (an issue with the paper this is building from) and both setup-product chains.
  pub fn expected_num_constraints(&self) -> usize {
    let h = self.image_height;
    let w = self.image_width;
    let t = self.max_delta_length;
    let q = self.num_nonzero_entries();

    // Sparse products: Q.
    // LogUp ROM: Q address compressions + Q query recurrences + W table rows.
    // Main RAM shuffle: 4T + 3H - 2.
    // Valid-difference set shuffle: 5T - 2.
    // Final left-vector dot product (with the equality fused): H.
    3 * q + w + 9 * t + 4 * h - 4
  }

  pub fn expected_num_precommitted(&self) -> usize {
    let h = self.image_height;
    let w = self.image_width;
    let t = self.max_delta_length;
    let q = self.num_nonzero_entries();
    5 * t + 3 * q + 2 * h + w
  }

  pub fn expected_num_public_inputs(&self) -> usize {
    // target + left vector + right vector + seven fake challenges.
    self.image_height + self.image_width + 8
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SparseProductError {
  ConfigurationOverflow,
  VectorLength {
    name: &'static str,
    expected: usize,
    actual: usize,
  },
  RowOutOfBounds {
    entry: usize,
    row: usize,
    height: usize,
  },
  ColumnOutOfBounds {
    entry: usize,
    column: usize,
    width: usize,
  },
  TooManyBatches {
    required: usize,
    maximum: usize,
  },
}

impl fmt::Display for SparseProductError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ConfigurationOverflow => write!(f, "the configured circuit size overflows usize"),
      Self::VectorLength {
        name,
        expected,
        actual,
      } => write!(
        f,
        "{name} has length {actual}, but the circuit requires {expected}",
      ),
      Self::RowOutOfBounds { entry, row, height } => write!(
        f,
        "sparse entry {entry} has row {row}, outside 0..{height}",
      ),
      Self::ColumnOutOfBounds {
        entry,
        column,
        width,
      } => write!(
        f,
        "sparse entry {entry} has column {column}, outside 0..{width}",
      ),
      Self::TooManyBatches { required, maximum } => write!(
        f,
        "the sparse entries require {required} row-local batches, but max_delta_length is \
         {maximum}",
      ),
    }
  }
}

impl std::error::Error for SparseProductError {}

/// One supplied entry of the sparse H-by-W delta matrix.
///
/// Zero-valued entries are accepted and consume capacity because padding is
/// represented by explicit zero entries in the fixed-size encoding.
#[derive(Clone, Copy, Debug)]
pub struct SparseMatrixEntry<Scalar: PrimeField> {
  pub row: usize,
  pub column: usize,
  pub value: Scalar,
}

impl<Scalar: PrimeField> SparseMatrixEntry<Scalar> {
  pub fn new(row: usize, column: usize, value: Scalar) -> Self {
    Self { row, column, value }
  }
}

#[derive(Clone, Debug)]
struct PackedDeltas<Scalar: PrimeField> {
  rows: Vec<usize>,
  columns: Vec<usize>,
  values: Vec<Scalar>,
}

#[derive(Clone, Debug)]
struct MemoryTrace<Scalar: PrimeField> {
  rom_values: Vec<Scalar>,
  rom_multiplicities: Vec<Scalar>,
  batch_sums: Vec<Scalar>,
  old_values: Vec<Scalar>,
  old_times: Vec<Scalar>,
  final_values: Vec<Scalar>,
  final_times: Vec<Scalar>,
  set_query_versions: Vec<Scalar>,
  set_final_versions: Vec<Scalar>,
}

#[derive(Clone, Copy, Debug)]
struct FakeChallenges<Scalar: PrimeField> {
  rom_address: Scalar,
  rom_fraction: Scalar,
  ram_address: Scalar,
  ram_time: Scalar,
  ram_offset: Scalar,
  set_key: Scalar,
  set_offset: Scalar,
}

/// Bellpepper circuit for a sparse vector-matrix-vector product.
/// Implements the Read/Write RAM construction of https://eprint.iacr.org/2023/1115.
///
/// The enforced arithmetic relation is
///
/// `target = sum_(b,k) left[row[b]] * delta[b][k] * right[column[b][k]]`.
/// `left` has one entry per matrix row, and `right` has one entry per matrix
/// column. The circuit exposes no auxiliary vectors that do not participate in
/// this relation.
///
/// The `right[column]` accesses use a LogUp read-only lookup on the pair
/// `(column, value)`. The `delta_as[row] += batch_sum` accesses use the full
/// Two-Shuffles RAM construction: one record shuffle plus a second versioned
/// set shuffle proving `clock - old_time` is in `1..=max_delta_length`.
///
/// Seven public field elements are deterministic stand-ins for transcript
/// challenges because challenge support in the target integration is
/// currently unreliable. All query, trace, version, and multiplicity witness
/// values are nevertheless allocated in `precommitted`, so replacing these
/// stand-ins with real post-commitment challenges does not require changing
/// the memory relations. As expected, known deterministic challenges do not
/// provide adversarial Schwartz-Zippel soundness; this is the single prototype
/// deviation allowed by the caller, not a production security claim.
///
/// Both setup products are computed inside the circuit. This adds H+T-2
/// constraints relative to the paper's verifier-side preprocessing, but keeps
/// verifier work succinct in the RAM access count.
#[derive(Clone, Debug)]
pub struct SparseVectorMatrixVectorCircuit<Scalar: PrimeField> {
  config: SparseProductConfig,
  packed: PackedDeltas<Scalar>,
  left_vector: Vec<Scalar>,
  right_vector: Vec<Scalar>,
  trace: MemoryTrace<Scalar>,
  target: Scalar,
  computed_product: Scalar,
  challenges: FakeChallenges<Scalar>,
}

impl<Scalar: PrimeField> SparseVectorMatrixVectorCircuit<Scalar> {
  pub fn from_entries(
    config: SparseProductConfig,
    entries: Vec<SparseMatrixEntry<Scalar>>,
    left_vector: Vec<Scalar>,
    right_vector: Vec<Scalar>,
    challenge_seed: u64,
  ) -> Result<Self, SparseProductError> {
    Self::build(
      config,
      entries,
      left_vector,
      right_vector,
      None,
      challenge_seed,
    )
  }

  /// Builds the same witness while using an explicitly supplied public target.
  /// A target different from `computed_product()` creates a well-shaped but
  /// unsatisfied circuit, which is useful for negative tests.
  pub fn from_entries_with_target(
    config: SparseProductConfig,
    entries: Vec<SparseMatrixEntry<Scalar>>,
    left_vector: Vec<Scalar>,
    right_vector: Vec<Scalar>,
    target: Scalar,
    challenge_seed: u64,
  ) -> Result<Self, SparseProductError> {
    Self::build(
      config,
      entries,
      left_vector,
      right_vector,
      Some(target),
      challenge_seed,
    )
  }

  fn build(
    config: SparseProductConfig,
    entries: Vec<SparseMatrixEntry<Scalar>>,
    left_vector: Vec<Scalar>,
    right_vector: Vec<Scalar>,
    supplied_target: Option<Scalar>,
    challenge_seed: u64,
  ) -> Result<Self, SparseProductError> {
    if left_vector.len() != config.image_height {
      return Err(SparseProductError::VectorLength {
        name: "left_vector",
        expected: config.image_height,
        actual: left_vector.len(),
      });
    }
    if right_vector.len() != config.image_width {
      return Err(SparseProductError::VectorLength {
        name: "right_vector",
        expected: config.image_width,
        actual: right_vector.len(),
      });
    }

    let packed = pack_entries(&config, entries)?;
    let trace = build_memory_trace(&config, &packed, &right_vector);
    let computed_product = left_vector
      .iter()
      .zip(trace.final_values.iter())
      .fold(Scalar::ZERO, |acc, (left, value)| acc + *left * *value);
    let target = supplied_target.unwrap_or(computed_product);

    let challenges = select_fake_challenges(challenge_seed);
    Ok(Self {
      config,
      packed,
      left_vector,
      right_vector,
      trace,
      target,
      computed_product,
      challenges,
    })
  }

  pub fn config(&self) -> SparseProductConfig {
    self.config
  }

  pub fn target(&self) -> Scalar {
    self.target
  }

  pub fn computed_product(&self) -> Scalar {
    self.computed_product
  }

  pub fn final_accumulator(&self) -> &[Scalar] {
    &self.trace.final_values
  }

  /// Public-input order used by both `public_values` and `synthesize`.
  pub fn expected_public_values(&self) -> Vec<Scalar> {
    assemble_public_values(
      self.target,
      &self.left_vector,
      &self.right_vector,
      self.challenges,
    )
  }

  /// Independently constructs the public statement from verifier-known data.
  ///
  /// As previously mentioned, the random challenges are deterministically set
  /// because the Spartan2 library did not support these at the time.
  pub fn verifier_public_values(
    config: SparseProductConfig,
    target: Scalar,
    left_vector: &[Scalar],
    right_vector: &[Scalar],
    challenge_seed: u64,
  ) -> Result<Vec<Scalar>, SparseProductError> {
    if left_vector.len() != config.image_height {
      return Err(SparseProductError::VectorLength {
        name: "left_vector",
        expected: config.image_height,
        actual: left_vector.len(),
      });
    }
    if right_vector.len() != config.image_width {
      return Err(SparseProductError::VectorLength {
        name: "right_vector",
        expected: config.image_width,
        actual: right_vector.len(),
      });
    }
    let challenges = select_fake_challenges(challenge_seed);
    Ok(assemble_public_values(
      target,
      left_vector,
      right_vector,
      challenges,
    ))
  }
}

fn assemble_public_values<Scalar: PrimeField>(
  target: Scalar,
  left_vector: &[Scalar],
  right_vector: &[Scalar],
  challenges: FakeChallenges<Scalar>,
) -> Vec<Scalar> {
  let mut values = Vec::with_capacity(left_vector.len() + right_vector.len() + 8);
  values.push(target);
  values.extend_from_slice(left_vector);
  values.extend_from_slice(right_vector);
  values.extend([
    challenges.rom_address,
    challenges.rom_fraction,
    challenges.ram_address,
    challenges.ram_time,
    challenges.ram_offset,
    challenges.set_key,
    challenges.set_offset,
  ]);
  values
}

fn scalar_from_usize<Scalar: PrimeField>(value: usize) -> Scalar {
  Scalar::from_u128(value as u128)
}

fn pack_entries<Scalar: PrimeField>(
  config: &SparseProductConfig,
  entries: Vec<SparseMatrixEntry<Scalar>>,
) -> Result<PackedDeltas<Scalar>, SparseProductError> {
  let mut by_row: BTreeMap<usize, Vec<(usize, Scalar)>> = BTreeMap::new();
  for (entry_index, entry) in entries.into_iter().enumerate() {
    if entry.row >= config.image_height {
      return Err(SparseProductError::RowOutOfBounds {
        entry: entry_index,
        row: entry.row,
        height: config.image_height,
      });
    }
    if entry.column >= config.image_width {
      return Err(SparseProductError::ColumnOutOfBounds {
        entry: entry_index,
        column: entry.column,
        width: config.image_width,
      });
    }
    by_row
      .entry(entry.row)
      .or_default()
      .push((entry.column, entry.value));
  }

  let required_batches = by_row.values().try_fold(0usize, |acc, row| {
    let row_batches = row.len().div_ceil(config.batch_size);
    acc.checked_add(row_batches)
      .ok_or(SparseProductError::ConfigurationOverflow)
  })?;
  if required_batches > config.max_delta_length {
    return Err(SparseProductError::TooManyBatches {
      required: required_batches,
      maximum: config.max_delta_length,
    });
  }

  let q = config.num_nonzero_entries();
  let mut rows = vec![0usize; config.max_delta_length];
  let mut columns = vec![0usize; q];
  let mut values = vec![Scalar::ZERO; q];
  let mut batch = 0usize;

  for (row, row_entries) in by_row {
    for chunk in row_entries.chunks(config.batch_size) {
      rows[batch] = row;
      let base = batch * config.batch_size;
      for (slot, (column, value)) in chunk.iter().enumerate() {
        columns[base + slot] = *column;
        values[base + slot] = *value;
      }
      batch += 1;
    }
  }

  // Unused inner and outer slots remain `(row=0, column=0, delta=0)`. The
  // fixed-size circuit still performs unconditional ROM/RAM accesses for them.
  Ok(PackedDeltas {
    rows,
    columns,
    values,
  })
}

fn build_memory_trace<Scalar: PrimeField>(
  config: &SparseProductConfig,
  packed: &PackedDeltas<Scalar>,
  right_vector: &[Scalar],
) -> MemoryTrace<Scalar> {
  let t = config.max_delta_length;
  let q = config.num_nonzero_entries();

  let mut rom_values = Vec::with_capacity(q);
  let mut multiplicities = vec![0usize; config.image_width];
  for &column in &packed.columns {
    rom_values.push(right_vector[column]);
    multiplicities[column] += 1;
  }
  let rom_multiplicities = multiplicities
    .into_iter()
    .map(scalar_from_usize::<Scalar>)
    .collect();

  let mut memory = vec![Scalar::ZERO; config.image_height];
  let mut last_times = vec![0usize; config.image_height];
  let mut old_values = Vec::with_capacity(t);
  let mut old_times = Vec::with_capacity(t);
  let mut batch_sums = Vec::with_capacity(t);
  let mut set_versions = vec![0usize; t];
  let mut set_query_versions = Vec::with_capacity(t);

  for batch in 0..t {
    let row = packed.rows[batch];
    let clock = batch + 1;
    let old_value = memory[row];
    let old_time = last_times[row];
    let base = batch * config.batch_size;
    let batch_sum = (0..config.batch_size).fold(Scalar::ZERO, |acc, slot| {
      let query = base + slot;
      acc + packed.values[query] * rom_values[query]
    });

    old_values.push(old_value);
    old_times.push(scalar_from_usize(old_time));
    batch_sums.push(batch_sum);

    let diff = clock - old_time;
    set_query_versions.push(scalar_from_usize(set_versions[diff - 1]));
    set_versions[diff - 1] += 1;

    memory[row] = old_value + batch_sum;
    last_times[row] = clock;
  }

  MemoryTrace {
    rom_values,
    rom_multiplicities,
    batch_sums,
    old_values,
    old_times,
    final_values: memory,
    final_times: last_times
      .into_iter()
      .map(scalar_from_usize::<Scalar>)
      .collect(),
    set_query_versions,
    set_final_versions: set_versions
      .into_iter()
      .map(scalar_from_usize::<Scalar>)
      .collect(),
  }
}

fn select_fake_challenges<Scalar: PrimeField>(challenge_seed: u64) -> FakeChallenges<Scalar> {
  let mut rng = StdRng::seed_from_u64(challenge_seed);
  let mut sample = || Scalar::from_u128(rng.gen_range(1..(1u128 << 127)));
  FakeChallenges {
    rom_address: sample(),
    rom_fraction: sample(),
    ram_address: sample(),
    ram_time: sample(),
    ram_offset: sample(),
    set_key: sample(),
    set_offset: sample(),
  }
}

#[derive(Debug)]
struct PrecommittedLayout {
  rows: Range<usize>,
  columns: Range<usize>,
  deltas: Range<usize>,
  rom_values: Range<usize>,
  old_values: Range<usize>,
  old_times: Range<usize>,
  final_values: Range<usize>,
  final_times: Range<usize>,
  set_query_versions: Range<usize>,
  set_final_versions: Range<usize>,
  rom_multiplicities: Range<usize>,
  total: usize,
}

impl PrecommittedLayout {
  fn new(config: &SparseProductConfig) -> Self {
    fn next(cursor: &mut usize, length: usize) -> Range<usize> {
      let start = *cursor;
      *cursor += length;
      start..*cursor
    }

    let mut cursor = 0usize;
    let t = config.max_delta_length;
    let q = config.num_nonzero_entries();
    let h = config.image_height;
    let w = config.image_width;
    let rows = next(&mut cursor, t);
    let columns = next(&mut cursor, q);
    let deltas = next(&mut cursor, q);
    let rom_values = next(&mut cursor, q);
    let old_values = next(&mut cursor, t);
    let old_times = next(&mut cursor, t);
    let final_values = next(&mut cursor, h);
    let final_times = next(&mut cursor, h);
    let set_query_versions = next(&mut cursor, t);
    let set_final_versions = next(&mut cursor, t);
    let rom_multiplicities = next(&mut cursor, w);
    Self {
      rows,
      columns,
      deltas,
      rom_values,
      old_values,
      old_times,
      final_values,
      final_times,
      set_query_versions,
      set_final_versions,
      rom_multiplicities,
      total: cursor,
    }
  }
}

struct AllocatedChallenges<Scalar: PrimeField> {
  rom_address: AllocatedNum<Scalar>,
  rom_fraction: AllocatedNum<Scalar>,
  ram_address: AllocatedNum<Scalar>,
  ram_time: AllocatedNum<Scalar>,
  ram_offset: AllocatedNum<Scalar>,
  set_key: AllocatedNum<Scalar>,
  set_offset: AllocatedNum<Scalar>,
}

fn allocate_private<Scalar, CS>(
  cs: &mut CS,
  name: &str,
  value: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  AllocatedNum::alloc(cs.namespace(|| name.to_owned()), || Ok(value))
}

fn allocate_public<Scalar, CS>(
  cs: &mut CS,
  name: &str,
  value: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  AllocatedNum::alloc_input(cs.namespace(|| name.to_owned()), || Ok(value))
}

fn multiply_factors<Scalar, CS>(
  cs: &mut CS,
  label: &str,
  factors: &[LinearCombination<Scalar>],
  factor_values: &[Scalar],
) -> Result<(LinearCombination<Scalar>, Scalar), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  if factors.is_empty() || factors.len() != factor_values.len() {
    return Err(SynthesisError::Unsatisfiable);
  }

  let mut product_lc = factors[0].clone();
  let mut product_value = factor_values[0];
  for index in 1..factors.len() {
    product_value *= factor_values[index];
    let product = allocate_private(
      cs,
      &format!("{label} product {index}"),
      product_value,
    )?;
    cs.enforce(
      || format!("{label} product constraint {index}"),
      |lc| lc + &product_lc,
      |lc| lc + &factors[index],
      |lc| lc + product.get_variable(),
    );
    product_lc = LinearCombination::zero() + product.get_variable();
  }
  Ok((product_lc, product_value))
}

/// Enforces equality of two non-empty, equally sized factor products. The
/// final multiplication on the right outputs the existing left product, so
/// there is no separate equality constraint.
fn enforce_equal_products<Scalar, CS>(
  cs: &mut CS,
  label: &str,
  left_factors: &[LinearCombination<Scalar>],
  left_values: &[Scalar],
  right_factors: &[LinearCombination<Scalar>],
  right_values: &[Scalar],
) -> Result<(), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  if left_factors.is_empty()
    || left_factors.len() != left_values.len()
    || right_factors.len() != right_values.len()
    || left_factors.len() != right_factors.len()
  {
    return Err(SynthesisError::Unsatisfiable);
  }

  let (left_product, _) = multiply_factors(
    &mut cs.namespace(|| format!("{label} left product")),
    "left",
    left_factors,
    left_values,
  )?;

  if right_factors.len() == 1 {
    cs.enforce(
      || format!("{label} singleton product equality"),
      |lc| lc + CS::one(),
      |lc| lc + &right_factors[0],
      |lc| lc + &left_product,
    );
    return Ok(());
  }

  let last = right_factors.len() - 1;
  let (right_prefix, _) = multiply_factors(
    &mut cs.namespace(|| format!("{label} right product")),
    "right",
    &right_factors[..last],
    &right_values[..last],
  )?;
  cs.enforce(
    || format!("{label} product equality"),
    |lc| lc + &right_prefix,
    |lc| lc + &right_factors[last],
    |lc| lc + &left_product,
  );
  Ok(())
}

impl<E: Engine> SpartanCircuit<E> for SparseVectorMatrixVectorCircuit<E::Scalar> {
  fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
    Ok(self.expected_public_values())
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<E::Scalar>],
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    if !shared.is_empty() {
      return Err(SynthesisError::Unsatisfiable);
    }

    let mut allocated = Vec::with_capacity(self.config.expected_num_precommitted());
    for (index, &row) in self.packed.rows.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("row index {index}"),
        scalar_from_usize(row),
      )?);
    }
    for (index, &column) in self.packed.columns.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("column index {index}"),
        scalar_from_usize(column),
      )?);
    }
    for (index, &delta) in self.packed.values.iter().enumerate() {
      allocated.push(allocate_private(cs, &format!("delta {index}"), delta)?);
    }
    for (index, &value) in self.trace.rom_values.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("ROM returned value {index}"),
        value,
      )?);
    }
    for (index, &value) in self.trace.old_values.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("RAM old value {index}"),
        value,
      )?);
    }
    for (index, &time) in self.trace.old_times.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("RAM old time {index}"),
        time,
      )?);
    }
    for (index, &value) in self.trace.final_values.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("RAM final value {index}"),
        value,
      )?);
    }
    for (index, &time) in self.trace.final_times.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("RAM final time {index}"),
        time,
      )?);
    }
    for (index, &version) in self.trace.set_query_versions.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("valid-difference query version {index}"),
        version,
      )?);
    }
    for (index, &version) in self.trace.set_final_versions.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("valid-difference final version {index}"),
        version,
      )?);
    }
    for (index, &multiplicity) in self.trace.rom_multiplicities.iter().enumerate() {
      allocated.push(allocate_private(
        cs,
        &format!("ROM multiplicity {index}"),
        multiplicity,
      )?);
    }

    if allocated.len() != self.config.expected_num_precommitted() {
      return Err(SynthesisError::Unsatisfiable);
    }
    Ok(allocated)
  }

  fn num_challenges(&self) -> usize {
    // Prototype deviation requested by the caller: challenges are deterministic
    // public inputs below instead of transcript-generated challenges.
    0
  }

  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<E::Scalar>],
    precommitted: &[AllocatedNum<E::Scalar>],
    transcript_challenges: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    if !shared.is_empty()
      || transcript_challenges.is_some_and(|challenges| !challenges.is_empty())
    {
      return Err(SynthesisError::Unsatisfiable);
    }

    let layout = PrecommittedLayout::new(&self.config);
    if precommitted.len() != layout.total {
      return Err(SynthesisError::Unsatisfiable);
    }
    let rows = &precommitted[layout.rows.clone()];
    let columns = &precommitted[layout.columns.clone()];
    let deltas = &precommitted[layout.deltas.clone()];
    let rom_values = &precommitted[layout.rom_values.clone()];
    let old_values = &precommitted[layout.old_values.clone()];
    let old_times = &precommitted[layout.old_times.clone()];
    let final_values = &precommitted[layout.final_values.clone()];
    let final_times = &precommitted[layout.final_times.clone()];
    let set_query_versions = &precommitted[layout.set_query_versions.clone()];
    let set_final_versions = &precommitted[layout.set_final_versions.clone()];
    let rom_multiplicities = &precommitted[layout.rom_multiplicities.clone()];

    // Public statement values. This order exactly matches
    // `expected_public_values`.
    let target = allocate_public(cs, "target sparse product", self.target)?;
    let mut left_vector = Vec::with_capacity(self.config.image_height);
    for (index, &value) in self.left_vector.iter().enumerate() {
      left_vector.push(allocate_public(
        cs,
        &format!("left vector {index}"),
        value,
      )?);
    }
    let mut right_vector = Vec::with_capacity(self.config.image_width);
    for (index, &value) in self.right_vector.iter().enumerate() {
      right_vector.push(allocate_public(
        cs,
        &format!("right vector {index}"),
        value,
      )?);
    }
    let challenges = AllocatedChallenges {
      rom_address: allocate_public(
        cs,
        "fake ROM address challenge",
        self.challenges.rom_address,
      )?,
      rom_fraction: allocate_public(
        cs,
        "fake ROM fractional challenge",
        self.challenges.rom_fraction,
      )?,
      ram_address: allocate_public(
        cs,
        "fake RAM address challenge",
        self.challenges.ram_address,
      )?,
      ram_time: allocate_public(
        cs,
        "fake RAM time challenge",
        self.challenges.ram_time,
      )?,
      ram_offset: allocate_public(
        cs,
        "fake RAM offset challenge",
        self.challenges.ram_offset,
      )?,
      set_key: allocate_public(
        cs,
        "fake valid-difference key challenge",
        self.challenges.set_key,
      )?,
      set_offset: allocate_public(
        cs,
        "fake valid-difference offset challenge",
        self.challenges.set_offset,
      )?,
    };

    let q = self.config.num_nonzero_entries();
    let t = self.config.max_delta_length;
    let h = self.config.image_height;
    let w = self.config.image_width;

    // Sparse delta * ROM-returned-value products. Their batch sums are kept as
    // linear combinations and placed directly into the RAM write records.
    let mut sparse_products = Vec::with_capacity(q);
    for query in 0..q {
      let product_value = self.packed.values[query] * self.trace.rom_values[query];
      let product = allocate_private(
        cs,
        &format!("sparse product {query}"),
        product_value,
      )?;
      cs.enforce(
        || format!("sparse product constraint {query}"),
        |lc| lc + deltas[query].get_variable(),
        |lc| lc + rom_values[query].get_variable(),
        |lc| lc + product.get_variable(),
      );
      sparse_products.push(product);
    }

    // LogUp ROM over the full (address, value) tuple. Multiplying the allocated
    // public address challenge by every secret address costs Q constraints.
    let mut query_running_sum = E::Scalar::ZERO;
    let mut query_previous: Option<AllocatedNum<E::Scalar>> = None;
    for query in 0..q {
      let address_term_value =
        self.challenges.rom_address * scalar_from_usize::<E::Scalar>(self.packed.columns[query]);
      let address_term = allocate_private(
        cs,
        &format!("ROM compressed address {query}"),
        address_term_value,
      )?;
      cs.enforce(
        || format!("ROM address challenge multiplication {query}"),
        |lc| lc + columns[query].get_variable(),
        |lc| lc + challenges.rom_address.get_variable(),
        |lc| lc + address_term.get_variable(),
      );

      let denominator_value = self.challenges.rom_fraction
        + self.trace.rom_values[query]
        + address_term_value;
      query_running_sum += denominator_value
        .invert()
        .unwrap_or(E::Scalar::ZERO);
      let next_sum = allocate_private(
        cs,
        &format!("ROM query running sum {query}"),
        query_running_sum,
      )?;
      cs.enforce(
        || format!("ROM query LogUp recurrence {query}"),
        |lc| {
          let lc = lc + next_sum.get_variable();
          if let Some(previous) = &query_previous {
            lc - previous.get_variable()
          } else {
            lc
          }
        },
        |lc| {
          lc + challenges.rom_fraction.get_variable()
            + rom_values[query].get_variable()
            + address_term.get_variable()
        },
        |lc| lc + CS::one(),
      );
      query_previous = Some(next_sum);
    }
    let query_sum = query_previous.ok_or(SynthesisError::Unsatisfiable)?;

    // The final table recurrence writes directly to the query sum, fusing the
    // usual LogUp equality constraint.
    let mut table_running_sum = E::Scalar::ZERO;
    let mut table_previous: Option<AllocatedNum<E::Scalar>> = None;
    for address in 0..w {
      let address_scalar = scalar_from_usize::<E::Scalar>(address);
      let denominator_value = self.challenges.rom_fraction
        + self.right_vector[address]
        + self.challenges.rom_address * address_scalar;
      if address + 1 == w {
        cs.enforce(
          || format!("ROM final table LogUp recurrence {address}"),
          |lc| {
            let lc = lc + query_sum.get_variable();
            if let Some(previous) = &table_previous {
              lc - previous.get_variable()
            } else {
              lc
            }
          },
          |lc| {
            lc + challenges.rom_fraction.get_variable()
              + right_vector[address].get_variable()
              + (address_scalar, challenges.rom_address.get_variable())
          },
          |lc| lc + rom_multiplicities[address].get_variable(),
        );
      } else {
        table_running_sum += self.trace.rom_multiplicities[address]
          * denominator_value
            .invert()
            .unwrap_or(E::Scalar::ZERO);
        let next_sum = allocate_private(
          cs,
          &format!("ROM table running sum {address}"),
          table_running_sum,
        )?;
        cs.enforce(
          || format!("ROM table LogUp recurrence {address}"),
          |lc| {
            let lc = lc + next_sum.get_variable();
            if let Some(previous) = &table_previous {
              lc - previous.get_variable()
            } else {
              lc
            }
          },
          |lc| {
            lc + challenges.rom_fraction.get_variable()
              + right_vector[address].get_variable()
              + (address_scalar, challenges.rom_address.get_variable())
          },
          |lc| lc + rom_multiplicities[address].get_variable(),
        );
        table_previous = Some(next_sum);
      }
    }

    // First RAM shuffle. Writes are setup records plus each access's constrained
    // `old + batch_sum`; reads are each access plus a fixed-address teardown.
    let mut ram_read_factors = Vec::with_capacity(t + h);
    let mut ram_read_values = Vec::with_capacity(t + h);
    let mut ram_write_factors = Vec::with_capacity(t + h);
    let mut ram_write_values = Vec::with_capacity(t + h);
    for address in 0..h {
      let address_scalar = scalar_from_usize::<E::Scalar>(address);
      ram_write_factors.push(
        LinearCombination::zero()
          + challenges.ram_offset.get_variable()
          + (address_scalar, challenges.ram_address.get_variable()),
      );
      ram_write_values.push(
        self.challenges.ram_offset + self.challenges.ram_address * address_scalar,
      );
    }
    for batch in 0..t {
      let address_term_value =
        self.challenges.ram_address * scalar_from_usize::<E::Scalar>(self.packed.rows[batch]);
      let address_term = allocate_private(
        cs,
        &format!("RAM compressed access address {batch}"),
        address_term_value,
      )?;
      cs.enforce(
        || format!("RAM address challenge multiplication {batch}"),
        |lc| lc + rows[batch].get_variable(),
        |lc| lc + challenges.ram_address.get_variable(),
        |lc| lc + address_term.get_variable(),
      );

      let old_time_term_value = self.challenges.ram_time * self.trace.old_times[batch];
      let old_time_term = allocate_private(
        cs,
        &format!("RAM compressed old time {batch}"),
        old_time_term_value,
      )?;
      cs.enforce(
        || format!("RAM old-time challenge multiplication {batch}"),
        |lc| lc + old_times[batch].get_variable(),
        |lc| lc + challenges.ram_time.get_variable(),
        |lc| lc + old_time_term.get_variable(),
      );

      ram_read_factors.push(
        LinearCombination::zero()
          + challenges.ram_offset.get_variable()
          + old_values[batch].get_variable()
          + address_term.get_variable()
          + old_time_term.get_variable(),
      );
      ram_read_values.push(
        self.challenges.ram_offset
          + self.trace.old_values[batch]
          + address_term_value
          + old_time_term_value,
      );

      let clock = scalar_from_usize::<E::Scalar>(batch + 1);
      let mut write_factor = LinearCombination::zero()
        + challenges.ram_offset.get_variable()
        + old_values[batch].get_variable()
        + address_term.get_variable()
        + (clock, challenges.ram_time.get_variable());
      let base = batch * self.config.batch_size;
      for slot in 0..self.config.batch_size {
        write_factor = write_factor + sparse_products[base + slot].get_variable();
      }
      ram_write_factors.push(write_factor);
      ram_write_values.push(
        self.challenges.ram_offset
          + self.trace.old_values[batch]
          + self.trace.batch_sums[batch]
          + address_term_value
          + self.challenges.ram_time * clock,
      );
    }
    for address in 0..h {
      let final_time_term_value =
        self.challenges.ram_time * self.trace.final_times[address];
      let final_time_term = allocate_private(
        cs,
        &format!("RAM compressed final time {address}"),
        final_time_term_value,
      )?;
      cs.enforce(
        || format!("RAM final-time challenge multiplication {address}"),
        |lc| lc + final_times[address].get_variable(),
        |lc| lc + challenges.ram_time.get_variable(),
        |lc| lc + final_time_term.get_variable(),
      );
      let address_scalar = scalar_from_usize::<E::Scalar>(address);
      ram_read_factors.push(
        LinearCombination::zero()
          + challenges.ram_offset.get_variable()
          + final_values[address].get_variable()
          + (address_scalar, challenges.ram_address.get_variable())
          + final_time_term.get_variable(),
      );
      ram_read_values.push(
        self.challenges.ram_offset
          + self.trace.final_values[address]
          + self.challenges.ram_address * address_scalar
          + final_time_term_value,
      );
    }
    enforce_equal_products(
      &mut cs.namespace(|| "main RAM shuffle"),
      "main RAM",
      &ram_read_factors,
      &ram_read_values,
      &ram_write_factors,
      &ram_write_values,
    )?;

    // Second shuffle: versioned read-only set for valid positive differences
    // {1, ..., T}. The key is literally `clock - old_time`, not a free witness.
    let mut set_read_factors = Vec::with_capacity(2 * t);
    let mut set_read_values = Vec::with_capacity(2 * t);
    let mut set_write_factors = Vec::with_capacity(2 * t);
    let mut set_write_values = Vec::with_capacity(2 * t);
    for key in 1..=t {
      let key_scalar = scalar_from_usize::<E::Scalar>(key);
      set_write_factors.push(
        LinearCombination::zero()
          + challenges.set_offset.get_variable()
          + (key_scalar, challenges.set_key.get_variable()),
      );
      set_write_values.push(
        self.challenges.set_offset + self.challenges.set_key * key_scalar,
      );
    }
    for batch in 0..t {
      let clock = scalar_from_usize::<E::Scalar>(batch + 1);
      let diff_value = clock - self.trace.old_times[batch];
      let key_term_value = self.challenges.set_key * diff_value;
      let key_term = allocate_private(
        cs,
        &format!("valid-difference compressed key {batch}"),
        key_term_value,
      )?;
      cs.enforce(
        || format!("valid-difference key challenge multiplication {batch}"),
        |lc| lc + (clock, CS::one()) - old_times[batch].get_variable(),
        |lc| lc + challenges.set_key.get_variable(),
        |lc| lc + key_term.get_variable(),
      );

      let read_factor = LinearCombination::zero()
        + challenges.set_offset.get_variable()
        + key_term.get_variable()
        + set_query_versions[batch].get_variable();
      let read_value = self.challenges.set_offset
        + key_term_value
        + self.trace.set_query_versions[batch];
      set_read_factors.push(read_factor.clone());
      set_read_values.push(read_value);
      set_write_factors.push(read_factor + (E::Scalar::ONE, CS::one()));
      set_write_values.push(read_value + E::Scalar::ONE);
    }
    for key in 1..=t {
      let key_scalar = scalar_from_usize::<E::Scalar>(key);
      set_read_factors.push(
        LinearCombination::zero()
          + challenges.set_offset.get_variable()
          + (key_scalar, challenges.set_key.get_variable())
          + set_final_versions[key - 1].get_variable(),
      );
      set_read_values.push(
        self.challenges.set_offset
          + self.challenges.set_key * key_scalar
          + self.trace.set_final_versions[key - 1],
      );
    }
    enforce_equal_products(
      &mut cs.namespace(|| "valid-difference set shuffle"),
      "valid-difference set",
      &set_read_factors,
      &set_read_values,
      &set_write_factors,
      &set_write_values,
    )?;

    // Final left^T * delta_as. The last multiplication outputs
    // `target - previous_products`, fusing the final equality constraint.
    let mut dot_products = Vec::with_capacity(h.saturating_sub(1));
    for row in 0..h - 1 {
      let product_value = self.left_vector[row] * self.trace.final_values[row];
      let product = allocate_private(
        cs,
        &format!("final dot product {row}"),
        product_value,
      )?;
      cs.enforce(
        || format!("final dot product constraint {row}"),
        |lc| lc + left_vector[row].get_variable(),
        |lc| lc + final_values[row].get_variable(),
        |lc| lc + product.get_variable(),
      );
      dot_products.push(product);
    }
    let last = h - 1;
    cs.enforce(
      || "final sparse vector-matrix-vector equality",
      |lc| lc + left_vector[last].get_variable(),
      |lc| lc + final_values[last].get_variable(),
      |lc| {
        dot_products
          .iter()
          .fold(lc + target.get_variable(), |sum, product| {
            sum - product.get_variable()
          })
      },
    );

    Ok(())
  }
}

#[cfg(test)]
mod memory_argument_tests {
  use super::*;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use spartan2::{
    provider::T256HyraxEngine,
    traits::{Engine, circuit::SpartanCircuit},
  };

  type E = T256HyraxEngine;
  type Scalar = <E as Engine>::Scalar;

  fn scalar(value: u64) -> Scalar {
    Scalar::from_u128(value as u128)
  }

  fn fixture() -> SparseVectorMatrixVectorCircuit<Scalar> {
    let config = SparseProductConfig::new(3, 5, 4, 3);
    let entries = [
      (1, 0, 4),
      (1, 2, 2),
      (1, 2, 3),
      (1, 4, 5),
      (1, 1, 1),
      (2, 3, 1),
      (2, 0, 2),
    ]
    .into_iter()
    .map(|(row, column, value)| SparseMatrixEntry::new(row, column, scalar(value)))
    .collect();
    SparseVectorMatrixVectorCircuit::from_entries_with_target(
      config,
      entries,
      vec![scalar(2), scalar(5), scalar(7)],
      vec![scalar(3), scalar(11), scalar(13), scalar(17), scalar(19)],
      scalar(1076),
      0x5a17_2000,
    )
    .unwrap()
  }

  fn synthesize(
    circuit: &SparseVectorMatrixVectorCircuit<Scalar>,
  ) -> TestConstraintSystem<Scalar> {
    let mut cs = TestConstraintSystem::new();
    let shared =
      <SparseVectorMatrixVectorCircuit<Scalar> as SpartanCircuit<E>>::shared(circuit, &mut cs)
        .unwrap();
    let precommitted =
      <SparseVectorMatrixVectorCircuit<Scalar> as SpartanCircuit<E>>::precommitted(
        circuit,
        &mut cs,
        &shared,
      )
      .unwrap();
    <SparseVectorMatrixVectorCircuit<Scalar> as SpartanCircuit<E>>::synthesize(
      circuit,
      &mut cs,
      &shared,
      &precommitted,
      Some(&[]),
    )
    .unwrap();
    cs
  }

  #[test]
  fn rom_binds_address_and_value_together() {
    let mut circuit = fixture();

    // Cross-wire query (column=2) to value right[1]=11. Adjust every arithmetic
    // and RAM witness affected by that value so only the ROM tuple is invalid.
    circuit.trace.rom_values[1] = scalar(11);
    circuit.trace.batch_sums[0] = scalar(73);
    circuit.trace.old_values[1] = scalar(73);
    circuit.trace.final_values[1] = scalar(179);
    circuit.computed_product = scalar(1056);
    circuit.target = scalar(1056);

    let cs = synthesize(&circuit);
    assert!(!cs.is_satisfied());
    assert!(cs.which_is_unsatisfied().unwrap().contains("ROM"));
  }

  #[test]
  fn rom_rejects_an_out_of_range_zero_padding_address() {
    let mut circuit = fixture();
    let outer_padding_query = 3 * circuit.config.batch_size;
    circuit.packed.columns[outer_padding_query] = circuit.config.image_width;

    let cs = synthesize(&circuit);
    assert!(!cs.is_satisfied());
    assert!(cs.which_is_unsatisfied().unwrap().contains("ROM"));
  }

  #[test]
  fn main_ram_shuffle_rejects_broken_repeated_row_continuity() {
    let mut circuit = fixture();

    // The second row-1 batch falsely reads zero instead of the first batch's
    // value 77. Its local write and final dot product are made self-consistent;
    // only the RAM record chain is broken.
    circuit.trace.old_values[1] = scalar(0);
    circuit.trace.final_values[1] = scalar(106);
    circuit.computed_product = scalar(691);
    circuit.target = scalar(691);

    let cs = synthesize(&circuit);
    assert!(!cs.is_satisfied());
    assert!(cs.which_is_unsatisfied().unwrap().contains("main RAM"));
  }

  #[test]
  fn main_ram_shuffle_rejects_an_out_of_range_padding_row() {
    let mut circuit = fixture();
    circuit.packed.rows[3] = circuit.config.image_height;

    let cs = synthesize(&circuit);
    assert!(!cs.is_satisfied());
    assert!(cs.which_is_unsatisfied().unwrap().contains("main RAM"));
  }

  #[test]
  fn second_shuffle_rejects_a_future_read_cycle() {
    let config = SparseProductConfig::new(1, 1, 2, 1);
    let entries = vec![
      SparseMatrixEntry::new(0, 0, scalar(0)),
      SparseMatrixEntry::new(0, 0, scalar(0)),
    ];
    let mut circuit = SparseVectorMatrixVectorCircuit::from_entries_with_target(
      config,
      entries,
      vec![scalar(1)],
      vec![scalar(1)],
      scalar(0),
      0x5a17_3000,
    )
    .unwrap();

    // Reads at times [2,1] and teardown at time 0 are still exactly a
    // permutation of writes at times [0,1,2]. The first access nevertheless
    // reads from the future, so only the valid-difference set should reject it.
    circuit.trace.old_times[0] = scalar(2);
    circuit.trace.old_times[1] = scalar(1);
    circuit.trace.final_times[0] = scalar(0);

    let cs = synthesize(&circuit);
    assert!(!cs.is_satisfied());
    assert!(
      cs.which_is_unsatisfied()
        .unwrap()
        .contains("valid-difference"),
    );
  }
}
