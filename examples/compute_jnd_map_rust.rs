// Rust port of the JND map computation from scripts/jnd_diff.py.
//
// Implements the model from Wu et al., "Enhanced Just Noticeable Difference
// Model for Images With Pattern Complexity," IEEE TIP 2017.
//
// Run from the repo root with:
//   RUSTFLAGS="-C target-cpu=native" cargo run --example compute_jnd_map_rust --release

use image::{GrayImage, ImageBuffer, Luma};
use imageproc::distance_transform::Norm;
use imageproc::edges::canny;
use imageproc::morphology::dilate;
use ndarray::Array2;
use rayon::prelude::*;
use std::f32::consts::PI;
use std::path::{Path, PathBuf};
use std::time::Instant;

const EPS: f32 = 1e-6;

fn lum_jnd_lut() -> [f32; 256] {
  let (t0, gamma) = (17.0f32, 3.0f32 / 128.0);
  std::array::from_fn(|k| {
    if k < 127 {
      t0 * (1.0 - (k as f32 / 127.0).sqrt()) + 3.0
    } else {
      gamma * (k as f32 - 127.0) + 3.0
    }
  })
}

// Zero-padded 2-D cross-correlation (mirrors scipy.ndimage.correlate mode="constant").
fn correlate_2d(input: &Array2<f32>, kernel: &Array2<f32>) -> Array2<f32> {
  let (ih, iw) = input.dim();
  let (kh, kw) = kernel.dim();
  let ch = (kh / 2) as isize;
  let cw = (kw / 2) as isize;
  Array2::from_shape_fn((ih, iw), |(i, j)| {
    let mut sum = 0.0f32;
    for ki in 0..kh {
      for kj in 0..kw {
        let si = i as isize + ki as isize - ch;
        let sj = j as isize + kj as isize - cw;
        if si >= 0 && si < ih as isize && sj >= 0 && sj < iw as isize {
          sum += input[[si as usize, sj as usize]] * kernel[[ki, kj]];
        }
      }
    }
    sum
  })
}

// Normalised Gaussian kernel — matches scipy.stats.norm.pdf outer product.
fn gkern(kernlen: usize, nsig: f32) -> Array2<f32> {
  let pdf: Vec<f32> = (0..kernlen)
    .map(|i| {
      let x = if kernlen > 1 {
        -nsig + 2.0 * nsig * i as f32 / (kernlen - 1) as f32
      } else {
        0.0
      };
      (-x * x / 2.0).exp()
    })
    .collect();
  let outer = Array2::from_shape_fn((kernlen, kernlen), |(i, j)| pdf[i] * pdf[j]);
  let s = outer.sum();
  outer / s
}

// Symmetric (mirror) padding — matches numpy pad mode='symmetric'.
fn pad_symmetric(img: &Array2<f32>, pad: usize) -> Array2<f32> {
  let (h, w) = img.dim();
  let reflect = |i: isize, len: usize| -> usize {
    if i < 0 {
      ((-i) - 1).min(len as isize - 1) as usize
    } else if i >= len as isize {
      (2 * len as isize - i - 1).max(0) as usize
    } else {
      i as usize
    }
  };
  Array2::from_shape_fn((h + 2 * pad, w + 2 * pad), |(i, j)| {
    let si = reflect(i as isize - pad as isize, h);
    let sj = reflect(j as isize - pad as isize, w);
    img[[si, sj]]
  })
}

fn bg_lum_jnd(img: &Array2<f32>) -> Array2<f32> {
  let lut = lum_jnd_lut();
  let min_lum = 32.0f32;
  #[rustfmt::skip]
  let b_kernel = Array2::from_shape_vec((5, 5), vec![
    1.0, 1.0, 1.0, 1.0, 1.0,
    1.0, 2.0, 2.0, 2.0, 1.0,
    1.0, 2.0, 0.0, 2.0, 1.0,
    1.0, 2.0, 2.0, 2.0, 1.0,
    1.0, 1.0, 1.0, 1.0, 1.0,
  ]).unwrap();

  let bg_raw = correlate_2d(img, &b_kernel).mapv(|v| (v / 32.0).floor());
  let adapt = bg_raw.mapv(|v| (min_lum + v * (127.0 - min_lum) / 127.0 + EPS).round());

  let bg = Array2::from_shape_fn(img.dim(), |(i, j)| {
    if bg_raw[[i, j]] <= 127.0 { adapt[[i, j]] } else { bg_raw[[i, j]] }
  });

  bg.mapv(|v| 0.7 * lut[v.clamp(0.0, 255.0) as usize])
}

fn luminance_contrast(img: &Array2<f32>) -> Array2<f32> {
  let r = 2usize;
  let side = 2 * r + 1;
  let ker = Array2::from_elem((side, side), 1.0 / (side * side) as f32);
  let mean = correlate_2d(img, &ker);
  let sq_mean = correlate_2d(&img.mapv(|v| v * v), &ker);
  let (h, w) = img.dim();
  Array2::from_shape_fn((h, w), |(i, j)| {
    if i < r || i >= h - r || j < r || j >= w - r {
      0.0
    } else {
      (sq_mean[[i, j]] - mean[[i, j]] * mean[[i, j]]).max(0.0).sqrt()
    }
  })
}

fn ori_complexity(img: &Array2<f32>) -> Array2<f32> {
  let r = 1usize;
  let nb = 8usize;
  let otr = 6.0f32;

  let kx = Array2::from_shape_vec(
    (3, 3),
    vec![-1.0/3.0, 0.0, 1.0/3.0, -1.0/3.0, 0.0, 1.0/3.0, -1.0/3.0, 0.0, 1.0/3.0],
  ).unwrap();
  let ky = kx.t().to_owned();

  // 8 neighbor (dx,dy) offsets into the padded image for output pixel (i,j).
  // In Python: On = O_norm[dx:h-2r+dx, dy:w-2r+dy], so lookup at (dx+i, dy+j).
  let at = 2.0 * PI / nb as f32;
  let neighbor_offsets: Vec<(usize, usize)> = (0..nb)
    .map(|n| {
      let dx = (r as f32 + -(r as f32) * (n as f32 * at).sin() + EPS).round() as usize;
      let dy = (r as f32 + (r as f32) * (n as f32 * at).cos() + EPS).round() as usize;
      (dx, dy)
    })
    .collect();

  let imgd = pad_symmetric(img, r);
  let (ph, pw) = imgd.dim();
  let (oh, ow) = img.dim();

  let gx = correlate_2d(&imgd, &kx);
  let gy = correlate_2d(&imgd, &ky);

  // Edge validity and normalised orientation bin (int) on the padded image.
  let cv = Array2::from_shape_fn((ph, pw), |(i, j)| {
    (gx[[i, j]] * gx[[i, j]] + gy[[i, j]] * gy[[i, j]]).sqrt() >= 5.0
  });
  let o_norm = Array2::from_shape_fn((ph, pw), |(i, j)| -> i32 {
    let angle = if cv[[i, j]] {
      let mut a = (gy[[i, j]].atan2(gx[[i, j]]) / PI * 180.0 + EPS).round();
      if a > 90.0 { a -= 180.0; }
      if a < -90.0 { a += 180.0; }
      a + 90.0
    } else {
      180.0 + 2.0 * otr  // invalid bin marker
    };
    (angle / 2.0 / otr + EPS).round() as i32
  });

  // onum = 16, num_bins = 17  (bins 0–15 = valid orientations, 16 = invalid)
  let onum = (180.0f32 / 2.0 / otr).round() as usize + 1;
  let num_bins = onum + 1;

  let cvc = cv.slice(ndarray::s![r..r + oh, r..r + ow]).to_owned();

  let mut cmlx = Array2::<f32>::zeros((oh, ow));
  for i in 0..oh {
    for j in 0..ow {
      if !cvc[[i, j]] {
        cmlx[[i, j]] = 1.0;
        continue;
      }
      let mut seen = [false; 32];
      // Center is at padded position (i+r, j+r).
      seen[o_norm[[i + r, j + r]].clamp(0, num_bins as i32 - 1) as usize] = true;
      for &(dx, dy) in &neighbor_offsets {
        seen[o_norm[[dx + i, dy + j]].clamp(0, num_bins as i32 - 1) as usize] = true;
      }
      cmlx[[i, j]] = seen[..num_bins].iter().filter(|&&v| v).count() as f32;
    }
  }

  // Border pixels and non-edge pixels → complexity = 1 (matches Python cmlx[:r,:] = 1 etc.)
  for j in 0..ow { cmlx[[0, j]] = 1.0; cmlx[[oh - 1, j]] = 1.0; }
  for i in 0..oh { cmlx[[i, 0]] = 1.0; cmlx[[i, ow - 1]] = 1.0; }

  correlate_2d(&cmlx, &gkern(3, 1.0))
}

fn edge_protect(img: &Array2<f32>) -> Array2<f32> {
  let (h, w) = img.dim();

  #[rustfmt::skip]
  let kernels: Vec<Array2<f32>> = [
    vec![ 0.,  0.,  0.,  0.,  0.,  1.,  3.,  8.,  3.,  1.,  0.,  0.,  0.,  0.,  0., -1., -3., -8., -3., -1.,  0.,  0.,  0.,  0.,  0.],
    vec![ 0.,  0.,  1.,  0.,  0.,  0.,  8.,  3.,  0.,  0.,  1.,  3.,  0., -3., -1.,  0.,  0., -3., -8.,  0.,  0.,  0., -1.,  0.,  0.],
    vec![ 0.,  0.,  1.,  0.,  0.,  0.,  0.,  3.,  8.,  0., -1., -3.,  0.,  3.,  1.,  0., -8., -3.,  0.,  0.,  0.,  0., -1.,  0.,  0.],
    vec![ 0.,  1.,  0., -1.,  0.,  0.,  3.,  0., -3.,  0.,  0.,  8.,  0., -8.,  0.,  0.,  3.,  0., -3.,  0.,  0.,  1.,  0., -1.,  0.],
  ].into_iter()
    .map(|d| Array2::from_shape_vec((5, 5), d).unwrap())
    .collect();

  let mut max_grad = Array2::<f32>::zeros((h, w));
  for ker in &kernels {
    let g = correlate_2d(img, ker).mapv(|v| (v / 16.0).abs());
    for i in 0..h {
      for j in 0..w {
        if g[[i, j]] > max_grad[[i, j]] { max_grad[[i, j]] = g[[i, j]]; }
      }
    }
  }

  // Crop inner region and re-pad symmetrically (removes border convolution artefacts).
  let inner = max_grad.slice(ndarray::s![2..h - 2, 2..w - 2]).to_owned();
  let max_grad = pad_symmetric(&inner, 2);

  let global_max = max_grad.iter().cloned().fold(0.0f32, f32::max);
  let edge_threshold = (60.0 / (global_max + EPS)).min(0.8);

  let low = 0.4 * edge_threshold * 255.0;
  let high = edge_threshold * 255.0;

  let gray_img: GrayImage = ImageBuffer::from_fn(w as u32, h as u32, |x, y| {
    Luma([img[[y as usize, x as usize]].clamp(0.0, 255.0) as u8])
  });
  let edge_img = canny(&gray_img, low, high);
  // Approximate skimage disk(3) with imageproc L1 norm, k=3.
  let dilated = dilate(&edge_img, Norm::L1, 3);

  let not_edge = Array2::from_shape_fn((h, w), |(i, j)| {
    if dilated.get_pixel(j as u32, i as u32)[0] > 0 { 0.0f32 } else { 1.0 }
  });

  correlate_2d(&not_edge, &gkern(5, 0.8))
}

// ── public entry point ───────────────────────────────────────────────────────

pub fn compute_jnd_map(img: &Array2<f32>) -> Array2<f32> {
  let jnd_la = bg_lum_jnd(img);
  let l_c = luminance_contrast(img);

  let (alpha, beta_sq) = (0.115f32 * 16.0, 26.0f32 * 26.0);
  let jnd_lc = l_c.mapv(|lc| (alpha * lc.powf(2.4)) / (lc * lc + beta_sq));

  let p_c = ori_complexity(img);
  let (a1, a2) = (0.3f32, 2.7f32);
  let c_t = p_c.mapv(|pc| (a1 * pc.powf(a2)) / (pc * pc + 1.0));

  let ep = edge_protect(img);
  let jnd_pm = Array2::from_shape_fn(img.dim(), |(i, j)| l_c[[i, j]] * c_t[[i, j]] * ep[[i, j]]);
  let jnd_vm = Array2::from_shape_fn(img.dim(), |(i, j)| jnd_lc[[i, j]].max(jnd_pm[[i, j]]));

  Array2::from_shape_fn(img.dim(), |(i, j)| {
    let (la, vm) = (jnd_la[[i, j]], jnd_vm[[i, j]]);
    la + vm - 0.3 * la.min(vm)
  })
}

fn load_gray(path: &Path) -> Array2<f32> {
  let img = image::open(path)
    .unwrap_or_else(|_| panic!("cannot open {}", path.display()))
    .to_luma8();
  let (w, h) = img.dimensions();
  Array2::from_shape_fn((h as usize, w as usize), |(i, j)| {
    img.get_pixel(j as u32, i as u32)[0] as f32
  })
}

fn save_jnd(map: &Array2<f32>, path: &Path) {
  let (h, w) = map.dim();
  let img: GrayImage = ImageBuffer::from_fn(w as u32, h as u32, |x, y| {
    Luma([map[[y as usize, x as usize]].floor().clamp(0.0, 255.0) as u8])
  });
  img.save(path).unwrap_or_else(|_| panic!("cannot save {}", path.display()));
}

fn main() {
  let edited_frames_dir = Path::new("video_data/edited_video_frames");
  let jnd_maps_dir = Path::new("video_data/jnd_maps");

  std::fs::create_dir_all(jnd_maps_dir).expect("cannot create jnd_maps dir");

  let mut frame_paths: Vec<PathBuf> = std::fs::read_dir(edited_frames_dir)
    .expect("cannot read edited_video_frames dir")
    .filter_map(|e| e.ok())
    .map(|e| e.path())
    .filter(|p| p.extension().map_or(false, |e| e == "png"))
    .collect();
  frame_paths.sort();

  println!("Processing {} frames in parallel...", frame_paths.len());
  let overall = Instant::now();

  let timings: Vec<std::time::Duration> = frame_paths
    .par_iter()
    .map(|frame_path| {
      let img = load_gray(frame_path);
      let t0 = Instant::now();
      let jnd_map = compute_jnd_map(&img);
      let elapsed = t0.elapsed();

      let stem = frame_path.file_stem().unwrap().to_str().unwrap();
      let num = stem.split_once('_').map(|(_, n)| n).unwrap_or(stem);
      save_jnd(&jnd_map, &jnd_maps_dir.join(format!("jnd_{num}.png")));
      elapsed
    })
    .collect();

  let n = timings.len() as f64;
  let total_compute: f64 = timings.iter().map(|d| d.as_secs_f64()).sum();
  let mean_ms = total_compute / n * 1000.0;
  let min_ms = timings.iter().map(|d| d.as_secs_f64() * 1000.0).fold(f64::INFINITY, f64::min);
  let max_ms = timings.iter().map(|d| d.as_secs_f64() * 1000.0).fold(0.0f64, f64::max);

  println!(
    "\nDone in {:.1}s wall time  |  compute: mean {mean_ms:.1}ms  min {min_ms:.1}ms  max {max_ms:.1}ms",
    overall.elapsed().as_secs_f64(),
  );
}
