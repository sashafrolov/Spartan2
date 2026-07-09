// Simple test file. I wanted to test what the artifacts that arise from the differences between
// our grayscale implementation and FFmpeg's look like, and then whether they compress well.
// Unfortunately, I don't think they do.

#[path = "circuits/utils.rs"]
mod utils;
use utils::read_mono_png;

use image::GrayImage;
use rayon::prelude::*;
use std::{fs, path::Path};

fn main() {
  let source_dir = "video_data/edited_video_frames";
  let ffmpeg_dir = "video_data/redecoded_videos";
  let jnd_dir = "video_data/jnd_maps";
  let output_dir = "video_data/video_differences";

  fs::create_dir_all(output_dir).expect("failed to create output directory");

  let mut frame_entries: Vec<_> = fs::read_dir(source_dir)
    .expect("failed to read edited_video_frames directory")
    .filter_map(|e| e.ok())
    .filter(|e| {
      e.path()
        .extension()
        .map(|ext| ext == "png")
        .unwrap_or(false)
    })
    .collect();
  frame_entries.sort_by_key(|e| e.file_name());

  for entry in &frame_entries {
    let frame_path = entry.path();
    let filename = entry.file_name();
    let filename_str = filename.to_string_lossy();

    let source_image = read_mono_png(frame_path.to_str().expect("non-UTF8 path"));

    let ffmpeg_path = Path::new(ffmpeg_dir).join(&*filename_str);
    let ffmpeg_image = read_mono_png(ffmpeg_path.to_str().expect("non-UTF8 path"));

    let jnd_filename = filename_str.replace("frame_", "jnd_");
    let jnd_path = Path::new(jnd_dir).join(&*jnd_filename);
    let jnd_map = read_mono_png(jnd_path.to_str().expect("non-UTF8 path"));

    assert_eq!(
      source_image.len(),
      ffmpeg_image.len(),
      "height mismatch for {filename_str}"
    );
    assert_eq!(
      source_image[0].len(),
      ffmpeg_image[0].len(),
      "width mismatch for {filename_str}"
    );
    assert_eq!(
      source_image.len(),
      jnd_map.len(),
      "jnd height mismatch for {filename_str}"
    );
    assert_eq!(
      source_image[0].len(),
      jnd_map[0].len(),
      "jnd width mismatch for {filename_str}"
    );

    let height = source_image.len() as u32;
    let width = source_image[0].len() as u32;

    let mut diff_pixels = vec![0u8; (height * width) as usize];
    diff_pixels
      .par_chunks_mut(width as usize)
      .zip(
        source_image
          .par_iter()
          .zip(ffmpeg_image.par_iter())
          .zip(jnd_map.par_iter()),
      )
      .for_each(|(chunk, ((source_row, ffmpeg_row), jnd_row))| {
        for (out, ((&s, &f), &jnd)) in chunk
          .iter_mut()
          .zip(source_row.iter().zip(ffmpeg_row.iter()).zip(jnd_row.iter()))
        {
          let signed_diff = s as i16 - f as i16;
          let abs_diff = signed_diff.unsigned_abs();
          *out = if abs_diff <= jnd as u16 {
            0
          } else if signed_diff < 0 {
            (256i16 + signed_diff) as u8
          } else {
            signed_diff as u8
          };
        }
      });
    let diff_image = GrayImage::from_raw(width, height, diff_pixels).expect("buffer size mismatch");

    let nonzero_count = diff_image.iter().filter(|&&p| p != 0).count();

    let output_path = Path::new(output_dir).join(&*filename_str);
    diff_image
      .save(&output_path)
      .unwrap_or_else(|e| panic!("failed to save {}: {e}", output_path.display()));

    println!("Processed {filename_str}: {nonzero_count} nonzero differences");
  }

  println!("Done. Difference images written to {output_dir}");
}
