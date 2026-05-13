// Simple test file. I wanted to test what the artifacts that arise from the differences between
// our grayscale implementation and FFmpeg's look like, and then whether they compress well.
// Unfortunately, I don't think they do.

#[path = "circuits/utils.rs"]
mod utils;
use utils::{read_color_png, read_mono_png};

use image::GrayImage;
use rayon::prelude::*;
use std::fs;
use std::path::Path;

fn main() {
    let decomposed_dir = "video_data/decomposed_frames";
    let edited_dir = "video_data/edited_video_frames";
    let output_dir = "video_data/video_differences";

    fs::create_dir_all(output_dir).expect("failed to create output directory");

    let mut frame_entries: Vec<_> = fs::read_dir(decomposed_dir)
        .expect("failed to read decomposed_frames directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "png").unwrap_or(false))
        .collect();
    frame_entries.sort_by_key(|e| e.file_name());

    for entry in &frame_entries {
        let frame_path = entry.path();
        let filename = entry.file_name();
        let filename_str = filename.to_string_lossy();

        let color_image = read_color_png(frame_path.to_str().expect("non-UTF8 path"));

        let grayscaled: Vec<Vec<u8>> = color_image
            .par_iter()
            .map(|row| {
                row.iter()
                    .map(|&(r, g, b)| {
                        ((r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000) as u8
                    })
                    .collect()
            })
            .collect();

        let edited_path = Path::new(edited_dir).join(&*filename_str);
        let edited_image = read_mono_png(edited_path.to_str().expect("non-UTF8 path"));

        assert_eq!(
            grayscaled.len(),
            edited_image.len(),
            "height mismatch for {filename_str}"
        );
        assert_eq!(
            grayscaled[0].len(),
            edited_image[0].len(),
            "width mismatch for {filename_str}"
        );

        let height = grayscaled.len() as u32;
        let width = grayscaled[0].len() as u32;

        let mut diff_pixels = vec![0u8; (height * width) as usize];
        diff_pixels
            .par_chunks_mut(width as usize)
            .zip(grayscaled.par_iter().zip(edited_image.par_iter()))
            .for_each(|(chunk, (gray_row, edited_row))| {
                for (out, (&g, &e)) in chunk.iter_mut().zip(gray_row.iter().zip(edited_row.iter())) {
                    *out = g.abs_diff(e);
                }
            });
        let diff_image = GrayImage::from_raw(width, height, diff_pixels)
            .expect("buffer size mismatch");

        let output_path = Path::new(output_dir).join(&*filename_str);
        diff_image
            .save(&output_path)
            .unwrap_or_else(|e| panic!("failed to save {}: {e}", output_path.display()));

        println!("Processed {filename_str}");
    }

    println!("Done. Difference images written to {output_dir}");
}
