#[path = "circuits/utils.rs"]
mod utils;
use utils::{
    read_color_png,
    create_resizing_sparse, sparse_dense_matmul_u64, dense_sparse_matmul_u64,
    create_gblur_matrix_u64, matrix_matrix_product_band_left_u64, matrix_matrix_product_band_right_u64,
    SIGMA, GBLUR_RADIUS,
};

use image::{GrayImage, RgbImage};
use rayon::prelude::*;
use std::env;
use std::fs;
use std::path::Path;

enum Operation {
    Grayscale,
    Resize,
    Blur,
}

fn apply_grayscale(image: &[Vec<(u8, u8, u8)>]) -> Vec<Vec<u8>> {
    image
        .par_iter()
        .map(|row| {
            row.iter()
                .map(|&(r, g, b)| {
                    ((r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000) as u8
                })
                .collect()
        })
        .collect()
}

fn split_channels(image: &[Vec<(u8, u8, u8)>]) -> (Vec<Vec<u64>>, Vec<Vec<u64>>, Vec<Vec<u64>>) {
    let r = image.iter().map(|row| row.iter().map(|&(r, _, _)| r as u64).collect()).collect();
    let g = image.iter().map(|row| row.iter().map(|&(_, g, _)| g as u64).collect()).collect();
    let b = image.iter().map(|row| row.iter().map(|&(_, _, b)| b as u64).collect()).collect();
    (r, g, b)
}

fn apply_resize_channel(channel: &[Vec<u64>]) -> Vec<Vec<u8>> {
    let height = channel.len();
    let width = channel[0].len();
    assert!(height % 2 == 0 && width % 2 == 0, "image dimensions must be even for 2x downscaling");
    let resize_v = create_resizing_sparse(height, height / 2, false);
    let resize_h = create_resizing_sparse(width, width / 2, true);
    let row_wise = sparse_dense_matmul_u64(&resize_v, channel);
    let result = dense_sparse_matmul_u64(&row_wise, &resize_h, width / 2);
    result.iter().map(|row| row.iter().map(|&v| (v >> 32) as u8).collect()).collect()
}

fn apply_blur_channel(channel: &[Vec<u64>]) -> Vec<Vec<u8>> {
    let height = channel.len();
    let width = channel[0].len();
    let gblur_v = create_gblur_matrix_u64(height, SIGMA, GBLUR_RADIUS);
    let gblur_h = create_gblur_matrix_u64(width, SIGMA, GBLUR_RADIUS);
    let row_wise = matrix_matrix_product_band_left_u64(&gblur_v, channel, GBLUR_RADIUS);
    let result = matrix_matrix_product_band_right_u64(&row_wise, &gblur_h, GBLUR_RADIUS);
    result.iter().map(|row| row.iter().map(|&v| (v >> 32) as u8).collect()).collect()
}

fn merge_channels_to_rgb(r: &[Vec<u8>], g: &[Vec<u8>], b: &[Vec<u8>]) -> Vec<u8> {
    let height = r.len();
    let width = r[0].len();
    let mut pixels = Vec::with_capacity(height * width * 3);
    for i in 0..height {
        for j in 0..width {
            pixels.push(r[i][j]);
            pixels.push(g[i][j]);
            pixels.push(b[i][j]);
        }
    }
    pixels
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <grayscale|resize|blur>", args[0]);
        std::process::exit(1);
    }

    let op = match args[1].as_str() {
        "grayscale" => Operation::Grayscale,
        "resize" => Operation::Resize,
        "blur" => Operation::Blur,
        other => {
            eprintln!("Unknown operation: {other}. Expected grayscale, resize, or blur.");
            std::process::exit(1);
        }
    };

    let decomposed_dir = "video_data/decomposed_frames";
    let output_dir = "video_data/edited_video_frames";

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
        let height = color_image.len() as u32;
        let width = color_image[0].len() as u32;

        let output_path = Path::new(output_dir).join(&*filename_str);

        match op {
            Operation::Grayscale => {
                let gray = apply_grayscale(&color_image);
                let pixels: Vec<u8> = gray.into_iter().flatten().collect();
                GrayImage::from_raw(width, height, pixels)
                    .expect("buffer size mismatch")
                    .save(&output_path)
                    .unwrap_or_else(|e| panic!("failed to save {}: {e}", output_path.display()));
            }
            Operation::Resize => {
                let (r_ch, g_ch, b_ch) = split_channels(&color_image);
                let r_out = apply_resize_channel(&r_ch);
                let g_out = apply_resize_channel(&g_ch);
                let b_out = apply_resize_channel(&b_ch);
                let out_height = r_out.len() as u32;
                let out_width = r_out[0].len() as u32;
                let pixels = merge_channels_to_rgb(&r_out, &g_out, &b_out);
                RgbImage::from_raw(out_width, out_height, pixels)
                    .expect("buffer size mismatch")
                    .save(&output_path)
                    .unwrap_or_else(|e| panic!("failed to save {}: {e}", output_path.display()));
            }
            Operation::Blur => {
                let (r_ch, g_ch, b_ch) = split_channels(&color_image);
                let r_out = apply_blur_channel(&r_ch);
                let g_out = apply_blur_channel(&g_ch);
                let b_out = apply_blur_channel(&b_ch);
                let pixels = merge_channels_to_rgb(&r_out, &g_out, &b_out);
                RgbImage::from_raw(width, height, pixels)
                    .expect("buffer size mismatch")
                    .save(&output_path)
                    .unwrap_or_else(|e| panic!("failed to save {}: {e}", output_path.display()));
            }
        }

        println!("Processed {filename_str}");
    }

    println!("Done. Edited frames written to {output_dir}");
}
