use image::ImageReader;
use image::GrayImage;
use image::RgbImage;

pub fn read_color_png(path: &str) -> Vec<Vec<(u8, u8, u8)>> {
  let img: RgbImage = ImageReader::open(path)
    .unwrap_or_else(|e| panic!("failed to open {path}: {e}"))
    .decode()
    .unwrap_or_else(|e| panic!("failed to decode {path}: {e}"))
    .into_rgb8();

  let (width, height) = img.dimensions();
  (0..height)
    .map(|y| (0..width).map(|x| { let p = img.get_pixel(x, y); (p[0], p[1], p[2]) }).collect())
    .collect()
}

pub fn read_mono_png(path: &str) -> Vec<Vec<u8>> {
  let img: GrayImage = ImageReader::open(path)
    .unwrap_or_else(|e| panic!("failed to open {path}: {e}"))
    .decode()
    .unwrap_or_else(|e| panic!("failed to decode {path}: {e}"))
    .into_luma8();

  let (width, height) = img.dimensions();
  (0..height)
    .map(|y| (0..width).map(|x| img.get_pixel(x, y)[0]).collect())
    .collect()
}
