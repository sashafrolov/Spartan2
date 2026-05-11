#!/usr/bin/env python3
"""
Compute and save the JND (Just Noticeable Difference) map for a video frame.

The JND map is derived solely from the reference (original) image using the
model from Wu et al., "Enhanced Just Noticeable Difference Model for Images
With Pattern Complexity," IEEE TIP 2017. DOI: 10.1109/TIP.2017.2685682

JND is a luminance-based model: the input RGB frame is first converted to
grayscale, then the JND map is computed once and reused as the per-pixel
distortion threshold for all three R, G, B channel proofs. This is both
perceptually justified (luminance structure dominates human distortion
sensitivity) and efficient (1 map per frame instead of 3).

The output map is a public input to the ZK proof. Anyone with the original
frame can independently recompute it to verify the proof.

Usage:
    python3 compute_jnd_map.py <input_image> <output_map.png>

Arguments:
    input_image   Reference (original) RGB or grayscale frame.
    output_map    Output path for the JND map (saved as 8-bit grayscale PNG).
                  Pixel value = floor(jnd_threshold), clamped to [0, 255].
"""

import sys
import cv2
import numpy as np
from jnd_diff import compute_jnd_map, load_gray


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_image> <output_map.png>", file=sys.stderr)
        sys.exit(2)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    img = load_gray(input_path)
    jnd_map = compute_jnd_map(img)

    # Save as 8-bit PNG: floor and clamp to [0, 255]
    jnd_u8 = np.clip(np.floor(jnd_map), 0, 255).astype(np.uint8)
    cv2.imwrite(output_path, jnd_u8)

    print(f"JND map saved to {output_path}")
    print(f"  Input shape : {img.shape[1]}x{img.shape[0]} (WxH)")
    print(f"  JND min     : {jnd_map.min():.2f}")
    print(f"  JND max     : {jnd_map.max():.2f}")
    print(f"  JND mean    : {jnd_map.mean():.2f}")
    print(f"  Applies to  : R, G, B channels (1 map reused for all 3)")


if __name__ == "__main__":
    main()
