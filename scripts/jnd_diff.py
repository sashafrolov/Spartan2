#!/usr/bin/env python3
"""
Compare two grayscale images using a Just Noticeable Difference (JND) map.

Returns exit code 0 + prints "false" if all pixel differences are within JND
(images are perceptually identical), or exit code 1 + prints "true" if any
pixel exceeds its JND threshold (images are perceptually different).

Usage:
    python3 jnd_diff.py <image1> <image2>

Arguments:
    image1  Reference image (used to compute JND map). Can be grayscale or RGB.
    image2  Image to compare against image1.
"""

import sys
import cv2
import numpy as np
import skimage
from skimage import feature
from scipy.ndimage import correlate

_eps = 1e-6

def _conv(input, filter):
    return correlate(input, filter, mode="constant", cval=0.0)

def _gkern(kernlen=5, nsig=0.8):
    import scipy.stats as st
    x = np.linspace(-nsig, nsig, kernlen)
    kern1d = st.norm.pdf(x)
    kernel_raw = np.outer(kern1d, kern1d)
    return kernel_raw / kernel_raw.sum()

T0, gamma = 17, 3 / 128
_lum_jnd_lut = np.array([
    T0 * (1 - np.sqrt(k / 127)) + 3 if k < 127 else gamma * (k - 127) + 3
    for k in range(256)
])

def _bg_lum_jnd(img):
    alpha = 0.7
    min_lum = 32
    B = np.array([[1, 1, 1, 1, 1],
                  [1, 2, 2, 2, 1],
                  [1, 2, 0, 2, 1],
                  [1, 2, 2, 2, 1],
                  [1, 1, 1, 1, 1]])
    bg_lum = np.floor(_conv(img, B) / 32)
    adapt_bg = np.round(min_lum + bg_lum * (127 - min_lum) / 127 + _eps)
    bg_lum = np.where(bg_lum <= 127, adapt_bg, bg_lum)
    jnd_lum = _lum_jnd_lut[bg_lum.astype(int).clip(0, 255)]
    return alpha * jnd_lum

def _luminance_contrast(img):
    R = 2
    ker = np.ones((2 * R + 1, 2 * R + 1)) / (2 * R + 1) ** 2
    mean_mask = _conv(img, ker)
    var_mask = _conv(img ** 2, ker) - mean_mask ** 2
    var_mask[var_mask < 0] = 0
    valid_mask = np.zeros_like(img)
    valid_mask[R:-R, R:-R] = 1
    return np.sqrt(var_mask * valid_mask)

def _ori_complexity(img):
    r = 1
    nb = r * 8
    otr = 6
    kx = np.array([[-1, 0, 1], [-1, 0, 1], [-1, 0, 1]]) / 3
    ky = kx.T
    sps = np.zeros((nb, 2))
    at = 2 * np.pi / nb
    idx = np.arange(nb)
    sps[:, 0] = -r * np.sin(idx * at)
    sps[:, 1] = r * np.cos(idx * at)
    imgd = np.pad(img, ((r, r), (r, r)), 'symmetric')
    h, w = imgd.shape
    Gx = _conv(imgd, kx)
    Gy = _conv(imgd, ky)
    C = np.sqrt(Gx ** 2 + Gy ** 2)
    Cv = (C >= 5).astype(float)
    O = np.round(np.arctan2(Gy, Gx) / np.pi * 180 + _eps)
    O[O > 90] -= 180
    O[O < -90] += 180
    O += 90
    O[Cv == 0] = 180 + 2 * otr
    Oc = O[r:-r, r:-r]
    Cvc = Cv[r:-r, r:-r]
    onum = int(np.round(180 / 2 / otr) + 1 + _eps)
    O_norm = np.round(O / 2 / otr + _eps)
    Oc_norm = np.round(Oc / 2 / otr + _eps)
    bins = np.arange(onum + 1)
    ssr_val = (Oc_norm[:, :, None] == bins).astype(float)
    for i in range(nb):
        dx = int(np.round(r + sps[i, 0]) + _eps)
        dy = int(np.round(r + sps[i, 1]) + _eps)
        On = O_norm[dx:h - 2 * r + dx, dy:w - 2 * r + dy]
        ssr_val += (On[:, :, None] == bins)
    cmlx = np.sum(ssr_val != 0, axis=2).astype(float)
    cmlx[Cvc == 0] = 1
    cmlx[:r, :] = cmlx[-r:, :] = cmlx[:, :r] = cmlx[:, -r:] = 1
    return _conv(cmlx, _gkern(3, 1))

def _edge_protect(img):
    G1 = np.array([[0,0,0,0,0],[1,3,8,3,1],[0,0,0,0,0],[-1,-3,-8,-3,-1],[0,0,0,0,0]])
    G2 = np.array([[0,0,1,0,0],[0,8,3,0,0],[1,3,0,-3,-1],[0,0,-3,-8,0],[0,0,-1,0,0]])
    G3 = np.array([[0,0,1,0,0],[0,0,3,8,0],[-1,-3,0,3,1],[0,-8,-3,0,0],[0,0,-1,0,0]])
    G4 = np.array([[0,1,0,-1,0],[0,3,0,-3,0],[0,8,0,-8,0],[0,3,0,-3,0],[0,1,0,-1,0]])
    grad = np.stack([_conv(img, G) / 16 for G in [G1, G2, G3, G4]], axis=2)
    max_grad = np.max(np.abs(grad), axis=2)
    max_grad = np.pad(max_grad[2:-2, 2:-2], ((2, 2), (2, 2)), 'symmetric')
    edge_h = 60
    edge_threshold = min(edge_h / (np.max(max_grad) + _eps), 0.8)
    edge_region = feature.canny(
        img, sigma=np.sqrt(2),
        low_threshold=0.4 * edge_threshold * 255,
        high_threshold=edge_threshold * 255
    ).astype(np.float32)
    kernel = skimage.morphology.disk(3)
    img_edge = skimage.morphology.dilation(edge_region, kernel)
    return _conv(1.0 - img_edge, _gkern(5, 0.8))

def compute_jnd_map(img_gray):
    """Compute per-pixel JND threshold from a grayscale float32 image."""
    jnd_la = _bg_lum_jnd(img_gray)
    L_c = _luminance_contrast(img_gray)
    alpha, beta = 0.115 * 16, 26
    jnd_lc = (alpha * np.power(L_c, 2.4)) / (np.power(L_c, 2) + beta ** 2)
    P_c = _ori_complexity(img_gray)
    a1, a2, a3 = 0.3, 2.7, 1
    C_t = (a1 * np.power(P_c, a2)) / (np.power(P_c, 2) + a3 ** 2)
    jnd_pm = L_c * C_t * _edge_protect(img_gray)
    jnd_vm = np.maximum(jnd_lc, jnd_pm)
    return (jnd_la + jnd_vm - 0.3 * np.minimum(jnd_la, jnd_vm)).astype(np.float32)

def load_gray(path):
    img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise FileNotFoundError(f"Could not read image: {path}")
    if img.ndim == 3:
        img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return img.astype(np.float32)

def images_are_different(path1, path2):
    """
    Returns True if any pixel in image2 differs from image1 by more than
    its per-pixel JND threshold (computed from image1).
    """
    img1 = load_gray(path1)
    img2 = load_gray(path2)

    if img1.shape != img2.shape:
        raise ValueError(f"Shape mismatch: {img1.shape} vs {img2.shape}")

    jnd_map = compute_jnd_map(img1)
    diff = np.abs(img1 - img2)
    return bool(np.any(diff > jnd_map))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <image1> <image2>", file=sys.stderr)
        sys.exit(2)

    result = images_are_different(sys.argv[1], sys.argv[2])
    print("true" if result else "false")
    sys.exit(1 if result else 0)
