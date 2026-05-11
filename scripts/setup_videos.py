#!/usr/bin/env python3
"""
Prepare video data for ZK proofs.

Usage:
    python3 setup_videos.py <video_path> <edit_type>

Edit types:
    grayscale  - Convert video to grayscale

Outputs (all under video_data/):
    decomposed_frames/           - Original video frames as PNGs
    decomposed_frame_channels/   - R/G/B channel PNGs for each original frame
    edited_videos/               - Edited video file
    edited_video_frames/         - Edited video frames as PNGs
    edited_video_frame_channels/ - Channel PNGs for each edited frame (non-grayscale only)
    jnd_maps/                    - JND map PNGs for each edited frame
"""

import sys
import os
import subprocess
from pathlib import Path
import cv2
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jnd_diff import compute_jnd_map, load_gray

VIDEO_DATA = Path(__file__).parent.parent / "video_data"

DECOMPOSED_FRAMES_DIR   = VIDEO_DATA / "decomposed_frames"
DECOMPOSED_CHANNELS_DIR = VIDEO_DATA / "decomposed_frame_channels"
EDITED_VIDEOS_DIR       = VIDEO_DATA / "edited_videos"
EDITED_FRAMES_DIR       = VIDEO_DATA / "edited_video_frames"
EDITED_CHANNELS_DIR     = VIDEO_DATA / "edited_video_frame_channels"
JND_MAPS_DIR            = VIDEO_DATA / "jnd_maps"

SUPPORTED_EDITS = {"grayscale"}


def decompose_video_to_frames(video_path: Path, output_dir: Path) -> list[Path]:
    """Extract every frame from video_path as a numbered PNG into output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    pattern = str(output_dir / "frame_%04d.png")
    result = subprocess.run(
        ["ffmpeg", "-y", "-i", str(video_path), pattern],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ffmpeg error:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    frames = sorted(output_dir.glob("frame_*.png"))
    print(f"  Extracted {len(frames)} frames to {output_dir}")
    return frames


def decompose_frames_to_channels(frames: list[Path], output_dir: Path) -> None:
    """Save each frame as three grayscale PNGs — one per RGB channel."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for frame_path in frames:
        num = frame_path.stem.split("_", 1)[1]   # "frame_0001" -> "0001"
        img = cv2.imread(str(frame_path))
        if img is None:
            print(f"Warning: could not read {frame_path}", file=sys.stderr)
            continue
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        for i, ch in enumerate(["R", "G", "B"]):
            cv2.imwrite(str(output_dir / f"{ch}_{num}.png"), rgb[:, :, i])
    print(f"  Saved R/G/B channel PNGs to {output_dir}")


def apply_grayscale_edit(video_path: Path, output_dir: Path) -> Path:
    """Convert video to grayscale via ffmpeg, return path to the output file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{video_path.stem}_grayscaled{video_path.suffix}"
    result = subprocess.run(
        ["ffmpeg", "-y", "-i", str(video_path), "-vf", "format=gray", str(output_path)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ffmpeg error:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"  Grayscale video saved to {output_path}")
    return output_path


def compute_and_save_jnd_maps(frames: list[Path], output_dir: Path) -> None:
    """Compute and save a JND map PNG for each frame (treated as grayscale)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for frame_path in frames:
        num = frame_path.stem.split("_", 1)[1]
        img_gray = load_gray(str(frame_path))
        jnd_map = compute_jnd_map(img_gray)
        jnd_u8 = np.clip(np.floor(jnd_map), 0, 255).astype(np.uint8)
        cv2.imwrite(str(output_dir / f"jnd_{num}.png"), jnd_u8)
    print(f"  Saved {len(frames)} JND maps to {output_dir}")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <video_path> <edit_type>", file=sys.stderr)
        print(f"Edit types: {', '.join(sorted(SUPPORTED_EDITS))}", file=sys.stderr)
        sys.exit(2)

    video_path = Path(sys.argv[1])
    edit_type  = sys.argv[2]

    if not video_path.exists():
        print(f"Error: video file not found: {video_path}", file=sys.stderr)
        sys.exit(1)

    if edit_type not in SUPPORTED_EDITS:
        print(f"Error: unsupported edit type '{edit_type}'", file=sys.stderr)
        print(f"Supported: {', '.join(sorted(SUPPORTED_EDITS))}", file=sys.stderr)
        sys.exit(1)

    print(f"Video : {video_path}")
    print(f"Edit  : {edit_type}")

    # Step 1: original video -> frames
    print("\nStep 1: decomposing original video into frames...")
    orig_frames = decompose_video_to_frames(video_path, DECOMPOSED_FRAMES_DIR)

    # Step 2: original frames -> R/G/B channel PNGs
    print("\nStep 2: decomposing original frames into channels...")
    decompose_frames_to_channels(orig_frames, DECOMPOSED_CHANNELS_DIR)

    # Step 3: apply edit
    print(f"\nStep 3: applying '{edit_type}' edit...")
    if edit_type == "grayscale":
        edited_video = apply_grayscale_edit(video_path, EDITED_VIDEOS_DIR)

    # Step 4: edited video -> frames
    print("\nStep 4: decomposing edited video into frames...")
    edited_frames = decompose_video_to_frames(edited_video, EDITED_FRAMES_DIR)

    # Step 5: edited frames -> channels (not needed for grayscale)
    if edit_type == "grayscale":
        print("\nStep 5: skipped (grayscale frames have no color channels to split)")
    else:
        print("\nStep 5: decomposing edited frames into channels...")
        decompose_frames_to_channels(edited_frames, EDITED_CHANNELS_DIR)

    # Step 6: compute JND maps for each edited frame
    print("\nStep 6: computing JND maps for edited frames...")
    compute_and_save_jnd_maps(edited_frames, JND_MAPS_DIR)

    print("\nDone.")


if __name__ == "__main__":
    main()
