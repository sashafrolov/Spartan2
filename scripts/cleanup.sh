#!/usr/bin/env bash
set -euo pipefail

VIDEO_DATA="$(dirname "$0")/../video_data"

for dir in \
    decomposed_frames \
    decomposed_frame_channels \
    edited_videos \
    edited_video_frames \
    edited_video_frame_channels \
    jnd_maps
do
    target="$VIDEO_DATA/$dir"
    find "$target" -mindepth 1 -not -name '.gitkeep' -delete
    echo "Cleaned $dir"
done
