# Setup Scripts
The scripts in this directory set up videos ahead of being proven. 

To do this, run `python3 setup_videos.py path_to_video edit_type`. This script does the following:
1. It decomposes `video` into a sequence of PNGs representing the video in `video_data/decomposed_frames`.
2. It decomposes `video` into a sequence of triples of grayscale PNGs representing the video in `video_data/decomposed_frame_channels`.
3. It uses `ffmpeg` (or a custom implementation of an edit, this is TK) to edit the video. This is output in `edited_videos`.
4. It decomposes this edited video into PNG frames in `edited_video_frames`.
5. It decomposes these edited frame channels into monochrome PNGs in `edited_video_frame_channels`.
6. It computes `jnd_maps` for each channel in `edited_video_frame_channels`.

These are then used as prover inputs in various scripts. 
Possible edit types are `blur`, `resize`, `grayscale` and `mask`.
Currently, only `grayscale` is implemented.

# Dependencies:
1. Must have FFmpeg.
2. Set up venv using our `requirements.txt`:
```
python3 -m venv venv
source venv/bin/activate
pip install -r scripts/requirements.txt
```