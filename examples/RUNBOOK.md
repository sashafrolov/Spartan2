# Set up the decomposed video directory structure:
I have a "long" and "short" version of each command.
1a. Download the video (10 second is the easiest): 
`curl -o video_data/videos/10stestvideo.mp4 https://test-videos.co.uk/vids/bigbuckbunny/mp4/h264/720/Big_Buck_Bunny_720_10s_10MB.mp4`
1b. Download a ~10 minute test video: `curl -o video_data/videos/10mintestvideo.mp4 https://download.blender.org/peach/bigbuckbunny_movies/big_buck_bunny_720p_h264.mov`
1c. Reencode the test video to be 3600 frames long: `ffmpeg -i video_data/videos/10mintestvideo.mp4 -frames:v 3600 -c:v libx264 video_data/videos/longtestvideo.mp4`. 
2a. Decompose the input video in various ways. `python3 scripts/setup_videos.py video_data/videos/10stestvideo.mp4 grayscale` (when the edit is `grayscale`).
2b. `python3 scripts/setup_videos.py video_data/videos/longtestvideo.mp4 grayscale`            

# Neutron Nova video editing, example circuit

Note: the example circuit is a circuit with similar constraints to a Freivald's convolution based editing circuit, but it doesn't do anything and the circuits are kind of simulated.

All in one command: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_video_editing --release`

## Zaratan flow for non-streaming: 
Build: `RUSTFLAGS="-C target-cpu=native" cargo build --example neutron_nova_video_editing --release -j 96`
Reserve machine: `srun --partition=standard --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=2:00:00 --pty bash`
Run: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk_ram_optimized=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_video_editing --release`
To get RAM usage: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk_ram_optimized=info RUSTFLAGS="-C target-cpu=native" /usr/bin/time -v cargo run --example neutron_nova_video_editing --release`

## Zaratan flow for streaming: 
Build: `RUSTFLAGS="-C target-cpu=native" cargo build --example neutron_nova_streaming_video_editing --release -j 96`
Reserve machine: `srun --partition=standard --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=2:00:00 --pty bash`
Run: `RUST_LOG=neutron_nova_streaming_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_video_editing --release`
To get RAM usage: `RUST_LOG=neutron_nova_streaming_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" SCRIBE_TEMP_DIR=/tmp/ /usr/bin/time -v cargo run --example neutron_nova_streaming_video_editing --release`

## Reserve the debug partition:
`srun --partition=debug --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=15:00 --pty bash`

# SHA-256 test

All in one command: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_sha256_example --release`


# Grayscaling

Grayscaling is a particularly simple/cheap edit. 

## Zaratan flow for non-streaming: 
Build: `RUSTFLAGS="-C target-cpu=native" cargo build --example neutron_nova_grayscaling --release -j 96`
Reserve machine: `srun --partition=standard --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=2:00:00 --pty bash`
Run: `RUST_LOG=neutron_nova_grayscaling=info,spartan2::neutronnova_zk_ram_optimized=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_grayscaling --release`
To get RAM usage: `RUST_LOG=neutron_nova_grayscaling=info,spartan2::neutronnova_zk_ram_optimized=info RUSTFLAGS="-C target-cpu=native" /usr/bin/time -v cargo run --example neutron_nova_grayscaling --release`

## Zaratan flow for streaming: 
Build: `RUSTFLAGS="-C target-cpu=native" cargo build --example neutron_nova_streaming_grayscaling --release -j 96`
Reserve machine: `srun --partition=standard --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=2:00:00 --pty bash`
Run: `RUST_LOG=neutron_nova_streaming_grayscaling=info,spartan2::neutronnova_zk_streaming=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_grayscaling --release`
To get RAM usage: `RUST_LOG=neutron_nova_streaming_grayscaling=info,spartan2::neutronnova_zk_streaming=info RUSTFLAGS="-C target-cpu=native" /usr/bin/time -v cargo run --example neutron_nova_streaming_grayscaling --release`