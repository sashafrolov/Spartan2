# Neutron Nova video editing

All in one command: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_video_editing --release`

## Zaratan flow for non-streaming: 
Build: `RUSTFLAGS="-C target-cpu=native" cargo build --example neutron_nova_video_editing --release -j 96`
Reserve machine: `srun --partition=standard --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=2:00:00 --pty bash`
Run: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_video_editing --release`
To get RAM usage: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" /usr/bin/time -v cargo run --example neutron_nova_video_editing --release`

## Zaratan flow for streaming: 
Build: `RUSTFLAGS="-C target-cpu=native" cargo build --example neutron_nova_streaming_video_editing --release -j 96`
Reserve machine: `srun --partition=standard --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=2:00:00 --pty bash`
Run: `RUST_LOG=neutron_nova_streaming_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_streaming_video_editing --release`
To get RAM usage: `RUST_LOG=neutron_nova_streaming_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" /usr/bin/time -v cargo run --example neutron_nova_streaming_video_editing --release`

## Reserve the debug partition:
`srun --partition=debug --nodes=1 --ntasks=1 --cpus-per-task=64 --mem=256G --time=15:00 --pty bash`

# SHA-256 test

All in one command: `RUST_LOG=neutron_nova_video_editing=info,spartan2::neutronnova_zk=info RUSTFLAGS="-C target-cpu=native" cargo run --example neutron_nova_sha256_example --release`