import cv2
import numpy as np
import os
from pathlib import Path
import json

class VideoFrameDecomposer:
    """
    Decomposes a video into key frames and delta frames with RGB channel separation.
    
    Key frames: Frames where significant changes occur (detected using frame differencing)
    Delta frames: Difference between consecutive frames
    """
    
    def __init__(self, video_path, output_dir, threshold=30.0):
        """
        Initialize the decomposer.
        
        Args:
            video_path: Path to input video file
            output_dir: Directory to save output frames
            threshold: Threshold for detecting key frames (mean pixel difference)
        """
        self.video_path = video_path
        self.output_dir = Path(output_dir)
        self.threshold = threshold
        
        # Create output directories
        self.keyframes_dir = self.output_dir / 'keyframes'
        self.delta_dir = self.output_dir / 'delta_frames'
        self.rgb_dir = self.output_dir / 'rgb_channels'
        
        for dir_path in [self.keyframes_dir, self.delta_dir, self.rgb_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
            
        # Create subdirectories for RGB channels
        for channel in ['R', 'G', 'B']:
            (self.rgb_dir / f'channel_{channel}').mkdir(exist_ok=True)
    
    def compute_frame_difference(self, frame1, frame2):
        """Compute the mean absolute difference between two frames."""
        diff = cv2.absdiff(frame1, frame2)
        return np.mean(diff)
    
    def save_rgb_channels(self, frame, frame_idx, is_keyframe=False):
        """
        Save individual RGB channels of a frame.
        
        Args:
            frame: BGR image (OpenCV format)
            frame_idx: Frame index number
            is_keyframe: Whether this is a key frame
        """
        # Convert BGR to RGB
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        # Split into channels
        r_channel = rgb_frame[:, :, 0] # Red channel
        g_channel = rgb_frame[:, :, 1] # Green channel
        b_channel = rgb_frame[:, :, 2] # Blue channel
        
        prefix = 'output' #'key' if is_keyframe else 'frame'
        
        # Save each channel as grayscale image
        cv2.imwrite(str(self.rgb_dir / f'channel_R/{prefix}_{frame_idx:04d}_R.png'), r_channel)
        cv2.imwrite(str(self.rgb_dir / f'channel_G/{prefix}_{frame_idx:04d}_G.png'), g_channel)
        cv2.imwrite(str(self.rgb_dir / f'channel_B/{prefix}_{frame_idx:04d}_B.png'), b_channel)
        
        # # Also save a visualization with all channels side by side
        # combined = np.hstack([
        #     cv2.cvtColor(r_channel, cv2.COLOR_GRAY2BGR),
        #     cv2.cvtColor(g_channel, cv2.COLOR_GRAY2BGR),
        #     cv2.cvtColor(b_channel, cv2.COLOR_GRAY2BGR)
        # ])
        # cv2.imwrite(str(self.rgb_dir / f'{prefix}_{frame_idx:04d}_RGB_split.png'), combined)
    
    def decompose(self, max_frames=None, keyframe_interval=None, sample_rate=1):
        """
        Decompose video into key frames and delta frames.
        
        Args:
            max_frames: Maximum number of frames to process (None for all)
            keyframe_interval: Force keyframe every N frames (None for automatic)
            sample_rate: Process every Nth frame (1 = all frames, 5 = every 5th frame)
        
        Returns:
            Dictionary with statistics about the decomposition
        """
        cap = cv2.VideoCapture(self.video_path)
        
        if not cap.isOpened():
            raise ValueError(f"Could not open video file: {self.video_path}")
        
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        print(f"Video info:")
        print(f"  Total frames: {total_frames}")
        print(f"  FPS: {fps}")
        print(f"  Resolution: {width}x{height}")
        print(f"  Sample rate: every {sample_rate} frame(s)")
        print()
        
        prev_frame = None
        frame_idx = 0
        processed_count = 0
        keyframe_count = 0
        delta_count = 0
        
        stats = {
            'video_info': {
                'total_frames': total_frames,
                'fps': fps,
                'width': width,
                'height': height,
                'sample_rate': sample_rate
            },
            'total_frames_processed': 0,
            'keyframes': [],
            'delta_frames': [],
            'frame_differences': []
        }
        
        while True:
            ret, frame = cap.read()
            
            if not ret:
                break
            
            # Skip frames according to sample_rate
            if frame_idx % sample_rate != 0:
                frame_idx += 1
                continue
            
            if max_frames and processed_count >= max_frames:
                break
            
            is_keyframe = False
            
            # First frame is always a keyframe
            if prev_frame is None:
                is_keyframe = True
            else:
                # Compute difference with previous frame
                diff = self.compute_frame_difference(prev_frame, frame)
                stats['frame_differences'].append(diff)
                
                # Determine if this is a keyframe
                if keyframe_interval and processed_count % keyframe_interval == 0:
                    is_keyframe = True
                elif diff > self.threshold:
                    is_keyframe = True
                
                # Compute and save delta frame
                delta_frame = cv2.absdiff(prev_frame, frame)
                delta_filename = self.delta_dir / f'delta_{frame_idx:04d}.png'
                cv2.imwrite(str(delta_filename), delta_frame)
                delta_count += 1
                stats['delta_frames'].append({
                    'index': frame_idx,
                    'difference': float(diff),
                    'is_keyframe': is_keyframe
                })
            
            # Save keyframe if detected
            if is_keyframe:
                keyframe_filename = self.keyframes_dir / f'keyframe_{frame_idx:04d}.png'
                cv2.imwrite(str(keyframe_filename), frame)
                keyframe_count += 1
                stats['keyframes'].append({
                    'index': frame_idx,
                    'timestamp': frame_idx / fps
                })
                print(f"Keyframe detected at frame {frame_idx} ({frame_idx/fps:.2f}s)")
            
            
            self.save_rgb_channels(frame, frame_idx, is_keyframe)
            
            prev_frame = frame.copy()
            frame_idx += 1
            processed_count += 1
            
            if processed_count % 50 == 0:
                print(f"Processed {processed_count} frames (video frame {frame_idx})...")
        
        cap.release()
        
        stats['total_frames_processed'] = processed_count
        stats['total_keyframes'] = keyframe_count
        stats['total_delta_frames'] = delta_count
        
        print(f"\n{'='*60}")
        print(f"Decomposition complete!")
        print(f"{'='*60}")
        print(f"  Processed: {processed_count} frames")
        print(f"  Keyframes: {keyframe_count}")
        print(f"  Delta frames: {delta_count}")
        print(f"  Output directory: {self.output_dir}")
        
        # Save statistics
        stats_file = self.output_dir / 'decomposition_stats.json'
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"  Statistics saved to: {stats_file}")
        
        return stats


def main():
    # Configuration
    video_path = 'short_video.mp4'
    output_dir = './outputs/video_decomposition'
    
    print("="*60)
    print("VIDEO FRAME DECOMPOSITION")
    print("="*60)
    print()
    
    # Create decomposer
    decomposer = VideoFrameDecomposer(
        video_path=video_path,
        output_dir=output_dir,
        threshold=30.0  # Adjust this to control keyframe sensitivity
    )
    
    stats = decomposer.decompose(
        max_frames=20000, 
        keyframe_interval=None, 
        sample_rate=1  
    )
    
    print("\n" + "="*60)
    print("OUTPUT STRUCTURE")
    print("="*60)
    print(f"\n📁 {output_dir}/")
    print(f"  📁 keyframes/")
    print(f"     - Key frames where significant changes occur")
    print(f"     - Named: keyframe_XXXXXX.png")
    print(f"  📁 delta_frames/")
    print(f"     - Absolute difference between consecutive frames")
    print(f"     - Shows what changed between frames")
    print(f"     - Named: delta_XXXXXX.png")
    print(f"  📁 rgb_channels/")
    print(f"    📁 channel_R/        - Red channel only (grayscale)")
    print(f"    📁 channel_G/        - Green channel only (grayscale)")
    print(f"    📁 channel_B/        - Blue channel only (grayscale)")
    print(f"    📄 *_RGB_split.png   - R|G|B side-by-side visualization")
    print(f"  📄 decomposition_stats.json - Complete statistics")
    
    print(f"\n" + "="*60)
    print("USAGE NOTES")
    print("="*60)
    print("• Keyframes: Frames with significant visual changes")
    print("• Delta frames: Highlight motion/changes between frames")
    print("• RGB channels: Separate color information for analysis")
    print("• To process ALL frames: set sample_rate=1, max_frames=None")
    print("• To adjust sensitivity: modify threshold (lower = more keyframes)")
    

if __name__ == '__main__':
    main()
