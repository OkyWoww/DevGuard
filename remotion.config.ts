import { Config } from '@remotion/cli/config';

// 1. Extend timeout from default 30,000ms (30s) to 180,000ms (3 minutes)
// This resolves the "Timeout (30000ms) exceeded" error when seeking/buffering heavy video files
Config.setDelayRenderTimeoutInMilliseconds(180000);
Config.setTimeoutInMilliseconds(180000);

// 2. High-performance frame buffering: JPEG format is 3-5x faster than PNG
Config.setVideoImageFormat('jpeg');
Config.setJpegQuality(92);

// 3. Concurrency settings optimized for multi-core CPU rendering
Config.setConcurrency(4);

// 4. Color space & pixel format
Config.setPixelFormat('yuv420p');
Config.setCodec('h264');

