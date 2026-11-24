// Fuzz the vPDQ video hasher: the input is a video file (any container/codec
// libavformat/libavcodec can open). It goes through vpdq's public entry point
// facebook::vpdq::hashing::hashVideoFile, which demuxes, decodes, converts to
// RGB24 (sws_scale) and PDQ-hashes frames (FFmpegHasher / VpdqHasher).
// hashVideoFile takes a path, so the input is written to a private temp file.
#include <vpdq/cpp/hashing/filehasher.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <unistd.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* tmpdir = getenv("TMPDIR");
  std::string path = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") +
      "/vpdq_fuzz_XXXXXX";
  int fd = mkstemp(&path[0]);
  if (fd < 0) {
    return 0;
  }
  size_t off = 0;
  while (off < size) {
    ssize_t n = write(fd, data + off, size - off);
    if (n <= 0) {
      break;
    }
    off += (size_t)n;
  }
  close(fd);

  std::vector<facebook::vpdq::hashing::vpdqFeature> hashes;
  try {
    // One hash per second, native resolution, single hashing thread so each
    // run is deterministic and does not depend on the host's core count.
    facebook::vpdq::hashing::hashVideoFile(path, hashes, false, 1.0, 0, 0, 1);
  } catch (const std::exception&) {
    // hashVideoFile reports decoder failures by throwing; not a defect.
  }
  unlink(path.c_str());
  return 0;
}
