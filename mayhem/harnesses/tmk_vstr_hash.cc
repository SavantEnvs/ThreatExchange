// Fuzz the TMK decoded-video-stream (.vstr) pipeline, mirroring
// tmk/cpp/bin/vstr2tmk.cpp: readDecodedVideoStreamFileHeader parses the header
// (dims/fps come from the file), readRGBTriples reads frames, the PDQF frame
// hasher computes per-frame features and TMKFeatureVectors ingests them.
#include <tmk/cpp/algo/tmkfv.h>
#include <tmk/cpp/hashing/bufferhashers.h>
#include <tmk/cpp/io/tmkio.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>

using namespace facebook::tmk;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return -1; // fmemopen rejects a zero-length buffer
  }
  FILE* fp = fmemopen((void*)data, size, "rb");
  if (fp == nullptr) {
    return 0;
  }
  io::DecodedVideoStreamFileHeader hdr;
  if (!io::readDecodedVideoStreamFileHeader(fp, &hdr, "fuzz")) {
    fclose(fp);
    return 0;
  }
  int h = hdr.frameHeight, w = hdr.frameWidth;
  // vstr2tmk itself allocates a frameHeight*frameWidth*3 buffer from these
  // header fields; this harness plays that caller and only accepts frame sizes
  // a real decoded stream could have here (positive, at most 1024x1024), so the
  // fuzzer explores the hashing code instead of the allocator.
  if (h <= 0 || w <= 0 || (long)h * (long)w > 1024L * 1024L) {
    fclose(fp);
    return -1;
  }
  std::unique_ptr<hashing::AbstractFrameBufferHasher> hasher =
      hashing::FrameBufferHasherFactory::createFrameHasher(
          io::TMKFramewiseAlgorithm::PDQ_FLOAT, h, w);
  int dim = hasher->getFeatureDimension();
  std::unique_ptr<uint8_t[]> frame(new uint8_t[(size_t)h * w * 3]);
  std::vector<float> feature(dim);
  algo::TMKFeatureVectors fv(
      io::TMKFramewiseAlgorithm::PDQ_FLOAT,
      hdr.framesPerSecond,
      algo::TMKFeatureVectors::makePoullotPeriods(),
      algo::TMKFeatureVectors::makePoullotFourierCoefficients(),
      dim);
  bool eof = false;
  while (!feof(fp)) {
    bool rc = io::readRGBTriples(frame.get(), h, w, fp, eof);
    if (eof || !rc) {
      break;
    }
    if (!hasher->hashFrame(frame.get(), feature)) {
      break;
    }
    fv.ingestFrameFeature(feature, fv.getFrameFeatureCount());
  }
  fclose(fp);
  fv.finishFrameFeatureIngest();
  (void)algo::TMKFeatureVectors::computeLevel2Score(fv, fv);
  return 0;
}
