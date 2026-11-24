// Fuzz the TMK feature-vector (.tmk) reader: TMKFeatureVectors::readFromInputStream
// parses the header (magics, algorithm, header-driven vector sizes) and the
// int/float vectors. A successfully parsed file is then scored against itself
// and written back out, as tmk-query / tmk-compare-two-tmks do.
#include <tmk/cpp/algo/tmkfv.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>

using facebook::tmk::algo::TMKFeatureVectors;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return -1; // fmemopen rejects a zero-length buffer
  }
  FILE* fp = fmemopen((void*)data, size, "rb");
  if (fp == nullptr) {
    return 0;
  }
  std::shared_ptr<TMKFeatureVectors> fv =
      TMKFeatureVectors::readFromInputStream(fp, "fuzz");
  fclose(fp);
  if (!fv) {
    return 0;
  }
  if (TMKFeatureVectors::areCompatible(*fv, *fv)) {
    volatile float s1 = TMKFeatureVectors::computeLevel1Score(*fv, *fv);
    volatile float s2 = TMKFeatureVectors::computeLevel2Score(*fv, *fv);
    (void)s1;
    (void)s2;
    (void)TMKFeatureVectors::compare(*fv, *fv, 0.01f);
  }
  fv->L2NormalizePureAverageFeature();

  char* buf = nullptr;
  size_t len = 0;
  FILE* out = open_memstream(&buf, &len);
  if (out != nullptr) {
    fv->writeToOutputStream(out, "fuzz");
    fclose(out);
  }
  free(buf);
  return 0;
}
