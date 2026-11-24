// Fuzz PDQ photo hashing on decoded images. pdqHash256FromFile/
// pdqDihedralHash256esFromFile decode through CImg's load(), which falls back
// to spawning ImageMagick/GraphicsMagick for anything it cannot decode
// natively; so this harness does what those functions do (pdq/cpp/io/pdqio.cpp)
// but dispatches to CImg's in-process decoders itself, the way CImg's own
// cimg::ftype() sniffs the header: BMP ("BM") and PNM ("P1".."P8"). PFM and float PNM (P9) are
// left out: CImg loads their floats straight into the uint8_t image pdqio uses,
// an out-of-range float->uchar conversion by design that UBSan would report
// on nearly every input.
// The decoded image then goes through the same steps as pdqHash256FromFile:
// resize to <=512, loadFloatLumaFromCImg, pdqHash256FromFloatLuma and the
// eight dihedral hashes.
#include <pdq/cpp/hashing/pdqhashing.h>
#include <pdq/cpp/io/pdqio.h>

#include <cstdint>
#include <cstdio>

using namespace facebook::pdq::hashing;

static const int DOWNSAMPLE_DIMS = 512; // as in pdqio.cpp

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  cimg_library::cimg::exception_mode(0); // quiet: no stderr dump per throw
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) {
    return -1;
  }
  FILE* fp = fmemopen((void*)data, size, "rb");
  if (fp == nullptr) {
    return 0;
  }
  cimg_library::CImg<uint8_t> img;
  try {
    if (data[0] == 'B' && data[1] == 'M') {
      img.load_bmp(fp);
    } else if (data[0] == 'P' && data[1] >= '1' && data[1] <= '8') {
      img.load_pnm(fp);
    } else {
      fclose(fp);
      return 0;
    }
  } catch (const cimg_library::CImgException&) {
    fclose(fp);
    return 0;
  }
  fclose(fp);
  if (img.is_empty()) {
    return 0;
  }
  try {
    if (img.height() > DOWNSAMPLE_DIMS || img.width() > DOWNSAMPLE_DIMS) {
      img = img.resize(DOWNSAMPLE_DIMS, DOWNSAMPLE_DIMS);
    }
  } catch (const cimg_library::CImgException&) {
    return 0;
  }

  int numRows, numCols;
  float* full1 = loadFloatLumaFromCImg(img, numRows, numCols);
  float* full2 = new float[numRows * numCols];
  float* full3 = new float[numRows * numCols];
  for (int i = 0; i < numRows * numCols; i++) {
    full3[i] = full1[i];
  }
  static float b64x64[64][64], b16x64[16][64], b16x16[16][16], aux[16][16];
  Hash256 h, d[8];
  int quality = 0;
  pdqHash256FromFloatLuma(
      full1, full2, numRows, numCols, b64x64, b16x64, b16x16, h, quality);
  pdqDihedralHash256esFromFloatLuma(
      full3, full2, numRows, numCols, b64x64, b16x64, b16x16, aux,
      &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7], quality);
  delete[] full1;
  delete[] full2;
  delete[] full3;
  return 0;
}
