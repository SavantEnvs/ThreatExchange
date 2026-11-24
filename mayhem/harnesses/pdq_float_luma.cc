// Fuzz the PDQ hashing core on raw RGB frames of arbitrary small/odd sizes and
// strides, without an image decoder in the way: fillFloatLumaFromRGB, then
// pdqHash256FromFloatLuma, pdqFloat256FromFloatLuma and
// pdqDihedralHash256esFromFloatLuma (Jarosz box filters, DCT, Torben median).
// Layout: byte0 = rows-1, byte1 = cols-1 (1..256 each), byte2 low 3 bits =
// extra bytes of row padding; the rest is the interleaved RGB raster.
#include <pdq/cpp/downscaling/downscaling.h>
#include <pdq/cpp/hashing/pdqhashing.h>

#include <cstdint>
#include <vector>

using namespace facebook::pdq::hashing;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 3) {
    return -1;
  }
  int rows = data[0] + 1;
  int cols = data[1] + 1;
  int pad = data[2] & 7;
  int rowStride = cols * 3 + pad;
  size_t need = (size_t)(rows - 1) * rowStride + (size_t)cols * 3;
  const uint8_t* rgb = data + 3;
  if (size - 3 < need) {
    return -1; // fillFloatLumaFromRGB's precondition: the raster is complete
  }
  std::vector<uint8_t> raster(rgb, rgb + need);
  std::vector<float> luma(rows * cols), luma2(rows * cols), tmp(rows * cols);
  facebook::pdq::downscaling::fillFloatLumaFromRGB(
      &raster[0], &raster[1], &raster[2], rows, cols, rowStride, 3, luma.data());
  luma2 = luma;
  std::vector<float> luma3 = luma;

  static float b64x64[64][64], b16x64[16][64], b16x16[16][16], aux[16][16];
  Hash256 h, d[8];
  int quality = 0;
  pdqHash256FromFloatLuma(
      luma.data(), tmp.data(), rows, cols, b64x64, b16x64, b16x16, h, quality);
  pdqFloat256FromFloatLuma(
      luma2.data(), tmp.data(), rows, cols, b64x64, b16x64, b16x16, quality);
  pdqDihedralHash256esFromFloatLuma(
      luma3.data(), tmp.data(), rows, cols, b64x64, b16x64, b16x16, aux,
      &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7], quality);
  return 0;
}
