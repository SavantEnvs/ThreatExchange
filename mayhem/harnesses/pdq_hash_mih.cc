// Fuzz PDQ hash parsing and the mutually-indexed-hashing (MIH) index. Each
// input line is a hash in the "hash=<hex>,<metadata>" form of
// pdq/cpp/io/hashio.cpp; the hex is parsed by the throwing Hash256(const char*)
// constructor (hashio's own readers call fromStringOrDie, which exit(1)s on
// any malformed line). Parsed hashes go into MIH256 and are queried back, and
// the parse/format round trip is checked.
#include <pdq/cpp/common/pdqhamming.h>
#include <pdq/cpp/common/pdqhashtypes.h>
#include <pdq/cpp/index/mih.h>

#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using facebook::pdq::hashing::Hash256;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string in(reinterpret_cast<const char*>(data), size);
  std::vector<std::pair<Hash256, std::string>> pairs;
  size_t pos = 0;
  while (pos <= in.size() && pairs.size() < 256) {
    size_t nl = in.find('\n', pos);
    if (nl == std::string::npos) {
      nl = in.size();
    }
    std::string line = in.substr(pos, nl - pos);
    pos = nl + 1;
    std::string meta = "idx=" + std::to_string(pairs.size() + 1);
    size_t cut = line.find(',');
    if (cut != std::string::npos) {
      meta = line.substr(cut + 1);
      line = line.substr(0, cut);
    }
    if (line.compare(0, 5, "hash=") == 0) {
      line = line.substr(5);
    }
    try {
      Hash256 h(line.c_str());
      pairs.emplace_back(h, meta);
    } catch (const std::runtime_error&) {
    }
  }
  if (pairs.empty()) {
    return 0;
  }
  facebook::pdq::index::MIH256<std::string> mih;
  mih.insertAll(pairs);
  for (const auto& p : pairs) {
    // format() must invert the parser.
    Hash256 again(p.first.format().c_str());
    if (!(again == p.first)) {
      abort();
    }
    std::vector<std::pair<Hash256, std::string>> matches;
    mih.queryAll(p.first, 31, matches);
    if (matches.empty()) {
      abort(); // the hash itself is in the index at distance 0
    }
    (void)facebook::pdq::hashing::hammingDistance(p.first, pairs[0].first);
    Hash256 c = p.first;
    (void)c.hammingNorm();
  }
  return 0;
}
