#pragma once

#include <cstdint>

struct Sha512Context {
  uint8_t data[128];
  uint32_t dataLen;
  unsigned long long bitLen;
  uint64_t state[8];
};

__device__ void sha512_init(Sha512Context *ctx);
__device__ void sha512_update(Sha512Context *ctx, const uint8_t data[], size_t len);
__device__ void sha512_final(Sha512Context *ctx);
__device__ void sha512_write_output(Sha512Context *ctx, uint8_t hash[]);
