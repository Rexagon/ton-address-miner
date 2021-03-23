#pragma once

#include <cstdint>

struct Sha256Context {
  uint8_t data[64];
  uint32_t dataLen;
  unsigned long long bitLen;
  uint32_t state[8];
};

__device__ void sha256_init(Sha256Context *ctx);
__device__ void sha256_update(Sha256Context *ctx, const uint8_t data[], size_t len);
__device__ void sha256_final(Sha256Context *ctx);
__device__ void sha256_write_output(Sha256Context *ctx, uint8_t hash[]);
