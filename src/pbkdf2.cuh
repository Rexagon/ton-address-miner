#pragma once

#include <cstdint>

#include "sha512.cuh"

__device__ void pbkdf2_sha512(const uint8_t password[], size_t password_len, const uint8_t salt[], uint8_t salt_len,
                              int rounds, uint8_t *output);

struct HmacSha512Context {
  Sha512Context ctx_inside;
  Sha512Context ctx_outside;
};

__device__ void hmac_sha512_init(HmacSha512Context *ctx, const uint8_t password[], size_t password_len);
__device__ void hmac_sha512_update(HmacSha512Context *ctx, const uint8_t message[], size_t message_len);
__device__ void hmac_sha512_final(HmacSha512Context *ctx);
__device__ void hmac_sha512_write_output(HmacSha512Context *ctx, uint8_t hash[]);
