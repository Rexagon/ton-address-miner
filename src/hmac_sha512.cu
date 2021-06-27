#include "hmac_sha512.cuh"

__device__ void hmac_sha512_init(HmacSha512Context *ctx, const uint8_t password[], size_t password_len) {
  uint8_t key[128];
  if (password_len <= 128) {
    memcpy(key, password, password_len);
    memset(key + password_len, 0, 128 - password_len);
  } else {
    Sha512Context ctx_key{};
    sha512_init(&ctx_key);
    sha512_update(&ctx_key, key, password_len);
    sha512_final(&ctx_key);
    sha512_write_output(&ctx_key, key);
    memset(key + 64, 0, 64);
  }

#pragma unroll 128
  for (uint8_t &byte : key) {
    byte ^= 0x5c;
  }

  sha512_init(&ctx->ctx_outside);
  sha512_update(&ctx->ctx_outside, key, 128);

#pragma unroll 128
  for (uint8_t &byte : key) {
    byte ^= 0x5c ^ 0x36;
  }

  sha512_init(&ctx->ctx_inside);
  sha512_update(&ctx->ctx_inside, key, 128);
}

__device__ void hmac_sha512_update(HmacSha512Context *ctx, const uint8_t message[], size_t message_len) {
  sha512_update(&ctx->ctx_inside, message, message_len);
}

__device__ void hmac_sha512_final(HmacSha512Context *ctx) {
  uint8_t inner[64];
  sha512_final(&ctx->ctx_inside);
  sha512_write_output(&ctx->ctx_inside, inner);

  sha512_update(&ctx->ctx_outside, inner, 64);
  sha512_final(&ctx->ctx_outside);
}

__device__ void hmac_sha512_write_output(HmacSha512Context *ctx, uint8_t hash[]) {
  sha512_write_output(&ctx->ctx_outside, hash);
}
