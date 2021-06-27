#include "pbkdf2.cuh"

#include "hmac_sha512.cuh"

__device__ void pbkdf2_sha512(const uint8_t password[], size_t password_len, const uint8_t salt[], uint8_t salt_len,
                              int rounds, uint8_t *output, size_t output_len) {
  HmacSha512Context ctx{};
  uint8_t U[64];
  uint8_t T[64];

  const auto l = output_len / 64;
  auto output_pos = 0;

  for (uint32_t i = 1; i <= l; ++i) {
    uint8_t index_be[4] = {static_cast<uint8_t>(i >> 24), static_cast<uint8_t>(i >> 16), static_cast<uint8_t>(i >> 8),
                           static_cast<uint8_t>(i)};

    hmac_sha512_init(&ctx, password, password_len);
    hmac_sha512_update(&ctx, salt, salt_len);
    hmac_sha512_update(&ctx, index_be, 4);
    hmac_sha512_final(&ctx);
    hmac_sha512_write_output(&ctx, U);

    memcpy(T, U, 64);

    for (int r = 1; r < rounds; ++r) {
      hmac_sha512_init(&ctx, password, password_len);
      hmac_sha512_update(&ctx, U, 64);
      hmac_sha512_final(&ctx);
      hmac_sha512_write_output(&ctx, U);

#pragma unroll 64
      for (int k = 0; k < 64; ++k) {
        T[k] ^= U[k];
      }
    }

    memcpy(output, T + output_pos, 64);
    output_pos += 64;
  }
}
