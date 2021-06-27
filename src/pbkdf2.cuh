#pragma once

#include <cstdint>

__device__ void pbkdf2_sha512(const uint8_t password[], size_t password_len, const uint8_t salt[], uint8_t salt_len,
                              int rounds, uint8_t *output, size_t output_len);
