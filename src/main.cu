#include <iostream>
#include <cmath>

#include <curand.h>
#include <curand_kernel.h>

#include <bip39.cuh>

#include "sha256.cuh"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

constexpr auto ENTROPY_OFFSET = 8u;
constexpr auto MAX_BIP39_WORD_LEN = 8u;

constexpr auto THREAD_COUNT = 8192u;
constexpr auto THREADS_PER_BLOCK = 256u;

enum MnemonicType : uint32_t {
  Words12 = (128u << ENTROPY_OFFSET) | 4u,
  Words24 = (256u << ENTROPY_OFFSET) | 8u,
};

constexpr auto entropy_bits(MnemonicType type) -> size_t {
  return type >> ENTROPY_OFFSET;
}

constexpr auto checksum_bits(MnemonicType type) -> size_t {
  return type & 0xffu;
}

constexpr auto total_bits(MnemonicType type) -> size_t {
  return entropy_bits(type) + checksum_bits(type);
}

constexpr auto word_count(MnemonicType type) -> size_t {
  return total_bits(type) / 11u;
}

constexpr auto DEFAULT_MNEMONIC = MnemonicType::Words12;
constexpr auto MAX_PHRASE_LENGTH = (MAX_BIP39_WORD_LEN + 1) * word_count(DEFAULT_MNEMONIC);
constexpr auto ENTROPY_SIZE = entropy_bits(DEFAULT_MNEMONIC) >> 3u;
constexpr auto WORD_COUNT = word_count(DEFAULT_MNEMONIC);

#define MAKE_ONES(T, count) static_cast<T>((T{0b1u} << count) - T{0b1u})

inline void gpu_assert(cudaError_t code, const char* file, int line, bool abort = true) {
  if (code == cudaSuccess) {
    return;
  }
  fprintf(stderr, "GPU Assert: %s %s %d\n", cudaGetErrorString(code), file, line);
  if (abort) {
    exit(code);
  }
}

#define UNWRAP_GPU(result) \
  { gpu_assert((result), __FILE__, __LINE__); }

inline void curand_assert(curandStatus_t code, const char* file, int line, bool abort = true) {
  if (code == curandStatus::CURAND_STATUS_SUCCESS) {
    return;
  }
  fprintf(stderr, "cuRAND Assert: STATUS(%d) %s %d\n", code, file, line);
  if (abort) {
    exit(code);
  }
}

#define UNWRAP_CURAND(result) \
  { curand_assert((result), __FILE__, __LINE__); }

__global__ void init_kernel(curandState* states, uint64_t seed) {
  const auto idx = threadIdx.x + blockIdx.x * blockDim.x;
  curand_init(seed, idx, 0, &states[idx]);
}

__global__ void generate_words(curandState* states, char* output) {
  const auto idx = threadIdx.x + blockIdx.x * blockDim.x;

  // Generate entropy
  uint8_t buffer[ENTROPY_SIZE + 1];
  static_assert(ENTROPY_SIZE % 4 == 0, "Unaligned entropy used");

  for (auto i = 0; i < ENTROPY_SIZE / 4; ++i) {
    const auto randChunk = curand(&states[idx]);
    static_assert(sizeof(randChunk) == 4, "Invalid rand chunk length");

    for (auto j = 0; j < 4; ++j) {
      buffer[i * 4 + j] = reinterpret_cast<const uint8_t*>(&randChunk)[j];
    }
  }

  // Calculate checksum
  Sha256Context ctx{};
  sha256_init(&ctx);
  sha256_update(&ctx, buffer, ENTROPY_SIZE);
  buffer[ENTROPY_SIZE] = ctx.state[0] >> 24u;

  // Generate phrase
  auto phraseOffset = idx * MAX_PHRASE_LENGTH;
  auto bitsOffset = 0;
  for (auto i = 0; i < WORD_COUNT; ++i) {
    const auto j = bitsOffset / 8u;

    const auto first_byte_length = static_cast<uint16_t>(8u - (bitsOffset & 0b111u));

    const auto second_byte_length = MIN(11u - first_byte_length, 8u);
    const auto second_byte_offset = static_cast<uint16_t>(8u - second_byte_length);

    const auto third_byte_length = 11u - first_byte_length - second_byte_length;
    const auto third_byte_offset = static_cast<uint16_t>(8u - third_byte_length);

    uint16_t word_i{};
    word_i |= static_cast<uint16_t>(buffer[j] & MAKE_ONES(uint16_t, first_byte_length));
    word_i <<= second_byte_length;
    word_i |= static_cast<uint16_t>(buffer[j + 1] >> second_byte_offset);
    if (third_byte_length > 0) {
      word_i <<= third_byte_length;
      word_i |= static_cast<uint16_t>(buffer[j + 2] >> third_byte_offset);
    }

    bitsOffset += 11u;

    if (word_i >= 2048) {
      output[phraseOffset++] = 'A';
      continue;
    }

    if (i != 0) {
      output[phraseOffset++] = ' ';
    }
    auto word = reinterpret_cast<const char*>(&BIP39[word_i * 2]);
    for (auto k = 0; k < MAX_BIP39_WORD_LEN && word[k] != 0; ++k) {
      output[phraseOffset++] = word[k];
    }
  }
}

auto main() -> int {
  curandState* states;
  UNWRAP_GPU(cudaMalloc(&states, THREAD_COUNT * sizeof(curandState)))

  char* output;
  UNWRAP_GPU(cudaMallocManaged(&output, THREAD_COUNT * MAX_PHRASE_LENGTH))

  std::cout << "Word count: " << WORD_COUNT << std::endl;

  init_kernel<<<(THREAD_COUNT + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK, THREADS_PER_BLOCK>>>(states, 1);
  UNWRAP_GPU(cudaPeekAtLastError())
  UNWRAP_GPU(cudaDeviceSynchronize())

  generate_words<<<(THREAD_COUNT + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK, THREADS_PER_BLOCK>>>(states, output);
  UNWRAP_GPU(cudaPeekAtLastError())
  UNWRAP_GPU(cudaDeviceSynchronize())

  for (auto i = 0; i < THREAD_COUNT; ++i) {
    printf("%s\n", &output[i * MAX_PHRASE_LENGTH]);
  }

  UNWRAP_GPU(cudaFree(states))
  UNWRAP_GPU(cudaFree(output))
  return 0;
}
