#include <stdio.h>
#include <memory.h>
#include <pthread.h>
#include <stdatomic.h>
#include <argp.h>

#include <sys/sysinfo.h>

#include "mnemonic.h"
#include "contract.h"
#include "cell.h"

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

const uint8_t BITS[16] = {4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0};

atomic_int started_threads;
atomic_uint max_affinity;
pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;

const char* argp_program_version = "mineaddr 0.1.0";
static char doc[] = "Simple and fast multisig address miner for TON";
static struct argp_option options[] = {
    {"nomnemonic", 'n', 0, 0, "Generate only keys", 0}, {"fast", 'f', 0, 0, "Use /dev/random", 0}, {0}};

typedef struct Arguments {
  bool no_nemonic;
  bool fast;
} Arguments;

static error_t parse_opt(int key, char*, struct argp_state* state) {
  struct Arguments* arguments = state->input;
  switch (key) {
    case 'n':
      arguments->no_nemonic = true;
      break;
    case 'f':
      arguments->fast = true;
      break;
    case ARGP_KEY_ARG:
      return 0;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, "", doc, 0, 0, 0};

inline uint8_t get_affinity(const uint8_t* left, const uint8_t* right) {
  uint8_t result = 0;
  for (int i = 0; i < 32; ++i) {
    const uint8_t x = left[i] ^ right[i];

    if (x == 0) {
      result += 8;
    } else {
      if ((x & 0xf0) == 0) {
        result += BITS[(x & 0x0f)] + 4;
      } else {
        result += BITS[(x >> 4)];
      }
      break;
    }
  }

  return result;
}

bool get_address(int thread_id, ContractContext* cc, Arguments* args, const uint8_t* prefix) {
  // const bool no_mnemonic = args->no_nemonic;
  const bool fast = args->fast;

  EC_GROUP* secp256k1;
  if (!group_init(&secp256k1)) {
    fprintf(stderr, "failed to initialize secp256k1\n");
    return 1;
  }

  BocContext bc;
  memset(&bc, 0, sizeof(bc));

  {
    ByteStream src;
    byte_stream_init(&src, (uint8_t*)cc->wallet, cc->wallet_size);
    deserialize_cells_tree(&src, &bc, cc);
  }

  find_public_key_cell(&bc);  // sets public key cell index to boc_context
  Cell* cell = &bc.cells[bc.public_key_cell_index];
  uint8_t cell_data_size = cell_get_data_size(cell);
  uint8_t* cell_data = cell_get_data(cell);

  memcpy(bc.public_key_cell_data, cell_data, cell_data_size);

  uint8_t* data = bc.public_key_cell_data;
  SliceData slice;
  slice_data_init(&slice, data, sizeof(bc.public_key_cell_data));
  slice_data_move_by(&slice, bc.public_key_label_size_bits);
  uint8_t public_key_offset = slice.data_window_start;

  // char phrase[MAX_PHRASE_LENGTH];
  uint8_t private_key[32];
  uint8_t public_key[32];

  uint8_t previous_affinity = 0;

  int iteration = 0;
  while (true) {
    iteration += 1;

    if (unlikely(!generate_key_pair(fast, private_key, public_key))) {
      fprintf(stderr, "failed to generate key pair\n");
      return 1;
    }

    // const int phrase_len = generate_mnemonic(fast, phrase);
    // if (phrase_len < 0) {
    //   fprintf(stderr, "failed to generate mnemonic\n");
    //   return 1;
    // }
    //
    // PrivateKey pk;
    // if (!recover_key(secp256k1, phrase, phrase_len, &pk)) {
    //   fprintf(stderr, "failed to recover seed phrase\n");
    //   return 1;
    // }
    //
    // if (!private_key_serialize_raw_public(&pk, public_key)) {
    //   fprintf(stderr, "failed to get public key\n");
    //   return 1;
    // }
    //
    // private_key_close(&pk);

    slice_data_move_to(&slice, public_key_offset);
    slice_data_append(&slice, public_key, 32 * 8, true);

    for (int i = bc.cells_count - 1; i >= 1; --i) {
      Cell* bc_cell = &bc.cells[i];
      if (unlikely(!calc_cell_hash(bc_cell, i, &bc))) {
        return false;
      }
    }

    if (unlikely(!calc_root_cell_hash(&bc.cells[0], &bc, cc))) {
      return false;
    }

    const uint8_t affinity = get_affinity(bc.hashes, prefix);

    if (likely(affinity <= previous_affinity)) {
      continue;
    }

    const uint8_t current_affinity = atomic_load_explicit(&max_affinity, memory_order_acquire);

    if (likely(affinity > current_affinity)) {
      pthread_mutex_lock(&output_lock);

      printf("[thread %d][iteration %d] %d bits matched\n", thread_id, iteration, affinity);
      printf("Private key: ");
      for (int i = 0; i < 32; ++i) {
        printf("%02x", private_key[i]);
      }
      printf("\nPublic key: ");
      for (int i = 0; i < 32; ++i) {
        printf("%02x", public_key[i]);
      }

      // printf("Mnemonic: %s", phrase);

      printf("\nAddress: ");
      for (int i = 0; i < 32; ++i) {
        printf("%02x", bc.hashes[i]);
      }
      printf("\n\n");

      pthread_mutex_unlock(&output_lock);

      fflush(stdout);

      atomic_store_explicit(&max_affinity, affinity, memory_order_release);  // TODO: improve replace
      previous_affinity = affinity;
    }
  }
}

void* routine(void* arg) {
  const int thread_id = atomic_fetch_add_explicit(&started_threads, 1, memory_order_relaxed);

  ContractContext cc = (ContractContext){
      .code_hash = SAFE_MULTISIG_24H_CODE_HASH,
      .wallet = SAFE_MULTISIG_24H_WALLET,
      .wallet_size = sizeof(SAFE_MULTISIG_24H_WALLET),
      .wallet_cells_count = 6,
      .wallet_code_child_depth = 0x0c,
      .wallet_data_child_depth = 0x03,
  };

  const uint8_t target[32] = {
      0xde, 0xf1, 0xaa, 0x20, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  if (!get_address(thread_id, &cc, (Arguments*)arg, target)) {
    fprintf(stderr, "failed to generate address\n");
    return NULL;
  }

  return NULL;
}

int main(int argc, char* argv[]) {
  Arguments arguments;
  arguments.no_nemonic = false;
  arguments.fast = false;

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  const int thread_count = get_nprocs();
  pthread_t thread_ids[thread_count];

  for (int i = 0; i < thread_count; i++) {
    pthread_create(&thread_ids[i], NULL, routine, &arguments);
  }

  for (int i = 0; i < thread_count; i++) {
    pthread_join(thread_ids[i], NULL);
  }

  return 0;
}
