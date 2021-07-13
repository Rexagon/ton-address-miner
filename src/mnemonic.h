#ifndef MNEMONIC_H
#define MNEMONIC_H

#include <stdbool.h>

#include <openssl/ecdsa.h>

#define MAX_PHRASE_LENGTH 108u

bool group_init(EC_GROUP** group);

int generate_mnemonic(char* output);

typedef struct PrivateKey {
  EC_KEY* handle;
  EC_GROUP* group;
} PrivateKey;

bool recover_key(EC_GROUP* group, const char* phrase, int phrase_len, PrivateKey* private_key);

bool private_key_init(PrivateKey* private_key, EC_GROUP* group, const uint8_t* data);
void private_key_close(PrivateKey* private_key);
bool private_key_reset(PrivateKey* private_key, EC_GROUP* group, BIGNUM* number);
bool private_key_finalize(PrivateKey* private_key);
bool private_key_serialize(PrivateKey* private_key, uint8_t* output);
bool private_key_serialize_compressed_public(PrivateKey* private_key, uint8_t* output);
bool private_key_serialize_raw_public(PrivateKey* private_key, uint8_t* output);

typedef struct ExtendedPrivateKey {
  PrivateKey private_key;
  uint8_t chain_code[32];
} ExtendedPrivateKey;

bool extended_private_key_derive(ExtendedPrivateKey* extended_private_key, uint32_t number);

typedef struct Scalar {
  uint32_t v[8];
} Scalar;

bool scalar_init(Scalar* scalar, const BIGNUM* number);
bool scalar_check_overflow(Scalar* scalar);
bool scalar_reduce(Scalar* scalar, bool has_overflow);
bool scalar_add_in_place(Scalar* res, Scalar* a, Scalar* b);
void scalar_fill_buffer(Scalar* res, uint8_t* output);

#endif  // MNEMONIC_H
