#include "mnemonic.h"

#include <stdbool.h>
#include <memory.h>
#include <assert.h>

#include <sys/random.h>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "bip39.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAKE_ONES(T, count) (T)(((T)0b1u << count) - (T)(0b1u))

#define SECP256K1_N_0 0xD0364141u
#define SECP256K1_N_1 0xBFD25E8Cu
#define SECP256K1_N_2 0xAF48A03Bu
#define SECP256K1_N_3 0xBAAEDCE6u
#define SECP256K1_N_4 0xFFFFFFFEu
#define SECP256K1_N_5 0xFFFFFFFFu
#define SECP256K1_N_6 0xFFFFFFFFu
#define SECP256K1_N_7 0xFFFFFFFFu

const uint32_t SECP256K1_N_C_0 = ~SECP256K1_N_0 + 1u;
const uint32_t SECP256K1_N_C_1 = ~SECP256K1_N_1;
const uint32_t SECP256K1_N_C_2 = ~SECP256K1_N_2;
const uint32_t SECP256K1_N_C_3 = ~SECP256K1_N_3;
const uint32_t SECP256K1_N_C_4 = 1u;

#define PRIVATE_KEY_LEN 32

#define HARDENED_BIT 0x80000000u
#define PBKDF2_ROUNDS 2048

#define ENTROPY_SIZE 16u
#define WORD_COUNT 12u

const uint32_t DERIVATION_PATH[5] = {2147483692, 2147484044, 2147483648, 0, 0};

bool group_init(EC_GROUP** group) {
  *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  return *group != NULL;
}

int generate_mnemonic(bool fast, char* output) {
  // Generate entropy
  uint8_t buffer[ENTROPY_SIZE + 1];
  getrandom(buffer, ENTROPY_SIZE, fast ? 0 : GRND_RANDOM);

  // Calculate checksum
  uint8_t checksum[32];
  if (SHA256(buffer, ENTROPY_SIZE, checksum) != checksum) {
    return -1;
  }

  buffer[ENTROPY_SIZE] = checksum[0];

  // Generate phrase
  uint32_t phrase_length = 0;
  uint32_t bits_offset = 0;
  for (int i = 0; i < WORD_COUNT; ++i) {
    const uint32_t j = bits_offset / 8u;

    const uint32_t first_byte_length = 8u - (bits_offset & 0b111u);

    const uint32_t second_byte_length = MIN(11u - first_byte_length, 8u);
    const uint32_t second_byte_offset = 8u - second_byte_length;

    const uint32_t third_byte_length = 11u - first_byte_length - second_byte_length;
    const uint32_t third_byte_offset = 8u - third_byte_length;

    uint16_t word_i = 0;
    word_i |= (uint16_t)(buffer[j] & MAKE_ONES(uint16_t, first_byte_length));
    word_i <<= second_byte_length;
    word_i |= (uint16_t)(buffer[j + 1] >> second_byte_offset);
    if (third_byte_length > 0) {
      word_i <<= third_byte_length;
      word_i |= (uint16_t)(buffer[j + 2] >> third_byte_offset);
    }

    bits_offset += 11u;

    if (word_i >= 2048) {
      output[phrase_length++] = '?';
      continue;
    }

    if (i != 0) {
      output[phrase_length++] = ' ';
    }
    const char* word = (char*)(&BIP39[word_i * 2]);
    for (int k = 0; k < MAX_BIP39_WORD_LEN && word[k] != 0; ++k) {
      output[phrase_length++] = word[k];
    }
  }
  output[phrase_length] = 0;

  return (int)phrase_length;
}

bool generate_key_pair(bool fast, uint8_t* private_key, uint8_t* public_key) {
  getrandom(private_key, PRIVATE_KEY_LEN, fast ? 0 : GRND_RANDOM);

  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, PRIVATE_KEY_LEN);
  if (pkey == NULL) {
    return false;
  }

  size_t len = 32;
  if (!EVP_PKEY_get_raw_public_key(pkey, public_key, &len)) {
    EVP_PKEY_free(pkey);
    return false;
  }

  EVP_PKEY_free(pkey);
  return true;
}

bool recover_key(EC_GROUP* group, const char* phrase, int phrase_len, struct PrivateKey* private_key) {
  uint8_t seed[64];
  if (!PKCS5_PBKDF2_HMAC(phrase, phrase_len, (uint8_t*)"mnemonic", 8, PBKDF2_ROUNDS, EVP_sha512(), 64, seed)) {
    return false;
  }

  uint8_t hmac[64];
  uint32_t len = 0;
  if (HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, 64, hmac, &len) != hmac || len != 64) {
    return false;
  }

  if (!private_key_init(private_key, group, hmac)) {
    return false;
  }

  ExtendedPrivateKey sk = (ExtendedPrivateKey){
      .private_key = *private_key,
  };
  memcpy(sk.chain_code, &hmac[32], 32);

  if (!private_key_finalize(&sk.private_key)) {
    return false;
  }

  for (int i = 0; i < 5; ++i) {
    if (!extended_private_key_derive(&sk, DERIVATION_PATH[i])) {
      return false;
    }
  }

  *private_key = sk.private_key;
  return true;
}

bool private_key_init(PrivateKey* private_key, EC_GROUP* group, const uint8_t* data) {
  EC_KEY* handle = EC_KEY_new();
  if (handle == NULL) {
    return false;
  }

  if (!EC_KEY_set_group(handle, group)) {
    EC_KEY_free(handle);
    return false;
  }

  BIGNUM* number = BN_bin2bn(data, PRIVATE_KEY_LEN, NULL);
  if (number == NULL) {
    EC_KEY_free(handle);
    return false;
  }

  if (!EC_KEY_set_private_key(handle, number)) {
    EC_KEY_free(handle);
    BN_free(number);
    return false;
  }

  BN_free(number);

  *private_key = (PrivateKey){
      .handle = handle,
      .group = group,
  };

  return true;
}

void private_key_close(PrivateKey* private_key) {
  EC_KEY_free(private_key->handle);
}

bool private_key_reset(PrivateKey* private_key, EC_GROUP* group, BIGNUM* number) {
  EC_KEY* handle = EC_KEY_new();
  if (handle == NULL) {
    return false;
  }

  if (!EC_KEY_set_group(handle, group)) {
    EC_KEY_free(handle);
    return false;
  }

  if (!EC_KEY_set_private_key(handle, number)) {
    EC_KEY_free(handle);
    return false;
  }

  EC_KEY_free(private_key->handle);
  private_key->handle = handle;
  private_key->group = group;

  if (!private_key_finalize(private_key)) {
    EC_KEY_free(private_key->handle);
    return false;
  }

  return true;
}

bool private_key_finalize(PrivateKey* private_key) {
  const BIGNUM* pvt_key = EC_KEY_get0_private_key(private_key->handle);
  EC_POINT* pub_key = EC_POINT_new(private_key->group);

  if (!EC_POINT_mul(private_key->group, pub_key, pvt_key, NULL, NULL, NULL)) {
    EC_POINT_free(pub_key);
    return false;
  }

  if (!EC_KEY_set_public_key(private_key->handle, pub_key)) {
    EC_POINT_free(pub_key);
    return false;
  }

  EC_POINT_free(pub_key);

  return EC_KEY_check_key(private_key->handle);
}

bool private_key_serialize(PrivateKey* private_key, uint8_t* output) {
  const int len = BN_bn2binpad(EC_KEY_get0_private_key(private_key->handle), output, PRIVATE_KEY_LEN);
  return len > 0;
}

bool private_key_serialize_compressed_public(PrivateKey* private_key, uint8_t* output) {
  const EC_POINT* point = EC_KEY_get0_public_key(private_key->handle);
  if (point == NULL) {
    return false;
  }

  uint8_t* buffer;
  const size_t len = EC_POINT_point2buf(private_key->group, point, POINT_CONVERSION_COMPRESSED, &buffer, NULL);
  if (len != 33) {
    if (buffer != NULL) {
      OPENSSL_free(buffer);
    }
    return false;
  }

  memcpy(output, buffer, len);
  OPENSSL_free(buffer);

  return true;
}

bool private_key_serialize_raw_public(PrivateKey* private_key, uint8_t* output) {
  uint8_t buffer[32];
  if (!EC_KEY_priv2oct(private_key->handle, buffer, 32)) {
    return false;
  }

  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, buffer, 32);
  if (pkey == NULL) {
    return false;
  }

  size_t len = 32;
  if (!EVP_PKEY_get_raw_public_key(pkey, output, &len)) {
    EVP_PKEY_free(pkey);
    return false;
  }

  EVP_PKEY_free(pkey);
  return true;
}

bool extended_private_key_derive(ExtendedPrivateKey* extended_private_key, uint32_t number) {
  uint8_t hmac[64];
  uint8_t hmac_input[37];

  if ((number & HARDENED_BIT) == 0) {
    if (!private_key_serialize_compressed_public(&extended_private_key->private_key, hmac_input)) {
      return false;
    }
  } else {
    hmac_input[0] = 0;
    if (!private_key_serialize(&extended_private_key->private_key, &hmac_input[1])) {
      return false;
    }
  }

  for (uint32_t i = 0; i < 4; ++i) {
    const uint8_t shift = (uint8_t)(3u - i) << 3u;
    hmac_input[33 + i] = (uint8_t)(number >> shift);
  }

  uint32_t len = 0;
  if (HMAC(EVP_sha512(), extended_private_key->chain_code, 32, hmac_input, 37, hmac, &len) != hmac || len != 64) {
    return false;
  }

  PrivateKey temp_key;
  if (!private_key_init(&temp_key, extended_private_key->private_key.group, hmac)) {
    return false;
  }
  if (!private_key_finalize(&temp_key)) {
    private_key_close(&temp_key);
    return false;
  }

  Scalar source_data, current_data;
  if (!scalar_init(&source_data, EC_KEY_get0_private_key(temp_key.handle))) {
    private_key_close(&temp_key);
    return false;
  }
  private_key_close(&temp_key);

  if (!scalar_init(&current_data, EC_KEY_get0_private_key(extended_private_key->private_key.handle))) {
    return false;
  }

  Scalar result;
  scalar_add_in_place(&result, &source_data, &current_data);

  uint8_t buffer[32];
  scalar_fill_buffer(&result, buffer);

  BIGNUM* bn_buffer = BN_bin2bn(buffer, PRIVATE_KEY_LEN, NULL);
  if (bn_buffer == NULL) {
    return false;
  }

  if (!private_key_reset(&extended_private_key->private_key, extended_private_key->private_key.group, bn_buffer)) {
    BN_free(bn_buffer);
    return false;
  }

  BN_free(bn_buffer);

  memcpy(extended_private_key->chain_code, &hmac[32], 32);

  return true;
}

bool scalar_init(Scalar* scalar, const BIGNUM* number) {
  uint8_t b[32];

  const int len = BN_bn2binpad(number, b, PRIVATE_KEY_LEN);
  if (len < 0 || len > PRIVATE_KEY_LEN) {
    return false;
  }

  uint32_t* v = scalar->v;
  v[0] = (uint32_t)b[31] | ((uint32_t)b[30] << 8u) | ((uint32_t)b[29] << 16u) | ((uint32_t)b[28] << 24u);
  v[1] = (uint32_t)b[27] | ((uint32_t)b[26] << 8u) | ((uint32_t)b[25] << 16u) | ((uint32_t)b[24] << 24u);
  v[2] = (uint32_t)b[23] | ((uint32_t)b[22] << 8u) | ((uint32_t)b[21] << 16u) | ((uint32_t)b[20] << 24u);
  v[3] = (uint32_t)b[19] | ((uint32_t)b[18] << 8u) | ((uint32_t)b[17] << 16u) | ((uint32_t)b[16] << 24u);
  v[4] = (uint32_t)b[15] | ((uint32_t)b[14] << 8u) | ((uint32_t)b[13] << 16u) | ((uint32_t)b[12] << 24u);
  v[5] = (uint32_t)b[11] | ((uint32_t)b[10] << 8u) | ((uint32_t)b[9] << 16u) | ((uint32_t)b[8] << 24u);
  v[6] = (uint32_t)b[7] | ((uint32_t)b[6] << 8u) | ((uint32_t)b[5] << 16u) | ((uint32_t)b[4] << 24u);
  v[7] = (uint32_t)b[3] | ((uint32_t)b[2] << 8u) | ((uint32_t)b[1] << 16u) | ((uint32_t)b[0] << 24u);

  scalar_reduce(scalar, scalar_check_overflow(scalar));

  return true;
}

bool scalar_check_overflow(Scalar* scalar) {
  uint32_t* v = scalar->v;
  bool yes = false;
  bool no = false;
  no = no || (v[7] < SECP256K1_N_7); /* No need for a > check. */
  no = no || (v[6] < SECP256K1_N_6); /* No need for a > check. */
  no = no || (v[5] < SECP256K1_N_5); /* No need for a > check. */
  no = no || (v[4] < SECP256K1_N_4);
  yes = yes || ((v[4] > SECP256K1_N_4) && !no);
  no = no || ((v[3] < SECP256K1_N_3) && !yes);
  yes = yes || ((v[3] > SECP256K1_N_3) && !no);
  no = no || ((v[2] < SECP256K1_N_2) && !yes);
  yes = yes || ((v[2] > SECP256K1_N_2) && !no);
  no = no || ((v[1] < SECP256K1_N_1) && !yes);
  yes = yes || ((v[1] > SECP256K1_N_1) && !no);
  yes = yes || ((v[0] >= SECP256K1_N_0) && !no);
  return yes;
}

bool scalar_reduce(Scalar* scalar, bool has_overflow) {
  uint32_t* v = scalar->v;
  uint64_t o = has_overflow;
  uint64_t t;
  t = (uint64_t)v[0] + o * (uint64_t)SECP256K1_N_C_0;
  v[0] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)v[1] + o * (uint64_t)SECP256K1_N_C_1;
  v[1] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)v[2] + o * (uint64_t)SECP256K1_N_C_2;
  v[2] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)v[3] + o * (uint64_t)SECP256K1_N_C_3;
  v[3] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)v[4] + o * (uint64_t)SECP256K1_N_C_4;
  v[4] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)v[5];
  v[5] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)v[6];
  v[6] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)v[7];
  v[7] = (uint32_t)t;
  return has_overflow;
}

bool scalar_add_in_place(Scalar* res, Scalar* a, Scalar* b) {
  uint32_t* v = res->v;
  uint32_t* av = a->v;
  uint32_t* bv = b->v;

  uint64_t t = (uint64_t)av[0] + (uint64_t)bv[0];
  v[0] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)av[1] + (uint64_t)bv[1];
  v[1] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)av[2] + (uint64_t)bv[2];
  v[2] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)av[3] + (uint64_t)bv[3];
  v[3] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)av[4] + (uint64_t)bv[4];
  v[4] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)av[5] + (uint64_t)bv[5];
  v[5] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)av[6] + (uint64_t)bv[6];
  v[6] = (uint32_t)t;
  t >>= 32u;
  t += (uint64_t)av[7] + (uint64_t)bv[7];
  v[7] = (uint32_t)t;
  t >>= 32u;

  uint64_t overflow = t + (uint64_t)scalar_check_overflow(res);
  assert(overflow == 0 || overflow == 1);

  overflow = overflow | (uint64_t)scalar_reduce(res, overflow == 1);
  return overflow == 1;
}

void scalar_fill_buffer(Scalar* res, uint8_t* output) {
  uint32_t* v = res->v;
  output[0] = (v[7] >> 24u);
  output[1] = (v[7] >> 16u);
  output[2] = (v[7] >> 8u);
  output[3] = (v[7]);
  output[4] = (v[6] >> 24u);
  output[5] = (v[6] >> 16u);
  output[6] = (v[6] >> 8u);
  output[7] = (v[6]);
  output[8] = (v[5] >> 24u);
  output[9] = (v[5] >> 16u);
  output[10] = (v[5] >> 8u);
  output[11] = (v[5]);
  output[12] = (v[4] >> 24u);
  output[13] = (v[4] >> 16u);
  output[14] = (v[4] >> 8u);
  output[15] = (v[4]);
  output[16] = (v[3] >> 24u);
  output[17] = (v[3] >> 16u);
  output[18] = (v[3] >> 8u);
  output[19] = (v[3]);
  output[20] = (v[2] >> 24u);
  output[21] = (v[2] >> 16u);
  output[22] = (v[2] >> 8u);
  output[23] = (v[2]);
  output[24] = (v[1] >> 24u);
  output[25] = (v[1] >> 16u);
  output[26] = (v[1] >> 8u);
  output[27] = (v[1]);
  output[28] = (v[0] >> 24u);
  output[29] = (v[0] >> 16u);
  output[30] = (v[0] >> 8u);
  output[31] = (v[0]);
}
