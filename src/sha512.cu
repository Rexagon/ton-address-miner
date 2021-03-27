#include "sha512.cuh"

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (64 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 28) ^ ROTRIGHT(x, 34) ^ ROTRIGHT(x, 39))
#define EP1(x) (ROTRIGHT(x, 14) ^ ROTRIGHT(x, 18) ^ ROTRIGHT(x, 41))
#define SIG0(x) (ROTRIGHT(x, 1) ^ ROTRIGHT(x, 8) ^ ((x) >> 7))
#define SIG1(x) (ROTRIGHT(x, 19) ^ ROTRIGHT(x, 61) ^ ((x) >> 6))

__constant__ uint64_t sha512_kernel[] = {
    0x428a2f98d728ae22ul, 0x7137449123ef65cdul, 0xb5c0fbcfec4d3b2ful, 0xe9b5dba58189dbbcul, 0x3956c25bf348b538ul,
    0x59f111f1b605d019ul, 0x923f82a4af194f9bul, 0xab1c5ed5da6d8118ul, 0xd807aa98a3030242ul, 0x12835b0145706fbeul,
    0x243185be4ee4b28cul, 0x550c7dc3d5ffb4e2ul, 0x72be5d74f27b896ful, 0x80deb1fe3b1696b1ul, 0x9bdc06a725c71235ul,
    0xc19bf174cf692694ul, 0xe49b69c19ef14ad2ul, 0xefbe4786384f25e3ul, 0x0fc19dc68b8cd5b5ul, 0x240ca1cc77ac9c65ul,
    0x2de92c6f592b0275ul, 0x4a7484aa6ea6e483ul, 0x5cb0a9dcbd41fbd4ul, 0x76f988da831153b5ul, 0x983e5152ee66dfabul,
    0xa831c66d2db43210ul, 0xb00327c898fb213ful, 0xbf597fc7beef0ee4ul, 0xc6e00bf33da88fc2ul, 0xd5a79147930aa725ul,
    0x06ca6351e003826ful, 0x142929670a0e6e70ul, 0x27b70a8546d22ffcul, 0x2e1b21385c26c926ul, 0x4d2c6dfc5ac42aedul,
    0x53380d139d95b3dful, 0x650a73548baf63deul, 0x766a0abb3c77b2a8ul, 0x81c2c92e47edaee6ul, 0x92722c851482353bul,
    0xa2bfe8a14cf10364ul, 0xa81a664bbc423001ul, 0xc24b8b70d0f89791ul, 0xc76c51a30654be30ul, 0xd192e819d6ef5218ul,
    0xd69906245565a910ul, 0xf40e35855771202aul, 0x106aa07032bbd1b8ul, 0x19a4c116b8d2d0c8ul, 0x1e376c085141ab53ul,
    0x2748774cdf8eeb99ul, 0x34b0bcb5e19b48a8ul, 0x391c0cb3c5c95a63ul, 0x4ed8aa4ae3418acbul, 0x5b9cca4f7763e373ul,
    0x682e6ff3d6b2b8a3ul, 0x748f82ee5defb2fcul, 0x78a5636f43172f60ul, 0x84c87814a1f0ab72ul, 0x8cc702081a6439ecul,
    0x90befffa23631e28ul, 0xa4506cebde82bde9ul, 0xbef9a3f7b2c67915ul, 0xc67178f2e372532bul, 0xca273eceea26619cul,
    0xd186b8c721c0c207ul, 0xeada7dd6cde0eb1eul, 0xf57d4f7fee6ed178ul, 0x06f067aa72176fbaul, 0x0a637dc5a2c898a6ul,
    0x113f9804bef90daeul, 0x1b710b35131c471bul, 0x28db77f523047d84ul, 0x32caab7b40c72493ul, 0x3c9ebe0a15c9bebcul,
    0x431d67c49c100d4cul, 0x4cc5d4becb3e42b6ul, 0x597f299cfc657e2aul, 0x5fcb6fab3ad6faecul, 0x6c44198c4a475817ul};

__device__ void sha512_transform(Sha512Context *ctx, const uint8_t data[128]) {
  uint64_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[80];

#pragma unroll 16
  for (i = 0, j = 0; i < 16; ++i, j += 8) {
    m[i] = (static_cast<uint64_t>(data[j + 0]) << 56) | (static_cast<uint64_t>(data[j + 1]) << 48) |
           (static_cast<uint64_t>(data[j + 2]) << 40) | (static_cast<uint64_t>(data[j + 3]) << 32) |
           (static_cast<uint64_t>(data[j + 4]) << 24) | (static_cast<uint64_t>(data[j + 5]) << 16) |
           (static_cast<uint64_t>(data[j + 6]) << 8) | (static_cast<uint64_t>(data[j + 7]));
  }

#pragma unroll 80
  for (; i < 80; ++i) {
    m[i] = m[i - 16] + SIG0(m[i - 15]) + SIG1(m[i - 2]) + m[i - 7];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

#pragma unroll 80
  for (i = 0; i < 80; ++i) {
    t1 = h + EP1(e) + CH(e, f, g) + sha512_kernel[i] + m[i];
    t2 = EP0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

__device__ void sha512_init(Sha512Context *ctx) {
  ctx->dataLen = 0;
  ctx->bitLen = 0;
  ctx->state[0] = 0x6a09e667f3bcc908UL;
  ctx->state[1] = 0xbb67ae8584caa73bUL;
  ctx->state[2] = 0x3c6ef372fe94f82bUL;
  ctx->state[3] = 0xa54ff53a5f1d36f1UL;
  ctx->state[4] = 0x510e527fade682d1UL;
  ctx->state[5] = 0x9b05688c2b3e6c1fUL;
  ctx->state[6] = 0x1f83d9abfb41bd6bUL;
  ctx->state[7] = 0x5be0cd19137e2179UL;
}

__device__ void sha512_update(Sha512Context *ctx, const uint8_t data[], size_t len) {
  for (auto i = 0; i < len; ++i) {
    ctx->data[ctx->dataLen] = data[i];
    ctx->dataLen++;
    if (ctx->dataLen == 128) {
      sha512_transform(ctx, ctx->data);
      ctx->bitLen += 1024;
      ctx->dataLen = 0;
    }
  }
}

__device__ void sha512_final(Sha512Context *ctx) {
  uint32_t i;

  i = ctx->dataLen;

  // Pad whatever data is left in the buffer.
  if (ctx->dataLen < 112) {
    ctx->data[i++] = 0x80;
    while (i < 112) {
      ctx->data[i++] = 0x00;
    }
  } else {
    ctx->data[i++] = 0x80;
    while (i < 128) {
      ctx->data[i++] = 0x00;
    }
    sha512_transform(ctx, ctx->data);
    memset(ctx->data, 0, 112);
  }

  // Append to the padding the total message's length in bits and transform.
  ctx->bitLen += ctx->dataLen * 8;
  ctx->data[127] = ctx->bitLen;
  ctx->data[126] = ctx->bitLen >> 8;
  ctx->data[125] = ctx->bitLen >> 16;
  ctx->data[124] = ctx->bitLen >> 24;
  ctx->data[123] = ctx->bitLen >> 32;
  ctx->data[122] = ctx->bitLen >> 40;
  ctx->data[121] = ctx->bitLen >> 48;
  ctx->data[120] = ctx->bitLen >> 56;
  memset(ctx->data + 112, 0, 8);
  sha512_transform(ctx, ctx->data);
}

__device__ void sha512_write_output(Sha512Context *ctx, uint8_t hash[]) {
  for (auto i = 0; i < 8; ++i) {
    hash[i] = (ctx->state[0] >> (56 - i * 8)) & 0x000000ff;
    hash[i + 8] = (ctx->state[1] >> (56 - i * 8)) & 0x000000ff;
    hash[i + 16] = (ctx->state[2] >> (56 - i * 8)) & 0x000000ff;
    hash[i + 24] = (ctx->state[3] >> (56 - i * 8)) & 0x000000ff;
    hash[i + 32] = (ctx->state[4] >> (56 - i * 8)) & 0x000000ff;
    hash[i + 40] = (ctx->state[5] >> (56 - i * 8)) & 0x000000ff;
    hash[i + 48] = (ctx->state[6] >> (56 - i * 8)) & 0x000000ff;
    hash[i + 56] = (ctx->state[7] >> (56 - i * 8)) & 0x000000ff;
  }
}
