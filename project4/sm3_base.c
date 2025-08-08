
/* --- FILE: sm3_base.c --- */
#include "sm3.h"
#include <string.h>
#if defined(_MSC_VER)
#define ROTL32(x,n) _rotl((uint32_t)(x), (n))
#elif defined(__has_builtin)
#  if __has_builtin(__builtin_rotateleft32)
#    define ROTL32(x,n) __builtin_rotateleft32((uint32_t)(x), (n))
#  else
#    define ROTL32(x,n) (uint32_t)(((x) << (n)) | ((x) >> (32 - (n))))
#  endif
#else
#  define ROTL32(x,n) (uint32_t)(((x) << (n)) | ((x) >> (32 - (n))))
#endif

#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}
static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}
static inline uint32_t T(int j) {
    const uint32_t Tj = (j <= 15) ? 0x79CC4519u : 0x7A879D8Au;
    return ROTL32(Tj, j);
}

static inline uint32_t rd32be(const uint8_t b[4]) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}
static inline void wr32be(uint8_t out[4], uint32_t x) {
    out[0]=(uint8_t)(x>>24); out[1]=(uint8_t)(x>>16); out[2]=(uint8_t)(x>>8); out[3]=(uint8_t)x;
}

static void sm3_compress(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t Wp[64];

    for (int i = 0; i < 16; ++i) W[i] = rd32be(block + 4*i);
    for (int i = 16; i < 68; ++i) {
        uint32_t x = W[i - 16] ^ W[i - 9] ^ ROTL32(W[i - 3], 15);
        W[i] = P1(x) ^ ROTL32(W[i - 13], 7) ^ W[i - 6];
    }
    for (int i = 0; i < 64; ++i) Wp[i] = W[i] ^ W[i + 4];

    uint32_t A=V[0],B=V[1],C=V[2],D=V[3],E=V[4],F=V[5],G=V[6],H=V[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t A12 = ROTL32(A, 12);
        uint32_t SS1 = ROTL32((A12 + E + T(j)) & 0xFFFFFFFFu, 7);
        uint32_t SS2 = SS1 ^ A12;
        uint32_t TT1 = (FF(A,B,C,j) + D + SS2 + Wp[j]) & 0xFFFFFFFFu;
        uint32_t TT2 = (GG(E,F,G,j) + H + SS1 + W[j]) & 0xFFFFFFFFu;
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
    }

    V[0]^=A; V[1]^=B; V[2]^=C; V[3]^=D; V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;
}

void sm3_init(sm3_ctx *ctx) {
    static const uint32_t IV[8] = {
        0x7380166Fu, 0x4914B2B9u, 0x172442D7u, 0xDA8A0600u,
        0xA96F30BCu, 0x163138AAu, 0xE38DEE4Du, 0xB0FB0E4Eu
    };
    memcpy(ctx->state, IV, sizeof(IV));
    ctx->total = 0; ctx->buf_len = 0;
}

void sm3_update(sm3_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    ctx->total += len;
    if (ctx->buf_len) {
        size_t to_copy = 64 - ctx->buf_len; if (to_copy > len) to_copy = len;
        memcpy(ctx->buffer + ctx->buf_len, p, to_copy);
        ctx->buf_len += to_copy; p += to_copy; len -= to_copy;
        if (ctx->buf_len == 64) { sm3_compress(ctx->state, ctx->buffer); ctx->buf_len = 0; }
    }
    while (len >= 64) { sm3_compress(ctx->state, p); p += 64; len -= 64; }
    if (len) { memcpy(ctx->buffer + ctx->buf_len, p, len); ctx->buf_len += len; }
}

void sm3_final(sm3_ctx *ctx, uint8_t out[32]) {
    uint64_t total_bits = ctx->total * 8u;
    uint8_t pad[64 + 56]; size_t pad_len = 0;
    pad[pad_len++] = 0x80;
    size_t rem = (ctx->buf_len + 1) % 64;
    size_t zeroes = (rem <= 56) ? (56 - rem) : (56 + 64 - rem);
    memset(pad + pad_len, 0, zeroes); pad_len += zeroes;
    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i) len_be[7 - i] = (uint8_t)(total_bits >> (8 * i));
    sm3_update(ctx, pad, pad_len);
    sm3_update(ctx, len_be, 8);
    for (int i = 0; i < 8; ++i) wr32be(out + 4*i, ctx->state[i]);
    memset(ctx, 0, sizeof(*ctx));
}

void sm3_base(const void *data, size_t len, uint8_t out[32]) {
    sm3_ctx c; sm3_init(&c); sm3_update(&c, data, len); sm3_final(&c, out);
}

