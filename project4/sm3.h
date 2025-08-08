
/* --- FILE: sm3.h --- */
#ifndef SM3_H
#define SM3_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" { 
#endif

typedef struct {
    uint32_t state[8];
    uint64_t total;      // total bytes processed
    uint8_t  buffer[64];
    size_t   buf_len;
} sm3_ctx;

// ===== Base (scalar) API =====
void sm3_init(sm3_ctx *ctx);
void sm3_update(sm3_ctx *ctx, const void *data, size_t len);
void sm3_final(sm3_ctx *ctx, uint8_t out[32]);
void sm3_base(const void *data, size_t len, uint8_t out[32]);

// ===== Parallel API (4-way). AVX2-accelerated implementation in sm3_parrele.c =====
typedef struct { sm3_ctx lane[4]; } sm3x4_ctx;
void sm3x4_init(sm3x4_ctx *c);
void sm3x4_update(sm3x4_ctx *c, const uint8_t *data[4], const size_t len[4]);
void sm3x4_final(sm3x4_ctx *c, uint8_t out[4][32]);
void sm3_parrele(
    const uint8_t *m0, size_t n0,
    const uint8_t *m1, size_t n1,
    const uint8_t *m2, size_t n2,
    const uint8_t *m3, size_t n3,
    uint8_t out0[32], uint8_t out1[32], uint8_t out2[32], uint8_t out3[32]);

#ifdef __cplusplus
}
#endif
#endif // SM3_H