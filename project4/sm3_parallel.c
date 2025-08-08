
/* --- FILE: sm3_parrele.c --- */
// 4-way parallel SM3 with AVX2 fast path (equal-length messages) and portable fallback.
#include "sm3.h"
#include <string.h>
#ifdef __AVX2__
#include <immintrin.h>
#endif

void sm3x4_init(sm3x4_ctx *c){ for (int i=0;i<4;++i) sm3_init(&c->lane[i]); }

// Portable baseline (any lengths). Feeds each lane in chunks for cache locality.
void sm3x4_update(sm3x4_ctx *c, const uint8_t *data[4], const size_t len[4]){
    const size_t CHUNK=32768; size_t rem[4]={len[0],len[1],len[2],len[3]};
    const uint8_t* p[4]={data[0],data[1],data[2],data[3]};
    for(;;){ size_t any=rem[0]|rem[1]|rem[2]|rem[3]; if(!any) break;
        for(int i=0;i<4;++i){ if(rem[i]){ size_t t=rem[i]>CHUNK?CHUNK:rem[i]; sm3_update(&c->lane[i], p[i], t); p[i]+=t; rem[i]-=t; }} }
}

void sm3x4_final(sm3x4_ctx *c, uint8_t out[4][32]){ for(int i=0;i<4;++i) sm3_final(&c->lane[i], out[i]); }

#ifdef __AVX2__
// --- AVX2 helpers ---
static inline __m256i vrotl32(__m256i x, int n){
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32-n));
}
static inline __m256i vP0(__m256i x){ return _mm256_xor_si256(_mm256_xor_si256(x, vrotl32(x,9)), vrotl32(x,17)); }
static inline __m256i vP1(__m256i x){ return _mm256_xor_si256(_mm256_xor_si256(x, vrotl32(x,15)), vrotl32(x,23)); }
static inline __m256i vbroadcast32(uint32_t x){ return _mm256_set1_epi32((int)x); }
static inline __m256i vFF(__m256i X, __m256i Y, __m256i Z, int j){
    if (j<=15) return _mm256_xor_si256(_mm256_xor_si256(X,Y), Z);
    return _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(X,Y), _mm256_and_si256(X,Z)), _mm256_and_si256(Y,Z));
}
static inline __m256i vGG(__m256i X, __m256i Y, __m256i Z, int j){
    if (j<=15) return _mm256_xor_si256(_mm256_xor_si256(X,Y), Z);
    return _mm256_or_si256(_mm256_and_si256(X,Y), _mm256_andnot_si256(X,Z));
}

static void sm3_compress4(__m256i V[8], const uint8_t *blk0, const uint8_t *blk1, const uint8_t *blk2, const uint8_t *blk3){
    // Prepare schedule for 4 lanes (scalar), then pack to vectors.
    uint32_t W[4][68];
    for(int i=0;i<16;++i){
        W[0][i] = ((uint32_t)blk0[4*i]<<24)|((uint32_t)blk0[4*i+1]<<16)|((uint32_t)blk0[4*i+2]<<8)|(uint32_t)blk0[4*i+3];
        W[1][i] = ((uint32_t)blk1[4*i]<<24)|((uint32_t)blk1[4*i+1]<<16)|((uint32_t)blk1[4*i+2]<<8)|(uint32_t)blk1[4*i+3];
        W[2][i] = ((uint32_t)blk2[4*i]<<24)|((uint32_t)blk2[4*i+1]<<16)|((uint32_t)blk2[4*i+2]<<8)|(uint32_t)blk2[4*i+3];
        W[3][i] = ((uint32_t)blk3[4*i]<<24)|((uint32_t)blk3[4*i+1]<<16)|((uint32_t)blk3[4*i+2]<<8)|(uint32_t)blk3[4*i+3];
    }
    for(int i=16;i<68;++i){
        for(int l=0;l<4;++l){
            uint32_t r3 = (W[l][i-3] << 15) | (W[l][i-3] >> 17);
            uint32_t x  = W[l][i-16] ^ W[l][i-9] ^ r3;
            uint32_t p1 = x ^ ((x<<15)|(x>>17)) ^ ((x<<23)|(x>>9));
            W[l][i] = p1 ^ ((W[l][i-13]<<7)|(W[l][i-13]>>25)) ^ W[l][i-6];
        }
    }
    __m256i Wv[68], Wpv[64];
    for(int i=0;i<68;++i){
        __m128i low = _mm_set_epi32((int)W[3][i], (int)W[2][i], (int)W[1][i], (int)W[0][i]);
        Wv[i] = _mm256_broadcastsi128_si256(low);
    }
    for(int i=0;i<64;++i) Wpv[i] = _mm256_xor_si256(Wv[i], Wv[i+4]);

    __m256i A=V[0],B=V[1],C=V[2],D=V[3],E=V[4],F=V[5],G=V[6],H=V[7];

    for(int j=0;j<64;++j){
        __m256i A12 = vrotl32(A,12);
        uint32_t Tj = (j<=15)?0x79CC4519u:0x7A879D8Au;
        __m256i SS1 = vrotl32(_mm256_add_epi32(_mm256_add_epi32(A12,E), vrotl32(vbroadcast32(Tj), j)), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, A12);
        __m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(vFF(A,B,C,j), D), SS2), Wpv[j]);
        __m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(vGG(E,F,G,j), H), SS1), Wv[j]);
        D=C; C=vrotl32(B,9); B=A; A=TT1;
        H=G; G=vrotl32(F,19); F=E; E=vP0(TT2);
    }

    V[0] = _mm256_xor_si256(V[0], A);
    V[1] = _mm256_xor_si256(V[1], B);
    V[2] = _mm256_xor_si256(V[2], C);
    V[3] = _mm256_xor_si256(V[3], D);
    V[4] = _mm256_xor_si256(V[4], E);
    V[5] = _mm256_xor_si256(V[5], F);
    V[6] = _mm256_xor_si256(V[6], G);
    V[7] = _mm256_xor_si256(V[7], H);
}
#endif // __AVX2__

void sm3_parrele(
    const uint8_t *m0, size_t n0,
    const uint8_t *m1, size_t n1,
    const uint8_t *m2, size_t n2,
    const uint8_t *m3, size_t n3,
    uint8_t out0[32], uint8_t out1[32], uint8_t out2[32], uint8_t out3[32]){
#ifdef __AVX2__
    // AVX2 fast path: all messages have equal length.
    if (n0==n1 && n1==n2 && n2==n3){
        __m256i V[8]; __m128i low;
        low = _mm_set1_epi32(0x7380166F); V[0]=_mm256_broadcastsi128_si256(low);
        low = _mm_set1_epi32(0x4914B2B9); V[1]=_mm256_broadcastsi128_si256(low);
        low = _mm_set1_epi32(0x172442D7); V[2]=_mm256_broadcastsi128_si256(low);
        low = _mm_set1_epi32(0xDA8A0600); V[3]=_mm256_broadcastsi128_si256(low);
        low = _mm_set1_epi32(0xA96F30BC); V[4]=_mm256_broadcastsi128_si256(low);
        low = _mm_set1_epi32(0x163138AA); V[5]=_mm256_broadcastsi128_si256(low);
        low = _mm_set1_epi32(0xE38DEE4D); V[6]=_mm256_broadcastsi128_si256(low);
        low = _mm_set1_epi32(0xB0FB0E4E); V[7]=_mm256_broadcastsi128_si256(low);
        size_t off=0, full = n0 & ~(size_t)63;
        while (off < full){ sm3_compress4(V, m0+off, m1+off, m2+off, m3+off); off += 64; }
        // Finish each lane with scalar padding.
        sm3_ctx c0,c1,c2,c3; memset(&c0,0,sizeof c0); memset(&c1,0,sizeof c1); memset(&c2,0,sizeof c2); memset(&c3,0,sizeof c3);
        for(int i=0;i<8;++i){
            c0.state[i]=(uint32_t)_mm256_extract_epi32(V[i],0);
            c1.state[i]=(uint32_t)_mm256_extract_epi32(V[i],1);
            c2.state[i]=(uint32_t)_mm256_extract_epi32(V[i],2);
            c3.state[i]=(uint32_t)_mm256_extract_epi32(V[i],3);
        }
        c0.total=c1.total=c2.total=c3.total=off; c0.buf_len=c1.buf_len=c2.buf_len=c3.buf_len=0;
        if (off < n0){ size_t tail=n0-off;
            memcpy(c0.buffer,m0+off,tail); c0.buf_len=tail;
            memcpy(c1.buffer,m1+off,tail); c1.buf_len=tail;
            memcpy(c2.buffer,m2+off,tail); c2.buf_len=tail;
            memcpy(c3.buffer,m3+off,tail); c3.buf_len=tail;
        }
        sm3_final(&c0,out0); sm3_final(&c1,out1); sm3_final(&c2,out2); sm3_final(&c3,out3);
        return;
    }
#endif
    // Fallback portable path (handles different lengths)
    sm3x4_ctx c; sm3x4_init(&c);
    const uint8_t* msgs[4]={m0,m1,m2,m3}; const size_t lens[4]={n0,n1,n2,n3};
    sm3x4_update(&c, msgs, lens);
    uint8_t outs[4][32]; sm3x4_final(&c, outs);
    memcpy(out0, outs[0], 32); memcpy(out1, outs[1], 32); memcpy(out2, outs[2], 32); memcpy(out3, outs[3], 32);
}
