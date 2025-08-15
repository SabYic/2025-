
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static inline uint32_t rol32(uint32_t x, int r){ return (x << r) | (x >> (32 - r)); }
static inline uint32_t ror32(uint32_t x, int r){ return (x >> r) | (x << (32 - r)); }



static const uint32_t SM4_FK[4] = { 0xa3b1bac6U, 0x56aa3350U, 0x677d9197U, 0xb27022dcU };
static const uint32_t SM4_CK[32] = {
    0x00070e15U,0x1c232a31U,0x383f464dU,0x545b6269U,
    0x70777e85U,0x8c939aa1U,0xa8afb6bdU,0xc4cbd2d9U,
    0xe0e7eef5U,0xfc030a11U,0x181f262dU,0x343b4249U,
    0x50575e65U,0x6c737a81U,0x888f969dU,0xa4abb2b9U,
    0xc0c7ced5U,0xdce3eaf1U,0xf8ff060dU,0x141b2229U,
    0x30373e45U,0x4c535a61U,0x686f767dU,0x848b9299U,
    0xa0a7aeb5U,0xbcc3cad1U,0xd8dfe6edU,0xf4fb0209U,
    0x10171e25U,0x2c333a41U,0x484f565dU,0x646b7279U
};


static const uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static inline uint32_t sm4_tau(uint32_t a){
    uint8_t a0 = (a>>24)&0xff, a1=(a>>16)&0xff, a2=(a>>8)&0xff, a3=a&0xff;
    uint32_t b = ((uint32_t)SM4_SBOX[a0]<<24) | ((uint32_t)SM4_SBOX[a1]<<16) |
                 ((uint32_t)SM4_SBOX[a2]<<8)  | ((uint32_t)SM4_SBOX[a3]);
    return b;
}
static inline uint32_t sm4_L(uint32_t b){
    return b ^ rol32(b,2) ^ rol32(b,10) ^ rol32(b,18) ^ rol32(b,24);
}
static inline uint32_t sm4_T(uint32_t a){ return sm4_L(sm4_tau(a)); }

static inline uint32_t sm4_L_key(uint32_t b){
    return b ^ rol32(b,13) ^ rol32(b,23);
}
static inline uint32_t sm4_T_key(uint32_t a){ return sm4_L_key(sm4_tau(a)); }

// Round keys generation 
static void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]){
    uint32_t K0 = ((uint32_t)key[0]<<24)|((uint32_t)key[1]<<16)|((uint32_t)key[2]<<8)|key[3];
    uint32_t K1 = ((uint32_t)key[4]<<24)|((uint32_t)key[5]<<16)|((uint32_t)key[6]<<8)|key[7];
    uint32_t K2 = ((uint32_t)key[8]<<24)|((uint32_t)key[9]<<16)|((uint32_t)key[10]<<8)|key[11];
    uint32_t K3 = ((uint32_t)key[12]<<24)|((uint32_t)key[13]<<16)|((uint32_t)key[14]<<8)|key[15];
    uint32_t K[4] = { K0 ^ SM4_FK[0], K1 ^ SM4_FK[1], K2 ^ SM4_FK[2], K3 ^ SM4_FK[3] };
    for(int i=0;i<32;i++){
        uint32_t t = K[1]^K[2]^K[3]^SM4_CK[i];
        t = sm4_T_key(t);
        t ^= K[0];
        rk[i] = t;
        K[0]=K[1]; K[1]=K[2]; K[2]=K[3]; K[3]=t;
    }
}


static void sm4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]){
    uint32_t X0 = ((uint32_t)in[0]<<24)|((uint32_t)in[1]<<16)|((uint32_t)in[2]<<8)|in[3];
    uint32_t X1 = ((uint32_t)in[4]<<24)|((uint32_t)in[5]<<16)|((uint32_t)in[6]<<8)|in[7];
    uint32_t X2 = ((uint32_t)in[8]<<24)|((uint32_t)in[9]<<16)|((uint32_t)in[10]<<8)|in[11];
    uint32_t X3 = ((uint32_t)in[12]<<24)|((uint32_t)in[13]<<16)|((uint32_t)in[14]<<8)|in[15];
    for(int i=0;i<32;i++){
        uint32_t t = sm4_T(X1^X2^X3^rk[i]) ^ X0;
        X0=X1; X1=X2; X2=X3; X3=t;
    }
    uint32_t Y0=X3, Y1=X2, Y2=X1, Y3=X0;
    out[0]=Y0>>24; out[1]=Y0>>16; out[2]=Y0>>8; out[3]=Y0;
    out[4]=Y1>>24; out[5]=Y1>>16; out[6]=Y1>>8; out[7]=Y1;
    out[8]=Y2>>24; out[9]=Y2>>16; out[10]=Y2>>8; out[11]=Y2;
    out[12]=Y3>>24; out[13]=Y3>>16; out[14]=Y3>>8; out[15]=Y3;
}
static void sm4_decrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]){
    uint32_t drk[32];
    for(int i=0;i<32;i++) drk[i]=rk[31-i];
    sm4_encrypt_block(in,out,drk);
}

//T-table optimization 
#ifdef SM4_USE_TTABLE
// Precompute tables implementing L( Sbox(x) ) with byte-position rotation
static uint32_t TT0[256],TT1[256],TT2[256],TT3[256];
static int ttable_ready=0;
static inline uint32_t pack_be(uint8_t b3,uint8_t b2,uint8_t b1,uint8_t b0){
    return ((uint32_t)b3<<24)|((uint32_t)b2<<16)|((uint32_t)b1<<8)|b0;
}
static uint32_t L_of_byte(uint8_t x){
    uint32_t b = ((uint32_t)SM4_SBOX[x])<<24; // put at highest byte, others zero
    uint32_t l = b ^ rol32(b,2) ^ rol32(b,10) ^ rol32(b,18) ^ rol32(b,24);
    return l; // later we’ll rotate for other byte positions
}
static void sm4_ttable_init(){
    if(ttable_ready) return;
    for(int x=0;x<256;x++){
        uint32_t t = L_of_byte((uint8_t)x);
        TT0[x] = t;
        TT1[x] = ror32(t,8);
        TT2[x] = ror32(t,16);
        TT3[x] = ror32(t,24);
    }
    ttable_ready=1;
}
static inline uint32_t sm4_T_ttab(uint32_t a){
    uint8_t a0=(a>>24)&0xff, a1=(a>>16)&0xff, a2=(a>>8)&0xff, a3=a&0xff;
    return TT0[a0]^TT1[a1]^TT2[a2]^TT3[a3];
}
static void sm4_encrypt_block_ttab(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]){
    if(!ttable_ready) sm4_ttable_init();
    uint32_t X0 = ((uint32_t)in[0]<<24)|((uint32_t)in[1]<<16)|((uint32_t)in[2]<<8)|in[3];
    uint32_t X1 = ((uint32_t)in[4]<<24)|((uint32_t)in[5]<<16)|((uint32_t)in[6]<<8)|in[7];
    uint32_t X2 = ((uint32_t)in[8]<<24)|((uint32_t)in[9]<<16)|((uint32_t)in[10]<<8)|in[11];
    uint32_t X3 = ((uint32_t)in[12]<<24)|((uint32_t)in[13]<<16)|((uint32_t)in[14]<<8)|in[15];
    for(int i=0;i<32;i++){
        uint32_t t = sm4_T_ttab(X1^X2^X3^rk[i]) ^ X0;
        X0=X1; X1=X2; X2=X3; X3=t;
    }
    uint32_t Y0=X3, Y1=X2, Y2=X1, Y3=X0;
    out[0]=Y0>>24; out[1]=Y0>>16; out[2]=Y0>>8; out[3]=Y0;
    out[4]=Y1>>24; out[5]=Y1>>16; out[6]=Y1>>8; out[7]=Y1;
    out[8]=Y2>>24; out[9]=Y2>>16; out[10]=Y2>>8; out[11]=Y2;
    out[12]=Y3>>24; out[13]=Y3>>16; out[14]=Y3>>8; out[15]=Y3;
}
#endif

// AVX-512 rotate hooks 
#ifdef SM4_USE_AVX512
static inline __m512i rol32x16(__m512i x, int r){
#if defined(__AVX512F__)
    // VPROLD: rotate-left 32-bit lanes (AVX-512)
    return _mm512_rol_epi32(x, r);
#else
    return x; // compile guard
#endif
}
#endif

// We implement GHASH(H, A | C) with optional PCLMULQDQ acceleration.
// Poly: x^128 + x^7 + x^2 + x + 1 (0xE1 as reduction constant)

typedef struct { uint8_t H[16]; int use_pclmul; } ghash_key;

#ifndef SM4_NO_PCLMUL
// Compile-time availability check for intrinsics, independent from runtime CPUID
#if defined(__PCLMUL__)
#define SM4_HAVE_PCLMUL_COMPILE 1
#else
#define SM4_HAVE_PCLMUL_COMPILE 0
#endif

static int cpu_supports_pclmul(void){
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    eax=1; __asm__ __volatile__ ("cpuid" :
        "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx) : "a"(eax));
    return (ecx & (1u<<1))!=0; // PCLMULQDQ bit
#else
    return 0;
#endif
}
#endif
}
#endif

static void ghash_set_H(ghash_key* gk, const uint8_t H[16]){
    memcpy(gk->H, H, 16);
#ifndef SM4_NO_PCLMUL
    gk->use_pclmul = cpu_supports_pclmul();
#else
    gk->use_pclmul = 0;
#endif
}

// Byte swap 128-bit
static inline void bswap16(uint8_t x[16]){
    for(int i=0;i<8;i++){ uint8_t t=x[i]; x[i]=x[15-i]; x[15-i]=t; }
}

// Portable GF(2^128) multiply mod 0xE1
static void gf128mul_portable(uint8_t X[16], const uint8_t H[16]){
    uint8_t Z[16]={0};
    uint8_t V[16]; memcpy(V,H,16);
    for(int i=0;i<128;i++){
        int bit = (X[i>>3] >> (7-(i&7))) & 1;
        if(bit){ for(int j=0;j<16;j++) Z[j]^=V[j]; }
        int lsb = V[15] & 1;
        for(int j=15;j>0;j--) V[j] = (V[j]>>1) | (V[j-1]<<7);
        V[0] >>= 1;
        if(lsb) V[0] ^= 0xe1;
    }
    memcpy(X,Z,16);
}

#ifndef SM4_NO_PCLMUL
// PCLMULQDQ accelerated multiply (little-endian lanes);
// We convert to big-endian bit order per GCM convention.
#if SM4_HAVE_PCLMUL_COMPILE && defined(__GNUC__)
__attribute__((target("pclmul")))
#endif
static void gf128mul_pclmul(uint8_t X[16], const uint8_t H[16]){
    __m128i x = _mm_loadu_si128((const __m128i*)X);
    __m128i h = _mm_loadu_si128((const __m128i*)H);
    // Byte-swap both to big-endian polynomial form
    const __m128i rev = _mm_set_epi8(
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    // Actually use PSHUFB with reversed indices
    __m128i shuf = _mm_set_epi8(
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    // Safer: store to bytes and reverse (portable)
    uint8_t xb[16], hb[16]; _mm_storeu_si128((__m128i*)xb,x); _mm_storeu_si128((__m128i*)hb,h);
    bswap16(xb); bswap16(hb);
    x = _mm_loadu_si128((const __m128i*)xb);
    h = _mm_loadu_si128((const __m128i*)hb);

    __m128i x0 = _mm_clmulepi64_si128(x, h, 0x00);
    __m128i x1 = _mm_clmulepi64_si128(x, h, 0x01);
    __m128i x2 = _mm_clmulepi64_si128(x, h, 0x10);
    __m128i x3 = _mm_clmulepi64_si128(x, h, 0x11);

    __m128i t = _mm_xor_si128(x1, x2);

    // Karatsuba assemble into 256-bit result carried in two 128-bit regs: lo, hi
    __m128i lo = _mm_xor_si128(x0, _mm_slli_si128(t, 8));
    __m128i hi = _mm_xor_si128(x3, _mm_srli_si128(t, 8));

    // Reduction modulo x^128 + x^7 + x^2 + x + 1
    // Based on Intel whitepaper technique
    __m128i v1 = _mm_srli_epi64(hi, 63);
    __m128i v2 = _mm_srli_epi64(hi, 62);
    __m128i v7 = _mm_srli_epi64(hi, 57);

    __m128i tmp = _mm_xor_si128(_mm_xor_si128(v1, v2), v7);
    lo = _mm_xor_si128(lo, tmp);

    tmp = _mm_slli_epi64(hi, 1);
    __m128i tmp2 = _mm_slli_epi64(hi, 2);
    __m128i tmp7 = _mm_slli_epi64(hi, 7);

    lo = _mm_xor_si128(lo, _mm_xor_si128(_mm_xor_si128(tmp, tmp2), tmp7));

    // Fold carry from upper 64-bit lane to lower (per polynomial)
    __m128i lo_hi = _mm_shuffle_epi32(lo, _MM_SHUFFLE(1,0,3,2));
    __m128i hi_sh = _mm_srli_epi64(lo_hi, 63);
    __m128i hi_sh2= _mm_srli_epi64(lo_hi, 62);
    __m128i hi_sh7= _mm_srli_epi64(lo_hi, 57);
    __m128i fold = _mm_xor_si128(_mm_xor_si128(hi_sh, hi_sh2), hi_sh7);
    lo = _mm_xor_si128(lo, fold);

    // Convert back to little-endian bytes order
    _mm_storeu_si128((__m128i*)xb, lo);
    bswap16(xb);
    memcpy(X, xb, 16);
}
#endif

static void ghash_mul(uint8_t X[16], const ghash_key* gk){
#ifndef SM4_NO_PCLMUL
#if SM4_HAVE_PCLMUL_COMPILE
    if(gk->use_pclmul) { gf128mul_pclmul(X, gk->H); return; }
#else
    (void)gk; // suppress unused warning if compile-time support is absent
#endif
#endif
    gf128mul_portable(X, gk->H);
}
#endif
    gf128mul_portable(X, gk->H);
}

static void ghash_update(uint8_t S[16], const uint8_t *data, size_t len, const ghash_key* gk){
    uint8_t x[16];
    while(len>=16){
        for(int i=0;i<16;i++) S[i]^=data[i];
        memcpy(x,S,16); ghash_mul(x,gk); memcpy(S,x,16);
        data+=16; len-=16;
    }
    if(len){
        uint8_t last[16]={0}; memcpy(last,data,len);
        for(int i=0;i<16;i++) S[i]^=last[i];
        memcpy(x,S,16); ghash_mul(x,gk); memcpy(S,x,16);
    }
}

// ========================= SM4 in CTR and GCM =========================

typedef struct { uint32_t rk[32]; } sm4_key;

static void sm4_set_encrypt_key(sm4_key* k, const uint8_t key[16]){ sm4_key_schedule(key, k->rk); }

static void sm4_ctr_encrypt(const sm4_key* k, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len){
    uint8_t ctr[16]; memcpy(ctr, iv, 16);
    uint8_t keystream[16]; size_t off=0;
    while(len){
        #ifdef SM4_USE_TTABLE
        sm4_encrypt_block_ttab(ctr, keystream, k->rk);
        #else
        sm4_encrypt_block(ctr, keystream, k->rk);
        #endif
        size_t n = len<16?len:16;
        for(size_t i=0;i<n;i++) out[off+i] = in[off+i] ^ keystream[i];
        // increment 32-bit counter in last 4 bytes (GCM standard increments)
        for(int i=15;i>=12;i--){ if(++ctr[i]) break; }
        off+=n; len-=n;
    }
}

// GCM context
typedef struct {
    sm4_key ek;
    ghash_key hk;
    uint8_t H[16];
} sm4_gcm_ctx;

static void sm4_ecb_encrypt_block(const sm4_key* k, const uint8_t in[16], uint8_t out[16]){
#ifdef SM4_USE_TTABLE
    sm4_encrypt_block_ttab(in,out,k->rk);
#else
    sm4_encrypt_block(in,out,k->rk);
#endif
}

static void sm4_gcm_setkey(sm4_gcm_ctx* c, const uint8_t key[16]){
    sm4_set_encrypt_key(&c->ek, key);
    uint8_t zeros[16]={0};
    sm4_ecb_encrypt_block(&c->ek, zeros, c->H);
    ghash_set_H(&c->hk, c->H);
}

static void gcm_ghash_lengths(uint8_t S[16], uint64_t aad_bits, uint64_t ct_bits, const ghash_key* gk){
    uint8_t lenblk[16];
    for(int i=0;i<8;i++){ lenblk[i] = (aad_bits>>(56-8*i))&0xff; }
    for(int i=0;i<8;i++){ lenblk[8+i] = (ct_bits>>(56-8*i))&0xff; }
    for(int i=0;i<16;i++) S[i]^=lenblk[i];
    uint8_t x[16]; memcpy(x,S,16); ghash_mul(x,gk); memcpy(S,x,16);
}

// GCM: IV processing to create initial counter J0
static void gcm_prepare_J0(const ghash_key* gk, const uint8_t* iv, size_t ivlen, uint8_t J0[16]){
    if(ivlen==12){ memcpy(J0, iv, 12); J0[12]=0; J0[13]=0; J0[14]=0; J0[15]=1; return; }
    uint8_t S[16]={0}; ghash_update(S, iv, ivlen, gk);
    gcm_ghash_lengths(S, 0, (uint64_t)ivlen*8, gk);
    memcpy(J0, S, 16);
}

// API: encrypt (GCM)
static void sm4_gcm_encrypt(
    sm4_gcm_ctx* c,
    const uint8_t* iv, size_t ivlen,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t tag[16]
){
    uint8_t J0[16]; gcm_prepare_J0(&c->hk, iv, ivlen, J0);
    // GHASH over AAD and ciphertext (ciphertext computed on the fly)
    uint8_t S[16]={0};
    if(aad_len) ghash_update(S, aad, aad_len, &c->hk);

    // Counter = inc32(J0)
    uint8_t ctr[16]; memcpy(ctr, J0, 16);
    for(int i=15;i>=12;i--){ if(++ctr[i]) break; }
    // CTR encryption, streaming
    uint8_t keystream[16]; size_t off=0; size_t len=pt_len;
    while(len){
        sm4_ecb_encrypt_block(&c->ek, ctr, keystream);
        size_t n = len<16?len:16;
        for(size_t i=0;i<n;i++){ ct[off+i] = pt[off+i] ^ keystream[i]; }
        // GHASH the produced ciphertext block
        uint8_t block[16]={0}; memcpy(block, ct+off, n);
        for(int i=0;i<16;i++) S[i]^=block[i];
        uint8_t x[16]; memcpy(x,S,16); ghash_mul(x,&c->hk); memcpy(S,x,16);
        // inc32(ctr)
        for(int i=15;i>=12;i--){ if(++ctr[i]) break; }
        off+=n; len-=n;
    }
    gcm_ghash_lengths(S, (uint64_t)aad_len*8, (uint64_t)pt_len*8, &c->hk);

    // Tag = E(K, J0) ^ S
    uint8_t E_J0[16]; sm4_ecb_encrypt_block(&c->ek, J0, E_J0);
    for(int i=0;i<16;i++) tag[i] = E_J0[i] ^ S[i];
}

// API: decrypt (GCM). Returns 0 on success (tag ok), -1 on tag mismatch.
static int sm4_gcm_decrypt(
    sm4_gcm_ctx* c,
    const uint8_t* iv, size_t ivlen,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt
){
    uint8_t J0[16]; gcm_prepare_J0(&c->hk, iv, ivlen, J0);
    uint8_t S[16]={0};
    if(aad_len) ghash_update(S, aad, aad_len, &c->hk);

    uint8_t ctr[16]; memcpy(ctr, J0, 16);
    for(int i=15;i>=12;i--){ if(++ctr[i]) break; }

    uint8_t keystream[16]; size_t off=0; size_t len=ct_len;
    while(len){
        sm4_ecb_encrypt_block(&c->ek, ctr, keystream);
        size_t n = len<16?len:16;
        // GHASH over ciphertext
        uint8_t block[16]={0}; memcpy(block, ct+off, n);
        for(int i=0;i<16;i++) S[i]^=block[i];
        uint8_t x[16]; memcpy(x,S,16); ghash_mul(x,&c->hk); memcpy(S,x,16);
        // produce plaintext
        for(size_t i=0;i<n;i++) pt[off+i] = ct[off+i] ^ keystream[i];
        for(int i=15;i>=12;i--){ if(++ctr[i]) break; }
        off+=n; len-=n;
    }
    gcm_ghash_lengths(S, (uint64_t)aad_len*8, (uint64_t)ct_len*8, &c->hk);

    uint8_t E_J0[16], calc_tag[16]; sm4_ecb_encrypt_block(&c->ek, J0, E_J0);
    for(int i=0;i<16;i++) calc_tag[i] = E_J0[i] ^ S[i];

    // constant-time tag compare
    unsigned diff=0; for(int i=0;i<16;i++) diff |= (unsigned)(calc_tag[i]^tag[i]);
    return diff ? -1 : 0;
}

// ========================= Test & CLI =========================
static int hex2bin(const char* s, uint8_t* out, size_t outlen){
    size_t n=strlen(s); if(n!=outlen*2) return -1; for(size_t i=0;i<outlen;i++){ char c1=s[2*i], c2=s[2*i+1];
        int v1=(c1>='0'&&c1<='9')?c1-'0':(c1>='a'&&c1<='f')?c1-'a'+10:(c1>='A'&&c1<='F')?c1-'A'+10:-1;
        int v2=(c2>='0'&&c2<='9')?c2-'0':(c2>='a'&&c2<='f')?c2-'a'+10:(c2>='A'&&c2<='F')?c2-'A'+10:-1;
        if(v1<0||v2<0) return -1; out[i]=(uint8_t)((v1<<4)|v2);
    } return 0;
}

static void printhex(const char* name,const uint8_t* b,size_t n){
    printf("%s=",name);
    for(size_t i=0;i<n;i++) printf("%02x", b[i]);
    printf("\n");
}

static int selftest(void){
    // SM4 single-block test vector (from GM/T 0002-2012)
    uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    uint8_t pt[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    uint8_t expect_ct[16] = { 0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46 };

    sm4_key k; sm4_set_encrypt_key(&k, key);
#ifdef SM4_USE_TTABLE
    uint8_t ct_t[16]; sm4_encrypt_block_ttab(pt, ct_t, k.rk);
    if(memcmp(ct_t, expect_ct, 16)!=0){ fprintf(stderr, "T-table SM4 KAT failed\n"); return -1; }
#endif
    uint8_t ct[16]; sm4_encrypt_block(pt, ct, k.rk);
    if(memcmp(ct, expect_ct, 16)!=0){ fprintf(stderr, "Portable SM4 KAT failed\n"); return -1; }

    // GCM quick round-trip
    sm4_gcm_ctx ctx; sm4_gcm_setkey(&ctx, key);
    const uint8_t iv[12] = { 0x00,1,2,3,4,5,6,7,8,9,0x0a,0x0b };
    const uint8_t aad[20] = {0};
    const uint8_t msg[64] = "hello sm4-gcm — quick test................................";
    uint8_t enc[64], dec[64], tag[16];
    sm4_gcm_encrypt(&ctx, iv,sizeof(iv), aad,sizeof(aad), msg,sizeof(msg), enc, tag);
    if(sm4_gcm_decrypt(&ctx, iv,sizeof(iv), aad,sizeof(aad), enc,sizeof(enc), tag, dec)!=0){
        fprintf(stderr, "GCM decrypt tag check failed\n"); return -1;
    }
    if(memcmp(msg, dec, sizeof(msg))!=0){ fprintf(stderr, "GCM round-trip mismatch\n"); return -1; }

    return 0;
}

int main(int argc, char** argv){
    if(argc>1 && strcmp(argv[1], "--selftest")==0){
        int rc=selftest();
        if(rc==0) { printf("Selftest OK\n"); return 0; }
        return 1;
    }
    // Simple CLI demo:
    //   Encrypt one 16-byte block: ./sm4_gcm enc <hexkey16> <hexblock16>
    //   Decrypt one 16-byte block: ./sm4_gcm dec <hexkey16> <hexblock16>
    //   GCM encrypt: ./sm4_gcm genc <hexkey16> <hexiv> <hexaad> <hexpt>
    if(argc>=4 && (!strcmp(argv[1],"enc")||!strcmp(argv[1],"dec"))){
        uint8_t key[16], blk[16], out[16];
        if(hex2bin(argv[2], key, 16)||hex2bin(argv[3], blk, 16)){ fprintf(stderr, "bad hex\n"); return 1; }
        sm4_key k; sm4_set_encrypt_key(&k, key);
        if(!strcmp(argv[1],"enc")) sm4_ecb_encrypt_block(&k, blk, out);
        else sm4_decrypt_block(blk, out, k.rk);
        printhex("out", out, 16); return 0;
    }
    return 0;
}
