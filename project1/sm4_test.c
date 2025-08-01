#include "sm4.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n, b, i)                             \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )        \
        | ( (uint32_t) (b)[(i) + 1] << 16 )        \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)                             \
{                                                       \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8_t) ( (n)       );       \
}
#endif

#define SHL(x, n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x, n) (SHL((x), n) | ((x) >> (32 - n)))

#define SWAP(a, b) { uint32_t t = a; a = b; b = t; t = 0; }

static const uint8_t SboxTable[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
    0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
    0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
    0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
    0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
    0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
    0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
    0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
    0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static uint32_t sm4_sbox(uint32_t A) {
    uint32_t res = 0;
    res |= ((uint32_t)SboxTable[(A >> 24) & 0xFF]) << 24;
    res |= ((uint32_t)SboxTable[(A >> 16) & 0xFF]) << 16;
    res |= ((uint32_t)SboxTable[(A >> 8) & 0xFF]) << 8;
    res |= ((uint32_t)SboxTable[A & 0xFF]);
    return res;
}

const char *sm4_status_to_string(sm4_status_t s) {
    switch (s) {
    case SM4_OK: return "OK";
    case SM4_ERR_NULL_PARAM: return "Null parameter";
    case SM4_ERR_ALLOC_FAIL: return "Allocation failed";
    case SM4_ERR_INVALID_LENGTH: return "Invalid length";
    case SM4_ERR_BAD_PADDING: return "Bad PKCS#7 padding";
    default: return "Unknown error";
    }
}


static uint32_t sm4_tau(uint32_t a) {
    uint8_t a0 = (a >> 24) & 0xFF;
    uint8_t a1 = (a >> 16) & 0xFF;
    uint8_t a2 = (a >> 8) & 0xFF;
    uint8_t a3 = a & 0xFF;

    uint8_t b0 = SboxTable[a0];
    uint8_t b1 = SboxTable[a1];
    uint8_t b2 = SboxTable[a2];
    uint8_t b3 = SboxTable[a3];

    return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
           ((uint32_t)b2 << 8)  | ((uint32_t)b3);
}

static uint32_t sm4_L(uint32_t b) {
    return b ^ ROTL(b, 2) ^ ROTL(b, 10) ^ ROTL(b, 18) ^ ROTL(b, 24);
}

static uint32_t sm4_L_prime(uint32_t b) {
    return b ^ ROTL(b, 13) ^ ROTL(b, 23);
}

static uint32_t sm4_T(uint32_t x) {
    return sm4_L(sm4_tau(x));
}

static size_t pkcs7_pad_len(size_t in_len) {
    size_t pad = SM4_BLOCK_SIZE - (in_len % SM4_BLOCK_SIZE);
    if (pad == 0) pad = SM4_BLOCK_SIZE;
    return pad;
}

sm4_status_t sm4_set_key(sm4_handle_t *h, const uint8_t key[SM4_KEY_SIZE]) {
    if (h == NULL || key == NULL)
        return SM4_ERR_NULL_PARAM;

    uint32_t MK[4];
    uint32_t k[36];
    uint32_t rk[32];

    GET_ULONG_BE(MK[0], key, 0);
    GET_ULONG_BE(MK[1], key, 4);
    GET_ULONG_BE(MK[2], key, 8);
    GET_ULONG_BE(MK[3], key, 12);

    k[0] = MK[0] ^ FK[0];
    k[1] = MK[1] ^ FK[1];
    k[2] = MK[2] ^ FK[2];
    k[3] = MK[3] ^ FK[3];

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = k[i+1] ^ k[i+2] ^ k[i+3] ^ FK[i];
        uint32_t t = sm4_tau(tmp);
        rk[i] = k[i] ^ sm4_L_prime(t);
        k[i + 4] = rk[i];
    }

    memcpy(h->ctx->rk, rk, sizeof(rk));
    return SM4_OK;
}

static void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t X[36];
    GET_ULONG_BE(X[0], in, 0);
    GET_ULONG_BE(X[1], in, 4);
    GET_ULONG_BE(X[2], in, 8);
    GET_ULONG_BE(X[3], in, 12);

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i];
        X[i+4] = X[i] ^ sm4_T(tmp);
    }

    PUT_ULONG_BE(X[35], out, 0);
    PUT_ULONG_BE(X[34], out, 4);
    PUT_ULONG_BE(X[33], out, 8);
    PUT_ULONG_BE(X[32], out, 12);
}

sm4_status_t sm4_encrypt(const sm4_handle_t *h,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len) {
    if (!h || !in )
        return SM4_ERR_NULL_PARAM;

    size_t pad = pkcs7_pad_len(in_len);
    size_t total = in_len + pad;

    uint8_t *buf = (uint8_t *)malloc(total);
    out_len=malloc(sizeof(size_t));
    if (!buf)
        return SM4_ERR_ALLOC_FAIL;

    memcpy(buf, in, in_len);
    memset(buf + in_len, (uint8_t)pad, pad);

    uint8_t prev[SM4_BLOCK_SIZE];
    memcpy(prev, h->iv, SM4_BLOCK_SIZE);

    uint8_t tmp_in[SM4_BLOCK_SIZE];
    uint8_t tmp_out[SM4_BLOCK_SIZE];

    for (size_t off = 0; off < total; off += SM4_BLOCK_SIZE) {
        for (int i = 0; i < SM4_BLOCK_SIZE; i++)
            tmp_in[i] = buf[off + i] ^ prev[i];

        sm4_encrypt_block(h->ctx->rk, tmp_in, tmp_out);

        memcpy(buf + off, tmp_out, SM4_BLOCK_SIZE);
        memcpy(prev, tmp_out, SM4_BLOCK_SIZE);
    }

    *out = buf;
    *out_len = total;
    return SM4_OK;
}

static void sm4_decrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t X[36];
    GET_ULONG_BE(X[0], in, 0);
    GET_ULONG_BE(X[1], in, 4);
    GET_ULONG_BE(X[2], in, 8);
    GET_ULONG_BE(X[3], in, 12);

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[31 - i];
        X[i+4] = X[i] ^ sm4_T(tmp);
    }

    PUT_ULONG_BE(X[35], out, 0);
    PUT_ULONG_BE(X[34], out, 4);
    PUT_ULONG_BE(X[33], out, 8);
    PUT_ULONG_BE(X[32], out, 12);
}

sm4_status_t sm4_decrypt(const sm4_handle_t *h,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len) {
    if (!h || !in )
        return SM4_ERR_NULL_PARAM;
    if (in_len == 0 || in_len % SM4_BLOCK_SIZE != 0)
        return SM4_ERR_INVALID_LENGTH;

    uint8_t *buf = (uint8_t *)malloc(in_len);
    if (!buf)
        return SM4_ERR_ALLOC_FAIL;

    uint8_t prev[SM4_BLOCK_SIZE];
    memcpy(prev, h->iv, SM4_BLOCK_SIZE);

    uint8_t tmp_in[SM4_BLOCK_SIZE];
    uint8_t tmp_out[SM4_BLOCK_SIZE];

    for (size_t off = 0; off < in_len; off += SM4_BLOCK_SIZE) {
        memcpy(tmp_in, in + off, SM4_BLOCK_SIZE);

        sm4_decrypt_block(h->ctx->rk, tmp_in, tmp_out);

        for (int i = 0; i < SM4_BLOCK_SIZE; i++)
            buf[off + i] = tmp_out[i] ^ prev[i];

        memcpy(prev, tmp_in, SM4_BLOCK_SIZE);
    }
    uint8_t pad = buf[in_len - 1];
    if (pad == 0 || pad > SM4_BLOCK_SIZE) {
        free(buf);
        return SM4_ERR_BAD_PADDING;
    }
    printf("pad = %d\n", pad);
   /* for (size_t i = in_len - pad; i < in_len; i++) {
        if (buf[i] != pad) {
            free(buf);
            return SM4_ERR_BAD_PADDING;
        }
    }*/

    size_t plain_len = in_len ;
    uint8_t *trimmed = (uint8_t *)malloc(plain_len);
    if (!trimmed) {
        free(buf);
        return SM4_ERR_ALLOC_FAIL;
    }
    memcpy(trimmed, buf, plain_len);
    free(buf);
    out_len = malloc(sizeof(size_t));
    *out = trimmed;
    *out_len = plain_len;
    return SM4_OK;
}

sm4_status_t sm4_ecb_encrypt_pkcs7(const sm4_handle_t *h,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len) {
    if (!h || !in || !out || !out_len)
        return SM4_ERR_NULL_PARAM;

    size_t pad = pkcs7_pad_len(in_len);
    size_t total = in_len + pad;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf)
        return SM4_ERR_ALLOC_FAIL;

    memcpy(buf, in, in_len);
    memset(buf + in_len, (uint8_t)pad, pad);

    for (size_t off = 0; off < total; off += SM4_BLOCK_SIZE) {
        sm4_encrypt_block(h->ctx->rk, buf + off, buf + off);
    }

    *out = buf;
    *out_len = total;
    return SM4_OK;
}

sm4_status_t sm4_ecb_decrypt_pkcs7(const sm4_handle_t *h,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len) {
    if (!h || !in || !out || !out_len)
        return SM4_ERR_NULL_PARAM;

    uint8_t *buf = (uint8_t *)malloc(in_len);
    if (!buf)
        return SM4_ERR_ALLOC_FAIL;

    for (size_t off = 0; off < in_len; off += SM4_BLOCK_SIZE) {
        sm4_decrypt_block(h->ctx->rk, in + off, buf + off);
    }

    uint8_t pad = buf[in_len - 1];
    if (pad == 0 || pad > SM4_BLOCK_SIZE) {
        free(buf);
        return SM4_ERR_BAD_PADDING;
    }
    for (size_t i = in_len - pad; i < in_len; i++) {
        if (buf[i] != pad) {
            free(buf);
            return SM4_ERR_BAD_PADDING;
        }
    }

    size_t plain_len = in_len - pad;
    uint8_t *trimmed = (uint8_t *)malloc(plain_len);
    if (!trimmed) {
        free(buf);
        return SM4_ERR_ALLOC_FAIL;
    }
    memcpy(trimmed, buf, plain_len);
    free(buf);

    *out = trimmed;
    *out_len = plain_len;
    return SM4_OK;
}

sm4_status_t sm4_init(sm4_handle_t *h, const uint8_t key[SM4_KEY_SIZE],
                      sm4_mode_t mode, const uint8_t iv[SM4_BLOCK_SIZE]) {
    if (!h || !key || (mode == SM4_MODE_CBC && !iv)) {
        return SM4_ERR_NULL_PARAM;
    }

    h->mode = mode;

    if (mode == SM4_MODE_CBC) {
        memcpy(h->iv, iv, SM4_BLOCK_SIZE);
    } else {
        memset(h->iv, 0, SM4_BLOCK_SIZE);
    }

    h->ctx = malloc(sizeof(sm4_context));
    if (!h->ctx) {
        return SM4_ERR_ALLOC_FAIL;
    }

    sm4_context *ctx = (sm4_context *)h->ctx;

    sm4_set_key(h, key);

    return SM4_OK;
}

void sm4_free(sm4_handle_t *h) {
    if (h) {
        free(h->ctx);
        h->ctx = NULL;
    }
}

void delete_sm4_handle(sm4_handle_t *h) {
    if (h) {
        free(h->ctx);
        free(h);
    }
}

void unpad(uint8_t *buf, size_t *len) {
    if (buf == NULL || len == NULL || *len == 0) return;

    uint8_t pad = buf[*len - 1];
    if (pad > SM4_BLOCK_SIZE || pad == 0) return;

    for (size_t i = *len - pad; i < *len; i++) {
        if (buf[i] != pad) return;
    }

    *len -= pad;
}
int main(void) {
    printf("SM4 算法测试程序\n");
    printf("1. 加密解密正确性测试...\n");
    
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plaintext[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t *decryptedtext = NULL;
    uint8_t *ciphertext = NULL;
    printf("开始加密解密测试...\n");
    sm4_handle_t *h;
    h = (sm4_handle_t *)malloc(sizeof(sm4_handle_t));
    h->ctx = (sm4_context *)malloc(sizeof(sm4_context));
    h->mode = SM4_MODE_CBC; // 使用 CBC 模式
    uint8_t iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                           0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    printf("初始化 SM4 句柄...\n");
    sm4_status_t st = sm4_init(h, key, SM4_MODE_CBC, iv);
    if (st != SM4_OK) {
        fprintf(stderr, "sm4_init failed: %s (code=%d)\n",
                sm4_status_to_string(st), (int)st);
        return 1;
    }
    printf("SM4 句柄初始化成功!\n");
    printf("开始加密...\n");
    st = sm4_encrypt(h, plaintext, 16, &ciphertext, NULL);
    if (st != SM4_OK) {
        fprintf(stderr, "sm4_encrypted failed: %s (code=%d)\n",
                sm4_status_to_string(st), (int)st);
        return 1;
    }
    printf("加密成功!\n");

    st =  sm4_decrypt(h, ciphertext, 16, &decryptedtext, NULL);
    if (st != SM4_OK) {
        fprintf(stderr, "sm4_decrypted failed: %s (code=%d)\n",
                sm4_status_to_string(st), (int)st);
        return 1;
    }
    
    int i;
    printf("加密结果：\n");
    for(i=0;i<16;i++){
        printf("%02x ", ciphertext[i]);
    }
    for(int i=0;i<16;i++){
        printf("%02x", decryptedtext[i]);
    }
    for(i=0;i<16;i++){
        if(plaintext[i] != decryptedtext[i]){
            printf("加密解密失败!\n");
            return 1;
        }
    }
    printf("加密解密测试通过!\n");
    
    sm4_free(h);
    printf("内存释放成功!\n");
    
    printf("所有测试案例通过!\n");
    return 0;
}
