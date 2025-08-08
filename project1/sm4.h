#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16

typedef enum {
    SM4_OK = 0,
    SM4_ERR_NULL_PARAM,
    SM4_ERR_ALLOC_FAIL,
    SM4_ERR_INVALID_LENGTH,
    SM4_ERR_BAD_PADDING
} sm4_status_t;

typedef enum {
    SM4_MODE_ECB = 0,
    SM4_MODE_CBC = 1
} sm4_mode_t;

typedef struct {
    uint32_t rk[32];  /* 32 轮子密钥 */
} sm4_context;

typedef struct {
    sm4_mode_t mode;
    uint8_t    iv[SM4_BLOCK_SIZE]; /* CBC 使用 */
    sm4_context *ctx;               /* 保存轮密钥 */
} sm4_handle_t;

static inline const char *sm4_status_to_string(sm4_status_t s) {
    switch (s) {
    case SM4_OK: return "OK";
    case SM4_ERR_NULL_PARAM: return "Null parameter";
    case SM4_ERR_ALLOC_FAIL: return "Allocation failed";
    case SM4_ERR_INVALID_LENGTH: return "Invalid length";
    case SM4_ERR_BAD_PADDING: return "Bad PKCS#7 padding";
    default: return "Unknown error";
    }
}


sm4_status_t sm4_set_key(sm4_handle_t *h, const uint8_t key[SM4_KEY_SIZE]);

sm4_status_t sm4_init(sm4_handle_t *h,
                      const uint8_t key[SM4_KEY_SIZE],
                      sm4_mode_t mode,
                      const uint8_t iv[SM4_BLOCK_SIZE]);

void sm4_free(sm4_handle_t *h);

void delete_sm4_handle(sm4_handle_t *h);

sm4_status_t sm4_encrypt(const sm4_handle_t *h,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t **out_len);

sm4_status_t sm4_decrypt(const sm4_handle_t *h,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len);

sm4_status_t sm4_ecb_encrypt_pkcs7(const sm4_handle_t *h,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len);

sm4_status_t sm4_ecb_decrypt_pkcs7(const sm4_handle_t *h,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len);


void unpad(uint8_t *buf, size_t *len);
sm4_status_t sm4_set_key_withTtable(sm4_handle_t *h, const uint8_t key[SM4_KEY_SIZE]);

sm4_status_t sm4_init_T_tables(sm4_handle_t *h,
                               const uint8_t key[SM4_KEY_SIZE],
                               sm4_mode_t mode,
                               const uint8_t iv[SM4_BLOCK_SIZE]);

sm4_status_t sm4_encrypt_with_Ttable(const sm4_handle_t *h,
                                     const uint8_t *in, size_t in_len,
                                     uint8_t **out, size_t *out_len);

sm4_status_t sm4_decrypt_with_Ttable(const sm4_handle_t *h,
                                     const uint8_t *in, size_t in_len,
                                     uint8_t **out, size_t *out_len);


#ifdef __cplusplus
}
#endif

#endif 
