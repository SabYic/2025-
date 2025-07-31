#ifndef SM4_H
#define SM4_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SM4_OK = 0,
    SM4_ERR_NULL_PARAM = -1,
    SM4_ERR_BAD_PADDING = -2,
    SM4_ERR_ALLOC_FAIL = -3,
    SM4_ERR_INVALID_LENGTH = -4
} sm4_status_t;

typedef enum {
    SM4_MODE_ECB = 0,
    SM4_MODE_CBC = 1
} sm4_mode_t;

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16

typedef struct {
    void *internal; 
    uint8_t iv[SM4_BLOCK_SIZE]; // CBC 模式用
    sm4_mode_t mode;
} sm4_handle_t;

typedef struct {
    uint32_t rk[32];  // 32 轮轮密钥
} sm4_context;

sm4_status_t sm4_init(sm4_handle_t *h, const uint8_t key[SM4_KEY_SIZE],
                      sm4_mode_t mode, const uint8_t iv[SM4_BLOCK_SIZE]);

        
sm4_status_t sm4_set_key(sm4_handle_t *h, const uint8_t key[SM4_KEY_SIZE]);

void sm4_free(sm4_handle_t *h);


sm4_status_t sm4_encrypt(const sm4_handle_t *h,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len);


sm4_status_t sm4_decrypt(const sm4_handle_t *h,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len);


sm4_status_t sm4_ecb_encrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE],
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len);
sm4_status_t sm4_ecb_decrypt_pkcs7(const uint8_t key[SM4_KEY_SIZE],
                                   const uint8_t *in, size_t in_len,
                                   uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // SM4_H
