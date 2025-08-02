#define _POSIX_C_SOURCE 199309L
#include "sm4.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include <time.h>


static inline long diff_us(const struct timespec *start, const struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000000L + (end->tv_nsec - start->tv_nsec) / 1000L;
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
    uint64_t *outlen=NULL;

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    st = sm4_encrypt(h, plaintext, 16, &ciphertext, &outlen);
    if (st != SM4_OK) {
        fprintf(stderr, "sm4_encrypted failed: %s (code=%d)\n",
                sm4_status_to_string(st), (int)st);
        return 1;
    }
    printf("加密成功! 用时 %ld 微秒\n", diff_us(&t_start, &t_end));
    
    st =  sm4_decrypt(h, ciphertext, *outlen, &decryptedtext, NULL);

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
