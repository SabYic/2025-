#define _POSIX_C_SOURCE 199309L
#include "sm4.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static inline long diff_us(const struct timespec *start, const struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000000L + (end->tv_nsec - start->tv_nsec) / 1000L;
}

static void fill_pattern(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(i * 131 + 7);
}

static int check_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

static void print_hex(const char *title, const uint8_t *p, size_t n) {
    printf("%s", title);
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

/* 运行一次 CBC+PKCS#7 的加解密正确性（两种实现各自测 + 对比明文） */
static int test_correctness(void) {
    uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    uint8_t plain[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    auto int show_mismatch(const char *tag, const uint8_t *pt, size_t ptlen,
                           const uint8_t *ref, size_t reflen) {
        if (ptlen != reflen) {
            fprintf(stderr, "%s: length mismatch: got %zu, expect %zu\n",
                    tag, ptlen, reflen);
            return 0;
        }
        for (size_t i = 0; i < ptlen; ++i) {
            if (pt[i] != ref[i]) {
                fprintf(stderr, "%s: first diff at byte %zu: got %02x, expect %02x\n",
                        tag, i, pt[i], ref[i]);
                return 0;
            }
        }
        return 1;
    }

    /* ---------------- base ---------------- */
    sm4_handle_t hb = (sm4_handle_t){0};
    if (sm4_init(&hb, key, SM4_MODE_CBC, iv) != SM4_OK) {
        fprintf(stderr, "sm4_init(base) failed\n");
        return 0;
    }
    uint8_t *ct_b = NULL, *pt_b = NULL; size_t *outlen_b_ptr = NULL; size_t outlen_b = 0;
    if (sm4_encrypt(&hb, plain, sizeof(plain), &ct_b, &outlen_b_ptr) != SM4_OK) {
        fprintf(stderr, "sm4_encrypt(base) failed\n");
        sm4_free(&hb);
        return 0;
    }
    outlen_b = *outlen_b_ptr;
    if (sm4_decrypt(&hb, ct_b, outlen_b, &pt_b, &outlen_b) != SM4_OK) {
        fprintf(stderr, "sm4_decrypt(base) failed\n");
        free(ct_b); free(outlen_b_ptr); sm4_free(&hb);
        return 0;
    }
    int ok_b = show_mismatch("base", pt_b, outlen_b, plain, sizeof(plain));
    printf("base: %s (out_len=%zu)\n", ok_b ? "OK" : "BAD", outlen_b);

    free(ct_b); free(pt_b); free(outlen_b_ptr); sm4_free(&hb);

    /* --------------- T-table --------------- */
    sm4_handle_t ht = (sm4_handle_t){0};
    if (sm4_init_T_tables(&ht, key, SM4_MODE_CBC, iv) != SM4_OK) {
        fprintf(stderr, "sm4_init_T_tables failed\n");
        return 0;
    }
    uint8_t *ct_t = NULL, *pt_t = NULL; size_t outlen_t = 0;
    if (sm4_encrypt_with_Ttable(&ht, plain, sizeof(plain), &ct_t, &outlen_t) != SM4_OK) {
        fprintf(stderr, "sm4_encrypt_with_Ttable failed\n");
        sm4_free(&ht);
        return 0;
    }
    if (sm4_decrypt_with_Ttable(&ht, ct_t, outlen_t, &pt_t, &outlen_t) != SM4_OK) {
        fprintf(stderr, "sm4_decrypt_with_Ttable failed\n");
        free(ct_t); sm4_free(&ht);
        return 0;
    }
    int ok_t = show_mismatch("ttable", pt_t, outlen_t, plain, sizeof(plain));
    printf("ttable: %s (out_len=%zu)\n", ok_t ? "OK" : "BAD", outlen_t);

    free(ct_t); free(pt_t); sm4_free(&ht);

    if (!ok_b || !ok_t) {
        fprintf(stderr, "Correctness FAILED: base=%d, ttable=%d\n", ok_b, ok_t);
        return 0;
    }
    printf("Correctness PASSED (both match plaintext)\n");
    return 1;
}


/* 计算 MB/s */
static double throughput_MBps(size_t bytes, long usec) {
    if (usec <= 0) return 0.0;
    double mb = (double)bytes / (1024.0 * 1024.0);
    double sec = (double)usec / 1e6;
    return mb / sec;
}

/* 基准：运行 N 次取最小用时，减少抖动 */
static long time_encrypt_base(sm4_handle_t *h, const uint8_t *in, size_t len,
                              int repeat, uint8_t **out_buf, size_t *out_len) {
    struct timespec s, e;
    long best = -1;
    for (int r = 0; r < repeat; ++r) {
        uint8_t *out = NULL; size_t *olen_ptr = NULL; size_t olen = 0;
        clock_gettime(CLOCK_MONOTONIC, &s);
        sm4_status_t st = sm4_encrypt(h, in, len, &out, &olen_ptr);
        clock_gettime(CLOCK_MONOTONIC, &e);
        if (st != SM4_OK) return -1;
        long us = diff_us(&s, &e);
        if (best < 0 || us < best) { best = us; if (out_buf) *out_buf = out; else free(out); if (out_len) *out_len = *olen_ptr; }
        else { free(out); }
        free(olen_ptr);
    }
    return best;
}

static long time_decrypt_base(sm4_handle_t *h, const uint8_t *in, size_t len,
                              int repeat, uint8_t **out_buf, size_t *out_len) {
    struct timespec s, e;
    long best = -1;
    for (int r = 0; r < repeat; ++r) {
        uint8_t *out = NULL; size_t olen = 0;
        clock_gettime(CLOCK_MONOTONIC, &s);
        sm4_status_t st = sm4_decrypt(h, in, len, &out, &olen);
        clock_gettime(CLOCK_MONOTONIC, &e);
        if (st != SM4_OK) return -1;
        long us = diff_us(&s, &e);
        if (best < 0 || us < best) { best = us; if (out_buf) *out_buf = out; else free(out); if (out_len) *out_len = olen; }
        else { free(out); }
    }
    return best;
}

static long time_encrypt_ttbl(sm4_handle_t *h, const uint8_t *in, size_t len,
                              int repeat, uint8_t **out_buf, size_t *out_len) {
    struct timespec s, e;
    long best = -1;
    for (int r = 0; r < repeat; ++r) {
        uint8_t *out = NULL; size_t olen = 0;
        clock_gettime(CLOCK_MONOTONIC, &s);
        sm4_status_t st = sm4_encrypt_with_Ttable(h, in, len, &out, &olen);
        clock_gettime(CLOCK_MONOTONIC, &e);
        if (st != SM4_OK) return -1;
        long us = diff_us(&s, &e);
        if (best < 0 || us < best) { best = us; if (out_buf) *out_buf = out; else free(out); if (out_len) *out_len = olen; }
        else { free(out); }
    }
    return best;
}

static long time_decrypt_ttbl(sm4_handle_t *h, const uint8_t *in, size_t len,
                              int repeat, uint8_t **out_buf, size_t *out_len) {
    struct timespec s, e;
    long best = -1;
    for (int r = 0; r < repeat; ++r) {
        uint8_t *out = NULL; size_t olen = 0;
        clock_gettime(CLOCK_MONOTONIC, &s);
        sm4_status_t st = sm4_decrypt_with_Ttable(h, in, len, &out, &olen);
        clock_gettime(CLOCK_MONOTONIC, &e);
        if (st != SM4_OK) return -1;
        long us = diff_us(&s, &e);
        if (best < 0 || us < best) { best = us; if (out_buf) *out_buf = out; else free(out); if (out_len) *out_len = olen; }
        else { free(out); }
    }
    return best;
}

int main(void) {
    printf("SM4 Benchmark (CBC + PKCS#7)\n");

    if (!test_correctness()) {
        fprintf(stderr, "Correctness test FAILED.\n");
        return 1;
    }
    printf("Correctness test PASSED.\n\n");

    /* 测试参数 */
    const size_t sizes[] = {16, 64, 1024, 8192, 1<<20}; /* 16B, 64B, 1KB, 8KB, 1MB */
    const int nsizes = (int)(sizeof(sizes)/sizeof(sizes[0]));
    const int repeat = 5; /* 每个尺寸跑 5 次取最小值 */

    uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    uint8_t iv[16] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };

    for (int si = 0; si < nsizes; ++si) {
        size_t n = sizes[si];
        uint8_t *in = (uint8_t*)malloc(n);
        fill_pattern(in, n);

        /* base 句柄 */
        sm4_handle_t hb = {0};
        sm4_init(&hb, key, SM4_MODE_CBC, iv);

        /* ttable 句柄 */
        sm4_handle_t ht = {0};
        sm4_init_T_tables(&ht, key, SM4_MODE_CBC, iv);

        /* base 加密 */
        uint8_t *ct_b = NULL; size_t ct_b_len = 0;
        long enc_us_b = time_encrypt_base(&hb, in, n, repeat, &ct_b, &ct_b_len);
        double enc_MBps_b = throughput_MBps(ct_b_len, enc_us_b);

        /* ttable 加密 */
        uint8_t *ct_t = NULL; size_t ct_t_len = 0;
        long enc_us_t = time_encrypt_ttbl(&ht, in, n, repeat, &ct_t, &ct_t_len);
        double enc_MBps_t = throughput_MBps(ct_t_len, enc_us_t);

        /* base 解密 */
        uint8_t *pt_b = NULL; size_t pt_b_len = 0;
        long dec_us_b = time_decrypt_base(&hb, ct_b, ct_b_len, repeat, &pt_b, &pt_b_len);
        double dec_MBps_b = throughput_MBps(pt_b_len, dec_us_b);

        /* ttable 解密 */
        uint8_t *pt_t = NULL; size_t pt_t_len = 0;
        long dec_us_t = time_decrypt_ttbl(&ht, ct_t, ct_t_len, repeat, &pt_t, &pt_t_len);
        double dec_MBps_t = throughput_MBps(pt_t_len, dec_us_t);

        /* 校验还原长度与内容（去掉 PKCS#7 后应回到 n 字节） */
        int ok_b = (pt_b_len == n) && check_equal(in, pt_b, n);
        int ok_t = (pt_t_len == n) && check_equal(in, pt_t, n);

        printf("len=%-8zu  | base enc: %7.2f MB/s  dec: %7.2f MB/s  | "
               "ttbl enc: %7.2f MB/s  dec: %7.2f MB/s  | ok(b/t)=%d/%d\n",
               n, enc_MBps_b, dec_MBps_b, enc_MBps_t, dec_MBps_t, ok_b, ok_t);

        /* 释放 */
        free(in);
        free(ct_b); free(pt_b);
        free(ct_t); free(pt_t);
        sm4_free(&hb);
        sm4_free(&ht);
    }

    return 0;
}
