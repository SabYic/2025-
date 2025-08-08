
/* --- FILE: sm3_benchmark.c --- */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sm3.h"
#ifdef __x86_64__
#include <x86intrin.h>
#endif
#ifdef __APPLE__
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

static double now_sec(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW,&ts); return ts.tv_sec + ts.tv_nsec*1e-9; }
static uint64_t rdtsc(void){
#ifdef __x86_64__
    unsigned int aux; return __rdtscp(&aux);
#else
    return 0;
#endif
}
static void fill_random(uint8_t *p, size_t n){ for(size_t i=0;i<n;++i) p[i]=(uint8_t)rand(); }

static double bench_base(size_t msg_len, size_t iters){
    uint8_t *buf=(uint8_t*)malloc(msg_len); uint8_t out[32]; fill_random(buf,msg_len);
    double t0=now_sec(); uint64_t c0=rdtsc();
    for(size_t i=0;i<iters;++i) sm3_base(buf,msg_len,out);
    uint64_t c1=rdtsc(); double t1=now_sec(); free(buf);
    double secs=t1-t0; double mb=(double)msg_len*iters/(1024.0*1024.0);
    if (c1>c0 && msg_len*iters) printf("  base cycles/byte: %.2f", (double)(c1-c0)/(msg_len*iters));
    return mb/(secs>0?secs:1e-9);
}

static double bench_par4(size_t msg_len, size_t iters){
    uint8_t *b0=(uint8_t*)malloc(msg_len),*b1=(uint8_t*)malloc(msg_len),*b2=(uint8_t*)malloc(msg_len),*b3=(uint8_t*)malloc(msg_len);
    fill_random(b0,msg_len); fill_random(b1,msg_len); fill_random(b2,msg_len); fill_random(b3,msg_len);
    uint8_t o0[32],o1[32],o2[32],o3[32];
    double t0=now_sec(); uint64_t c0=rdtsc();
    for(size_t i=0;i<iters;++i) sm3_parrele(b0,msg_len,b1,msg_len,b2,msg_len,b3,msg_len,o0,o1,o2,o3);
    uint64_t c1=rdtsc(); double t1=now_sec();
    free(b0); free(b1); free(b2); free(b3);
    double secs=t1-t0; double mb=(double)msg_len*iters*4/(1024.0*1024.0);
    if (c1>c0 && msg_len*iters) printf("  par4 cycles/byte: %.2f", (double)(c1-c0)/(msg_len*iters*4));
    return mb/(secs>0?secs:1e-9);
}

int main(void){
    const size_t sizes[] = {64, 1024, 8192, 1<<20};
    const size_t ns = sizeof(sizes)/sizeof(sizes[0]);
    const size_t iters_base = 2000;
#ifdef __AVX2__
    printf("SM3 benchmark (base vs par4) — AVX2 build");
#else
    printf("SM3 benchmark (base vs par4) — non-AVX2 build");
#endif
    for(size_t i=0;i<ns;++i){
        size_t n=sizes[i]; size_t it = iters_base * (sizes[0]/n ? sizes[0]/n : 1);
        printf("len=%zu bytes", n);
        double b=bench_base(n,it);
        printf("  base:  %.1f MB/s", b);
        double p=bench_par4(n,it);
        printf("  par4:  %.1f MB/s", p);
        if (b>0) printf("  (speedup %.2fx)", p/b);
        printf("");
    }
    return 0;
}
