#ifndef __ENCLAVE_UTIL_H
#define __ENCLAVE_UTIL_H

#include <inttypes.h>

uint32_t my_sgx_rand();

int cmpfunc_int16(const void* a, const void* b);
int cmpfunc_int32(const void* a, const void* b);
int cmpfunc_float(const void* a, const void* b);

// Hash function: h(x) = (a * x + b) mod p, where p = 2 ^ 31 - 1
uint32_t cal_hash(uint64_t x, uint64_t a, uint64_t b);

#endif
