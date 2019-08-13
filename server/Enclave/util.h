#ifndef __ENCLAVE_UTIL_H
#define __ENCLAVE_UTIL_H

#include <inttypes.h>

#define HASH_MAX_16	32765
#define HASH_MIN_16	-32765

extern uint32_t mem_used;

typedef struct
{
	float value;
	uint32_t key;
} res_pair;

uint32_t my_sgx_rand();

int cmpfunc_int16(const void* a, const void* b);
int cmpfunc_int32(const void* a, const void* b);
int cmpfunc_float(const void* a, const void* b);
int cmpfunc_pair(const void* a, const void* b);

// Hash function: h(x) = (a * x + b) mod p, where p = 2 ^ 31 - 1
uint32_t cal_hash(uint64_t x, uint64_t a, uint64_t b);

// Matrix/Vector operations
float dot_prod(float* x, float *y, int n_);
void matrix_vector_mult(float **mat, float *vec, float *result, int rows, int cols);
void matrix_ortho_proj(float **omat, float *vec, float *result, int k, int m);

void orthonormal_test(float** V, size_t size, float* res);
void orthonormal_test_t(float** V, size_t size, float* res);

#endif
