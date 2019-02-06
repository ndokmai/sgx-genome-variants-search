#include <inttypes.h>
#include <sgx_trts.h>
#include "util.h"

uint32_t my_sgx_rand()
{
	uint32_t rand_num;
	sgx_read_rand((unsigned char*) &rand_num, sizeof(uint32_t));
	return rand_num & 0x7FFFFFFF;
}

int cmpfunc_int16(const void* a, const void* b)
{
	return (*(int16_t*) a - *(int16_t*) b);
}

int cmpfunc_int32(const void* a, const void* b)
{
	return (*(int32_t*) a - *(int32_t*) b);
}

int cmpfunc_float(const void* a, const void* b) 
{
	float fa = *(const float*) a;
	float fb = *(const float*) b;
	return ((fa > fb) - (fa < fb));
}

// Hash function: h(x) = (a * x + b) mod p, where p = 2 ^ 31 - 1
uint32_t cal_hash(uint64_t x, uint64_t a, uint64_t b)
{
	uint64_t result = a * x + b;
	result = (result & 0x7FFFFFFF) + (result >> 31);

	if(result >= 0x7FFFFFFF)
	{
		return (uint32_t) (result - 0x7FFFFFFF);
	}

	return (uint32_t) result;
}
