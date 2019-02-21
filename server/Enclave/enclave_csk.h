#ifndef __ENCLAVE_CSK_H
#define __ENCLAVE_CSK_H

#include "inttypes.h"

#define HASH_MAX_16	32765
#define HASH_MIN_16	-32765

extern struct csk* m_csk;

typedef struct csk
{
	uint32_t width;				// Number of Buckets
	uint32_t width_minus_one;	// For fast modulo of the hash into bucket number
	uint32_t depth;				// Number of Pairwise Independent Hash Functions
	float delta;				// Error Probability
	float epsilon;				// Error Factor
	int16_t** sketch;
	float** sketchf;

	// For custom hash functions
	uint64_t* seeds;
} csk;

void csk_init(uint32_t, uint32_t);
void csk_init_f(uint32_t, uint32_t);
void csk_free();
void csk_update_var(uint64_t, int16_t);
void csk_update_var_f(uint64_t, float);
int16_t csk_query_median_odd(uint64_t item);
int16_t csk_query_median_even(uint64_t item);
float csk_query_median_odd_f(uint64_t item);
float csk_query_median_even_f(uint64_t item);

#endif
