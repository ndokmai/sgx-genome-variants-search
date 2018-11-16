#ifndef __ENCLAVE_CMS_H
#define __ENCLAVE_CMS_H

#include "inttypes.h"

#define HASH_MAX	32765
#define HASH_MIN	-32765

extern struct cms* m_cms;

typedef struct cms
{
	int16_t** sketch;
	uint64_t* seeds;			// For custom hash functions
	int64_t st_length;			// Stream Length
	uint32_t width;				// Number of Buckets
	uint32_t width_minus_one;	// For fast modulo of the hash into the bucket number
	uint32_t depth;				// Number of Pairwise Independent Hash Functions
	float delta;				// Error Probability
	float epsilon;				// Error Factor
} cms;


uint32_t cal_hash(uint64_t, uint64_t, uint64_t);
void cms_init(uint32_t, uint32_t);
void cms_free();
void cms_update_var(uint64_t, int16_t);
void cms_update_var_row(uint64_t, int16_t, size_t);
int16_t cms_query_median_odd(uint64_t item);
int16_t cms_query_median_even(uint64_t item);

#endif
