#ifndef __ENCLAVE_CMS_H
#define __ENCLAVE_CMS_H

#include "inttypes.h"

#define HASH_MAX	32765
#define HASH_MIN	-32765

typedef struct cms
{
	uint32_t width;				// Number of Buckets
	uint32_t width_minus_one;	// For fast modulo of the hash into the bucket number
	uint32_t depth;				// Number of Pairwise Independent Hash Functions
	int64_t st_length;			// Stream Length
	float delta;				// Error Probability
	float epsilon;				// Error Factor
	int16_t** sketch;
	
	//For custom hash functions
	uint64_t* seeds;
	//uint32_t shift;
} cms;


uint32_t cal_hash(uint64_t, uint64_t, uint64_t);
void cms_init(uint32_t, uint32_t);
void cms_free();
void cms_update_var(uint64_t, int16_t);

#endif
