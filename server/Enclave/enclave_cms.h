#ifndef __ENCLAVE_CMS_H
#define __ENCLAVE_CMS_H

#include "inttypes.h"

extern struct cms* m_cms;

typedef struct cms
{
	int64_t st_length;			// Stream Length
	uint32_t width;				// Number of Buckets
	uint32_t width_minus_one;	// For fast modulo of the hash into the bucket number
	uint32_t depth;				// Number of Pairwise Independent Hash Functions
	float delta;				// Error Probability
	float epsilon;				// Error Factor
	int s_thres;			// For sketch querying when the depth is even
	int16_t** sketch;
	float** sketchf;
	
	uint64_t* seeds;			// For custom hash functions
} cms;

void cms_init(uint32_t, uint32_t);
void cms_init_f(uint32_t, uint32_t);
void cms_free();
void cms_setsth(int);
void cms_update_var(uint64_t, int16_t);
void cms_update_var_f(uint64_t, float);
void cms_update_var_row(uint64_t, int16_t, size_t);
void cms_update_var_row_f(uint64_t, float, size_t);
int16_t cms_query_median_odd(uint64_t item);
int16_t cms_query_median_even(uint64_t item);
float cms_query_median_odd_f(uint64_t);
float cms_query_median_even_f(uint64_t);

#endif
