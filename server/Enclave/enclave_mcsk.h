#ifndef __ENCLAVE_MCSK_H
#define __ENCLAVE_MCSK_H

#include <inttypes.h>

#define HASH_MAX_16	32765
#define HASH_MIN_16	-32765
#define HASH_MAX_32	2147483640
#define HASH_MIN_32	-2147483640

extern struct mcsk* m_mcsk;

// Matrix Count Sketch: For Random Projection of Rows  
typedef struct mcsk 
{
	uint32_t m;				// Row Vector Length
	uint32_t k;				// Number of Principal Components
	uint32_t depth;				// Number of Buckets
	uint32_t depth_minus_one;	// For fast modulo of the hash into bucket number
	float epsilon;				// Error Factor from PCA
	float** msketchf;

	// For custom hash functions.
	uint64_t* seeds;
} mcsk;

void mcsk_init(uint32_t, uint32_t, float);
void mcsk_quick_init(uint32_t, uint32_t);
void mcsk_setk(uint32_t);
void mcsk_free();
void mcsk_update_var(uint64_t, uint32_t, float);
void mcsk_mean_centering();
float** getmsk();

#endif
