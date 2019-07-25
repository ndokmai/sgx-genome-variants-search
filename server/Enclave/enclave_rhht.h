#ifndef __ENCLAVE_RHHT_H
#define __ENCLAVE_RHHT_H

#include "inttypes.h"

#define LOAD_FACTOR_PERCENT	95

extern struct rhht_table* rhht_snp_table;
extern struct rhht_table_pcc* rhht_snp_table_pcc;

struct elem
{
	uint32_t key;
	uint16_t case_count;
	uint16_t control_count;
};

// rank(PCC^2) = rank[(m * dotprod - s_x * s_y)^2 / (m * s_xx - s_x^2)]
// Require <= 16000 cases + controls
// Each elem_pcc occupies 4 * k + 14 bytes
struct elem_pcc
{
	uint32_t key;

	// Sum of squared (uncorrected) genotypes
	uint16_t ssqg;

	// Dot product between uncorrected genotypes and corrected phenotypes
	// Equal to dot product between corrected genotypes and corrected phenotypes
	float dotprod;

	// s_x = sg - sc
	// sc: sum of corrections to genotypes
	// sg: sum of uncorrected genotypes
	float sx;
	
	// Projection of genotypes to the k-dimensional subspace from PCA
	// s_xx = ssqg - <pc_projections, pc_projections>
	float* pc_projections;
};

struct rhht_table
{
	struct elem* buffer;
	uint32_t num_elems;
	uint32_t capacity;
	uint32_t resize_threshold;
};

struct rhht_table_pcc
{
	struct elem_pcc* buffer;
	uint8_t k; // For initializing elem_pcc;
	uint32_t num_elems;
	uint32_t capacity;
	uint32_t resize_threshold;
};

void allocate_table(uint32_t);

void deallocate_table();

void allocate_table_pcc(uint32_t, uint8_t);

void deallocate_table_pcc();

void construct(uint32_t, uint32_t, uint16_t, uint16_t);

void construct_pcc(uint32_t);

void insert(uint32_t, uint8_t, uint8_t);

void insert_pcc(uint32_t);

void grow();

void grow_pcc();

void set_index(uint32_t, uint32_t, float, float, float, float*);

int32_t lookup_index(uint32_t);

int32_t find(uint32_t);

int32_t find_pcc(uint32_t);
#endif
