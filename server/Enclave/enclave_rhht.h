#ifndef __ENCLAVE_RHHT_H
#define __ENCLAVE_RHHT_H

#include "inttypes.h"

#define LOAD_FACTOR_PERCENT	95

extern struct rhht_table* rhht_snp_table;

struct elem
{
	uint32_t key;
	uint16_t case_count;
	uint16_t control_count;
};

struct rhht_table
{
	struct elem* buffer;
	uint32_t num_elems;
	uint32_t capacity;
	uint32_t resize_threshold;
};


void allocate_table(uint32_t capacity);

void construct(uint32_t index, uint32_t key, uint16_t case_count, uint16_t control_count);

void insert(uint32_t key, uint8_t allele_type, uint8_t patient_status);

void grow();

int32_t lookup_index(uint32_t key);

int32_t find(uint32_t key);
#endif
