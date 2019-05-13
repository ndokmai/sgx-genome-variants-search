#ifndef __RHHT_H
#define __RHHT_H

#include <inttypes.h>

#define LOAD_FACTOR_PERCENT	95

extern struct rhht_table* rhht_snp_table;

struct elem
{
	uint32_t key;
	uint32_t val;
};

struct rhht_table
{
	struct elem* buffer;
	uint32_t num_elems;
	uint32_t capacity;
	uint32_t resize_threshold;
};


void allocate_table(uint32_t);

void construct(uint32_t, uint32_t, uint32_t);

void insert(uint32_t, uint32_t);

void grow();

int32_t lookup_index(uint32_t);

int32_t find(uint32_t);

#endif
