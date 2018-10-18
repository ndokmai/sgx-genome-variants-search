#ifndef __ENCLAVE_RHHT_H
#define __ENCLAVE_RHHT_H

#include "inttypes.h"

#define RHHT_INIT_CAPACITY	(1 << 23)
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

void allocate_table();

void reallocate_table(uint32_t new_capacity);

void construct(uint32_t index, uint32_t key, uint16_t case_count, uint16_t control_count);

uint32_t probe_distance(uint32_t key, uint32_t slot_index);

inline void insert_helper(uint32_t hash, uint32_t key, uint16_t case_count, uint16_t control_count)
{
	uint32_t pos = hash;
	uint32_t dist = 0;
	for(;;)
	{
		if((rhht_snp_table->buffer[pos].key & ((rhht_snp_table->capacity) - 1)) == 0)
		{
			construct(pos, key, case_count, control_count);
			return;
		}

		uint32_t existing_elem_probe_dist = probe_distance(rhht_snp_table->buffer[pos].key, pos);
		if(existing_elem_probe_dist < dist)
		{
			uint32_t temp_key = rhht_snp_table->buffer[pos].key;
			uint16_t temp_case_count = rhht_snp_table->buffer[pos].case_count;
			uint16_t temp_control_count = rhht_snp_table->buffer[pos].control_count;

			rhht_snp_table->buffer[pos].key = key;
			rhht_snp_table->buffer[pos].case_count = case_count;
			rhht_snp_table->buffer[pos].control_count = control_count;

			key = temp_key;
			case_count = temp_case_count;
			control_count = temp_control_count;

			dist = existing_elem_probe_dist;
		}

		pos = pos + 1;
		dist = dist + 1;
	}
}

void grow();

inline void insert(uint32_t key, uint8_t allele_type, uint8_t patient_status)
{
	rhht_snp_table->num_elems = rhht_snp_table->num_elems + 1;
	if(rhht_snp_table->num_elems >= rhht_snp_table->resize_threshold)
	{
		grow();
	}

	uint32_t hash = key & ((rhht_snp_table->capacity) - 1);
	if(patient_status == 0)
	{
		insert_helper(hash, key, 0, (uint32_t) allele_type);
	}
	else
	{
		insert_helper(hash, key, (uint32_t) allele_type, 0);
	}
}

int32_t lookup_index(uint32_t key);

int32_t find(uint32_t key);

#endif
