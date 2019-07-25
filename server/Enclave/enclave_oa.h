#ifndef __ENCLAVE_OA_H
#define __ENCLAVE_OA_H

#include "inttypes.h"

#define LOAD_FACTOR_PERCENT	95

struct oa_elem
{
	uint32_t key;
	uint32_t case_count;
	uint32_t control_count;
};

struct oa_table
{
	struct oa_elem* buffer;
	uint32_t num_elems;
	uint32_t capacity;
	uint32_t resize_threshold;
};

extern struct oa_table* oaht;

void oa_allocate_table(uint32_t capacity);

void oa_deallocate_table();

void oa_construct(uint32_t index, uint32_t key, uint16_t case_count, uint16_t control_count);

inline void oa_insert_helper(uint32_t hash, uint32_t key, uint16_t case_count, uint16_t control_count)
{
	uint32_t pos = hash;
	for(;;)
	{
		// Empty cell found, insert element
		if((oaht->buffer[pos].key & ((oaht->capacity) - 1)) == 0)
		{
			oa_construct(pos, key, case_count, control_count);
			return;
		}
		else
		{
			// Cell not empty, linear increase
			pos = pos + 1;

			// Wrap around the buffer if needed
			if(pos > oaht->capacity)
			{
				pos = 0;
			}
		}
	}
}

void oa_grow();

inline void oa_insert(uint32_t key, uint8_t allele_type, uint8_t patient_status)
{
	oaht->num_elems = oaht->num_elems + 1;
	if(oaht->num_elems >= oaht->resize_threshold)
	{
		oa_grow();
	}

	uint32_t hash = key & ((oaht->capacity) - 1);
	if(patient_status == 0)
	{
		oa_insert_helper(hash, key, 0, (uint32_t) allele_type);
	}
	else
	{
		oa_insert_helper(hash, key, (uint32_t) allele_type, 0);
	}
}

int32_t oa_find(uint32_t key);

#endif
