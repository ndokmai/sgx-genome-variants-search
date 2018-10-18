#include <stdlib.h>
#include "enclave_rhht.h"

struct rhht_table* rhht_snp_table = NULL;

// Allocate memory for SNP hash table
void allocate_table(uint32_t capacity)
{
	// Allocate memory for the top hash_table structure
	rhht_snp_table = (struct rhht_table*) malloc(sizeof(struct rhht_table));

	// Initialization
	rhht_snp_table->num_elems = 0;
	rhht_snp_table->capacity = capacity;
	rhht_snp_table->resize_threshold = (capacity * LOAD_FACTOR_PERCENT) / 100;

	// Allocate memory for the actual element buffer 
	rhht_snp_table->buffer = (struct elem*) malloc(capacity * sizeof(struct elem));

	// Mark all elements as unused
	for(uint32_t i = 0; i < capacity; i++)
	{
		rhht_snp_table->buffer[i].key = 0;
	}
}

void construct(uint32_t index, uint32_t key, uint16_t case_count, uint16_t control_count)
{
	rhht_snp_table->buffer[index].key = key;
	rhht_snp_table->buffer[index].case_count = case_count;
	rhht_snp_table->buffer[index].control_count = control_count;
}

uint32_t probe_distance(uint32_t key, uint32_t slot_index)
{
	uint32_t hash = key & ((rhht_snp_table->capacity) - 1);
	return (slot_index + rhht_snp_table->capacity - hash);
}

extern void insert_helper(uint32_t hash, uint32_t key, uint16_t case_count, uint16_t control_count);

// Expand the hash table if the number of elements exceed the resize threshold
void grow()
{
	struct elem* old_elems = rhht_snp_table->buffer;
	uint32_t old_capacity = rhht_snp_table->capacity;
	uint32_t new_capacity = old_capacity * 2;

	allocate_table(new_capacity);

	for(uint32_t i = 0; i < old_capacity; i++)
	{
		struct elem e = old_elems[i];
		uint32_t key = e.key;
		uint32_t hash = key & (new_capacity - 1);
		if(key != 0)
		{
			insert_helper(hash, e.key, e.case_count, e.control_count);
		}
	}
	free(old_elems);
}

extern  void insert(uint32_t key, uint8_t allele_type, uint8_t patient_status);

int32_t lookup_index(uint32_t key)
{
	uint32_t hash = key & ((rhht_snp_table->capacity) - 1);
	uint32_t pos = hash;
	uint32_t dist = 0;
	for(;;)
	{
		uint32_t curr_hash = rhht_snp_table->buffer[pos].key & ((rhht_snp_table->capacity) - 1);
		if(curr_hash == 0)
		{
			return -1;
		}
		else if(dist > probe_distance(rhht_snp_table->buffer[pos].key, pos))
		{
			return -1;
		}
		else if(curr_hash == hash && rhht_snp_table->buffer[pos].key == key)
		{
			return pos;
		}

		pos = pos + 1;
		dist = dist + 1;
	}
}

int32_t find(uint32_t key)
{
	return lookup_index(key);
}
