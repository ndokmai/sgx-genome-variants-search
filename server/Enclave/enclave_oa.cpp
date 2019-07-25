#include <stdlib.h>
#include "enclave_oa.h"

struct oa_table* oaht = NULL;

// Allocate memory for the hash table
void oa_allocate_table(uint32_t capacity)
{
	// Allocate memory for the top hash_table structure
	oaht = (struct oa_table*) malloc(sizeof(struct oa_table));

	// Initialization
	oaht->num_elems = 0;
	oaht->capacity = capacity;
	oaht->resize_threshold = (capacity * LOAD_FACTOR_PERCENT) / 100;

	// Allocate memory for the actual element buffer
	oaht->buffer = (struct oa_elem*) malloc(capacity * sizeof(struct oa_elem));

	// Mark all elements as unused
	for(uint32_t i = 0; i < capacity; i++)
	{
		oaht->buffer[i].key = 0;
	}
}

void oa_deallocate_table()
{
	free(oaht->buffer);
	free(oaht);
}

void oa_construct(uint32_t index, uint32_t key, uint16_t case_count, uint16_t control_count)
{
	oaht->buffer[index].key = key;
	oaht->buffer[index].case_count = case_count;
	oaht->buffer[index].control_count = control_count;
}

extern void oa_insert_helper(uint32_t hash, uint32_t key, uint16_t case_count, uint16_t control_count);

// Expand the hash table if the number of elements exceed the resize threshold
void oa_grow()
{
	struct oa_elem* old_elems = oaht->buffer;
	uint32_t old_capacity = oaht->capacity;
	uint32_t new_capacity = old_capacity * 2;

	oa_allocate_table(new_capacity);

	for(uint32_t i = 0; i < old_capacity; i++)
	{
		struct oa_elem e = old_elems[i];
		int key = e.key;
		int hash = key & (new_capacity - 1);
		if(key != 0)
		{
			oa_insert_helper(hash, e.key, e.case_count, e.control_count);
		}
	}
	free(old_elems);
}

extern void oa_insert(uint32_t key, uint8_t allele_type, uint8_t patient_status);


// Returns the index of the element with the searched key on success
// Returns -1 on failure
int32_t oa_find(uint32_t key)
{
	// Compute the hash of the key
	uint32_t hash = key & ((oaht->capacity) - 1);

	// Set the current position to the hash value
	uint32_t pos = hash;

	// Linear probe search
	for(;;)
	{
		uint32_t curr_hash = oaht->buffer[pos].key & ((oaht->capacity) - 1);

		// A key with value 0 denotes an empty cell, element not found
		if(curr_hash == 0)
		{
			return -1;
		}
		else if(curr_hash == hash && oaht->buffer[pos].key == key)
		{
			// Both the hash and key match, element found
			return pos;
		}

		// Try next cell
		pos = pos + 1;
	}
}
