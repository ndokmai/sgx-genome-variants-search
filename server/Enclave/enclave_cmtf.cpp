#include <stdlib.h>
#include "enclave_cmtf.h"

#define LOAD_FACTOR_PERCENT	95

// Chained Move-to-Front Hash Table, initially NULL
struct cmtf_table* cmtf_snp_table = NULL;

// Allocate memory for the hash table
void cmtf_allocate_table(uint32_t num_buckets)
{
	// Allocate memory for the top hash_table structure
	cmtf_snp_table = (struct cmtf_table*) malloc(sizeof(struct cmtf_table));

	// Initialization
	cmtf_snp_table->num_elements = 0;
	cmtf_snp_table->num_buckets_used = 0;
	cmtf_snp_table->num_buckets = num_buckets;
	cmtf_snp_table->resize_threshold = (num_buckets * LOAD_FACTOR_PERCENT) / 100;

	// Allocate memory for the actual element buffer
	cmtf_snp_table->buckets = (struct node**) malloc(num_buckets * sizeof(struct node*));

	// Mark all buckets as unused
	for(size_t i = 0; i < num_buckets; i++)
	{
		cmtf_snp_table->buckets[i] = NULL;
	}
}

void cmtf_deallocate_table()
{
	uint32_t num_buckets = cmtf_snp_table->num_buckets;
	for(size_t i = 0; i < num_buckets; i++)
	{
		if(cmtf_snp_table->buckets[i] != NULL)
		{
			struct node* head_ptr = cmtf_snp_table->buckets[i];
			struct node* temp;
			while (head_ptr != NULL)
			{
				temp = head_ptr;
				head_ptr = head_ptr->next;
				free(temp);
			}
		}
	}
	free(cmtf_snp_table->buckets);
	free(cmtf_snp_table);
}
