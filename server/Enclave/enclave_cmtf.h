#ifndef __ENCLAVE_CMTF_H
#define __ENCLAVE_CMTF_H

#include "inttypes.h"

extern struct cmtf_table* cmtf_snp_table;

struct node
{
	uint32_t key;
	uint32_t case_count;
	uint32_t control_count;
	struct node* next;
};

struct cmtf_table
{
	struct node** buckets;
	uint32_t num_elements;
	uint32_t num_buckets_used;
	uint32_t num_buckets;
	uint32_t resize_threshold;
};

void cmtf_allocate_table(uint32_t num_buckets);

void cmtf_deallocate_table();

#endif
