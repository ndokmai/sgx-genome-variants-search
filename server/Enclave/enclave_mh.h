#ifndef __ENCLAVE_MIN_HEAP_H
#define __ENCLAVE_MIN_HEAP_H

#include "inttypes.h"

#define MAX_ALLOWED_SIZE	128000

extern struct min_heap* mh;

struct mh_node
{
	uint32_t key;
	uint16_t case_count;
	uint16_t control_count;
	float chi_sq;
};

struct min_heap
{
	struct mh_node* mh_array;
	uint32_t curr_heap_size;
	uint32_t max_heap_size;
};

void allocate_heap(uint32_t capacity);
void free_heap();
uint8_t is_empty();
struct mh_node get_min();
struct mh_node get_left();
struct mh_node get_right();
struct mh_node get_parent();
void insert();
void remove_min();
void min_heapify(uint32_t idx);
void min_heapify_down(uint32_t idx);

#endif
