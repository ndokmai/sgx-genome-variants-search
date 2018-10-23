#ifndef __ENCLAVE_MIN_HEAP_H
#define __ENCLAVE_MIN_HEAP_H

#include "inttypes.h"

#define MAX_ALLOWED_SIZE	128000

extern struct min_heap* mh;

struct mh_node
{
	uint32_t key;
	uint16_t abs_diff;
	uint16_t case_count;
	uint16_t control_count;
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
struct mh_node get_left(uint32_t i);
struct mh_node get_right(uint32_t i);
struct mh_node get_parent(uint32_t i);
void insert(uint32_t id, uint16_t abs_diff);
void remove_min();
void min_heapify(uint32_t idx);
void min_heapify_down(uint32_t idx);

#endif
