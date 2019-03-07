#ifndef __ENCLAVE_MIN_HEAP_H
#define __ENCLAVE_MIN_HEAP_H

#include "inttypes.h"

#define MAX_ALLOWED_SIZE	(1 << 17)

extern struct min_heap* mh;

struct mh_node
{
	uint32_t key;
	uint16_t val;
};

struct mh_node_f
{
        uint32_t key;
        float val;
};

struct min_heap
{
	struct mh_node* mh_array;
	struct mh_node_f* mh_array_f;
	uint32_t curr_heap_size;
	uint32_t max_heap_size;
};

void allocate_heap(uint32_t);
void allocate_heap_f(uint32_t);
void free_heap();
uint8_t is_empty();
struct mh_node get_min();
struct mh_node_f get_min_f();
struct mh_node get_left(uint32_t);
struct mh_node_f get_left_f(uint32_t);
struct mh_node get_right(uint32_t);
struct mh_node_f get_right_f(uint32_t);
struct mh_node get_parent(uint32_t);
struct mh_node_f get_parent_f(uint32_t);
void mh_insert(uint32_t, uint16_t);
void mh_insert_f(uint32_t, float);
void remove_min();
void remove_min_f();
void min_heapify(uint32_t);
void min_heapify_f(uint32_t);
void min_heapify_down(uint32_t);
void min_heapify_down_f(uint32_t);

#endif
