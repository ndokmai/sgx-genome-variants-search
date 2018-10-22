#include <stdlib.h>
#include "enclave_mh.h"

struct min_heap* mh = NULL;

void allocate_heap(uint32_t capacity)
{
	if(capacity <= MAX_ALLOWED_SIZE)
	{
		mh = (struct min_heap*) malloc(sizeof(struct min_heap));
		
		mh->curr_heap_size = 0;
		mh->max_heap_size = capacity;

		mh->mh_array = (struct mh_node*) malloc(capacity * sizeof(struct mh_node));
	}
}

void free_heap()
{
	free(mh->mh_array);
	free(mh);
}

uint8_t is_empty()
{
	if(mh->curr_heap_size == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

// We should actually check for is_empty in most functions below, but leave that to the app for now, due to speed limitations
struct mh_node get_min()
{
	return mh->mh_array[0];
}

struct mh_node get_left(uint32_t i)
{
	uint32_t idx_left = (2 * i) + 1;
	return mh->mh_array[idx_left];
}

struct mh_node get_right(uint32_t i)
{
	uint32_t idx_right = (2 * i) + 2;
	return mh->mh_array[idx_right];
}

struct mh_node get_parent(uint32_t i)
{
	uint32_t idx_parent = (i - 1) / 2;
	return mh->mh_array[idx_parent];
}

void insert(uint32_t id, float chi_sq_val)
{
	// If the heap is full, remove min element before inserting
	if(mh->curr_heap_size == mh->max_heap_size)
	{
		remove_min();
	}

	struct mh_node new_elem;
	new_elem.key = id;
	new_elem.case_count = 0;
	new_elem.control_count = 0;
	new_elem.chi_sq = chi_sq_val;

	mh->curr_heap_size = mh->curr_heap_size + 1;
	mh->mh_array[mh->curr_heap_size - 1] = new_elem;
	min_heapify(mh->curr_heap_size - 1);
}

void min_heapify(uint32_t idx)
{
	uint32_t idx_parent;
	struct mh_node temp;

	if(idx != 0)
	{
		idx_parent = (idx - 1) / 2;
		if(mh->mh_array[idx_parent].chi_sq > mh->mh_array[idx].chi_sq)
		{
			temp = mh->mh_array[idx_parent];
			mh->mh_array[idx_parent] = mh->mh_array[idx];
			mh->mh_array[idx] = temp;
			min_heapify(idx_parent);
		}
	}
}

void min_heapify_down(uint32_t idx)
{
	uint32_t idx_left;
	uint32_t idx_right;
	uint32_t idx_min;
	struct mh_node temp;

	idx_left = (2 * idx) + 1;
	idx_right =(2 * idx) + 2;
	if(idx_right >= mh->curr_heap_size)
	{
		if(idx_left >= mh->curr_heap_size)
		{
			return;
		}
		else
		{
			idx_min = idx_left;
		}
	}
	else
	{
		if(mh->mh_array[idx_left].chi_sq <= mh->mh_array[idx_right].chi_sq)
		{
			idx_min = idx_left;
		}
		else
		{
			idx_min = idx_right;
		}
	}

	if(mh->mh_array[idx].chi_sq > mh->mh_array[idx_min].chi_sq)
	{
		temp = mh->mh_array[idx_min];
		mh->mh_array[idx_min] = mh->mh_array[idx];
		mh->mh_array[idx] = temp;
		min_heapify_down(idx_min);
	}
}

void remove_min()
{
	// Save the root node (the min node)
	struct mh_node temp = mh->mh_array[0];

	// Copy the last node in the heap to the root
	mh->mh_array[0] = mh->mh_array[mh->curr_heap_size - 1];

	// Decrease size
	mh->curr_heap_size = mh->curr_heap_size - 1;

	// Min Heapify root's value down
	min_heapify_down(0);
}
