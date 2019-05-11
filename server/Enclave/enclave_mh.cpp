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
		mh->mh_array_f = NULL;
                mh->mh_array = (struct mh_node*) malloc(capacity * sizeof(struct mh_node));
        }
}

void allocate_heap_f(uint32_t capacity)
{
        if(capacity <= MAX_ALLOWED_SIZE)
        {
                mh = (struct min_heap*) malloc(sizeof(struct min_heap));

                mh->curr_heap_size = 0;
                mh->max_heap_size = capacity;
		mh->mh_array = NULL;
                mh->mh_array_f = (struct mh_node_f*) malloc(capacity * sizeof(struct mh_node_f));
        }
}

void free_heap()
{
	if(mh->mh_array != NULL)
	{
		free(mh->mh_array);
	}
	if(mh->mh_array_f != NULL)
	{
		free(mh->mh_array_f);
	}
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

struct mh_node_f get_min_f()
{
        return mh->mh_array_f[0];
}

struct mh_node get_left(uint32_t i)
{
	return mh->mh_array[(i << 1) + 1];
}

struct mh_node_f get_left_f(uint32_t i)
{
        return mh->mh_array_f[(i << 1) + 1];
}

struct mh_node get_right(uint32_t i)
{
	return mh->mh_array[(i << 1) + 2];
}

struct mh_node_f get_right_f(uint32_t i)
{
        return mh->mh_array_f[(i << 1) + 2];
}

struct mh_node get_parent(uint32_t i)
{
	return mh->mh_array[(i - 1) >> 1];
}

struct mh_node_f get_parent_f(uint32_t i)
{
        return mh->mh_array_f[(i - 1) >> 1];
}

void mh_insert(uint32_t id, uint16_t val_)
{
	struct mh_node new_elem;
	new_elem.key = id;
	new_elem.val = val_;

	if(mh->curr_heap_size < mh->max_heap_size)
	{
		mh->curr_heap_size = mh->curr_heap_size + 1;
		mh->mh_array[mh->curr_heap_size - 1] = new_elem;
		min_heapify(mh->curr_heap_size - 1);
	}
	else
	{
		if(mh->mh_array[0].val >= val_)
		{
			return;
		}
		remove_min();
		mh->curr_heap_size = mh->curr_heap_size + 1;
		mh->mh_array[mh->curr_heap_size - 1] = new_elem;
		min_heapify(mh->curr_heap_size - 1);
	}
}

void mh_insert_f(uint32_t id, float val_)
{
        struct mh_node_f new_elem;
        new_elem.key = id;
        new_elem.val = val_;

        if(mh->curr_heap_size < mh->max_heap_size)
        {
                mh->curr_heap_size = mh->curr_heap_size + 1;
                mh->mh_array_f[mh->curr_heap_size - 1] = new_elem;
                min_heapify_f(mh->curr_heap_size - 1);
        }
        else
        {
                if(mh->mh_array_f[0].val >= val_)
                {
                        return;
                }
                remove_min_f();
                mh->curr_heap_size = mh->curr_heap_size + 1;
                mh->mh_array_f[mh->curr_heap_size - 1] = new_elem;
                min_heapify_f(mh->curr_heap_size - 1);
        }
}

void min_heapify(uint32_t idx)
{
	uint32_t idx_parent;
	struct mh_node temp;

	if(idx != 0)
	{
		idx_parent = ((idx - 1) >> 1);
		if(mh->mh_array[idx_parent].val > mh->mh_array[idx].val)
		{
			temp = mh->mh_array[idx_parent];
			mh->mh_array[idx_parent] = mh->mh_array[idx];
			mh->mh_array[idx] = temp;
			min_heapify(idx_parent);
		}
	}
}

void min_heapify_f(uint32_t idx)
{
        uint32_t idx_parent;
        struct mh_node_f temp;

        if(idx != 0)
        {
                idx_parent = ((idx - 1) >> 1);
                if(mh->mh_array_f[idx_parent].val > mh->mh_array_f[idx].val)
                {
                        temp = mh->mh_array_f[idx_parent];
                        mh->mh_array_f[idx_parent] = mh->mh_array_f[idx];
                        mh->mh_array_f[idx] = temp;
                        min_heapify_f(idx_parent);
                }
        }
}

void min_heapify_down(uint32_t idx)
{
	uint32_t idx_left;
	uint32_t idx_right;
	uint32_t idx_min;
	struct mh_node temp;

	idx_left = ((idx << 1) + 1);
	idx_right = ((idx << 1) + 2);
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
		if(mh->mh_array[idx_left].val <= mh->mh_array[idx_right].val)
		{
			idx_min = idx_left;
		}
		else
		{
			idx_min = idx_right;
		}
	}

	if(mh->mh_array[idx].val > mh->mh_array[idx_min].val)
	{
		temp = mh->mh_array[idx_min];
		mh->mh_array[idx_min] = mh->mh_array[idx];
		mh->mh_array[idx] = temp;
		min_heapify_down(idx_min);
	}
}

void min_heapify_down_f(uint32_t idx)
{
        uint32_t idx_left;
        uint32_t idx_right;
        uint32_t idx_min;
        struct mh_node_f temp;

        idx_left = ((idx << 1) + 1);
        idx_right = ((idx << 1) + 2);
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
                if(mh->mh_array_f[idx_left].val <= mh->mh_array_f[idx_right].val)
                {
                        idx_min = idx_left;
                }
                else
                {
                        idx_min = idx_right;
                }
        }

        if(mh->mh_array_f[idx].val > mh->mh_array_f[idx_min].val)
        {
                temp = mh->mh_array_f[idx_min];
                mh->mh_array_f[idx_min] = mh->mh_array_f[idx];
                mh->mh_array_f[idx] = temp;
                min_heapify_down_f(idx_min);
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

void remove_min_f()
{
        // Save the root node (the min node)
        struct mh_node_f temp = mh->mh_array_f[0];

        // Copy the last node in the heap to the root
        mh->mh_array_f[0] = mh->mh_array_f[mh->curr_heap_size - 1];

        // Decrease size
        mh->curr_heap_size = mh->curr_heap_size - 1;

        // Min Heapify root's value down
        min_heapify_down_f(0);
}

void get_mh_keys(uint32_t *keys, uint32_t l)
{
        if(l <= mh->max_heap_size)
        {
		for(uint32_t i = 0; i < l; i++)
		{
			keys[i] = mh->mh_array[i].key;
		}
        }
}

void get_mh_vals(uint16_t *vals, uint32_t l)
{
        if(l <= mh->max_heap_size)
        {
		for(uint32_t i = 0; i < l; i++)
		{
			vals[i] = mh->mh_array[i].val;
		}
        }
}

