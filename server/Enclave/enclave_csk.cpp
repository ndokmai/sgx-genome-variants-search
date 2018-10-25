#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include "enclave_csk.h"

struct csk* m_csk = NULL;

uint32_t my_sgx_rand_csk()
{
	uint32_t rand_num;
	sgx_read_rand((unsigned char*) &rand_num, sizeof(uint32_t));
	return rand_num & 0x7FFFFFFF;
}

int csk_cmpfunc_int16(const void* a, const void* b)
{
	return (*(int16_t*) a - *(int16_t*) b);
}

// Hash function: h(x) = (a * x + b) mod p, where p = 2 ^ 31 - 1
uint32_t csk_cal_hash(uint64_t x, uint64_t a, uint64_t b)
{
	uint64_t result = a * x + b;
	result = (result & 0x7FFFFFFF) + (result >> 31);

	if(result >= 0x7FFFFFFF)
	{
		return (uint32_t) (result - 0x7FFFFFFF);
	}

	return (uint32_t) result;
}

void csk_init(uint32_t width, uint32_t depth)
{
	m_csk->width = width;
	m_csk->depth = depth;
	m_csk->width_minus_one = width - 1;
	//self->shift = __builtin_clz(width - 1);
	m_csk->seeds = NULL;

	m_csk->sketch = (int16_t**) malloc(depth * sizeof(int16_t*));

	for(size_t i = 0; i < depth; i++)
	{
		m_csk->sketch[i] = (int16_t*) malloc(width * sizeof(int16_t));
		memset(m_csk->sketch[i], 0, width * sizeof(int16_t));
	}

	m_csk->seeds = (uint64_t*) malloc(depth * sizeof(uint64_t) << 2);
	//self->custom_signs = (int16_t*) malloc(depth * sizeof(int16_t));

	for(size_t i = 0; i < depth << 1; i++)
	{
		m_csk->seeds[(i << 1)] = my_sgx_rand_csk();
		while(m_csk->seeds[(i << 1)] == 0)
		{
			m_csk->seeds[(i << 1)] = my_sgx_rand_csk();
		}
		m_csk->seeds[(i << 1) + 1] = my_sgx_rand_csk();
	}
}

void csk_free()
{
	for(size_t i = 0; i < m_csk->depth; i++)
	{
		free(m_csk->sketch[i]);
	}
	free(m_csk->sketch);

	if(m_csk->seeds != NULL)
	{
		free(m_csk->seeds);
	}
}

void csk_update_var(uint64_t item, int16_t count)
{
	uint32_t hash;
	//int32_t sign;
	uint32_t pos;
	uint16_t count_;

	for(size_t i = 0; i < m_csk->depth; i++)
	{
		hash = csk_cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = csk_cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;
		if(m_csk->sketch[i][pos] >= HASH_MAX && count_ > 0)
		{
			continue;
		}
		if(m_csk->sketch[i][pos] <= HASH_MIN && count_ < 0)
		{
			continue;
		}
		m_csk->sketch[i][pos] = m_csk->sketch[i][pos] + count_;
	}
}

int16_t csk_query_median_odd(uint64_t item)
{
	int16_t* values;
	int16_t median;
	uint32_t hash;
	uint32_t pos;
	int32_t sign;

	values = (int16_t*) malloc(m_csk->depth * sizeof(int16_t));

	for(size_t i = 0; i < m_csk->depth; i++)
	{
		hash = csk_cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;
		hash = csk_cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		sign = ((hash & 0x1) == 0) ? -1 : 1;
		values[i] = m_csk->sketch[i][pos] * sign;
	}

	// Sort values
	qsort(values, m_csk->depth, sizeof(int16_t), csk_cmpfunc_int16);

	// Get median of values
	median = values[m_csk->depth / 2];

	// Free memory
	free(values);

	return median;
}

int16_t csk_query_median_even(uint64_t item)
{
	int16_t* values;
	int16_t median;
	uint32_t hash;
	uint32_t pos;
	int32_t sign;

	values = (int16_t*) malloc(m_csk->depth * sizeof(int16_t));

	for(size_t i = 0; i < m_csk->depth; i++)
	{
		hash = csk_cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;
		hash = csk_cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		sign = ((hash & 0x1) == 0) ? -1 : 1;
		values[i] = m_csk->sketch[i][pos] * sign;
	}

	// Sort values
	qsort(values, m_csk->depth, sizeof(int16_t), csk_cmpfunc_int16);

	// Get median of values
	if(values[m_csk->depth / 2] < 0)
	{
		median = values[m_csk->depth / 2 - 1];
	}
	else if(values[m_csk->depth / 2 - 1] > 0)
	{
		median = values[m_csk->depth / 2];
	}
	else
	{
		median = (values[m_csk->depth / 2 - 1] + values[m_csk->depth / 2]) / 2;
	}

	// Free memory
	free(values);

	return median;
}
