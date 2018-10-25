#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include "enclave_cms.h"

struct cms* m_cms = NULL;

uint32_t my_sgx_rand()
{
	uint32_t rand_num;
	sgx_read_rand((unsigned char*) &rand_num, sizeof(uint32_t));
	return rand_num & 0x7FFFFFFF;
}

int cmpfunc_int16(const void* a, const void* b)
{
	return (*(int16_t*) a - *(int16_t*) b);
}

// Hash function: h(x) = (a * x + b) mod p, where p = 2 ^ 31 - 1
uint32_t cal_hash(uint64_t x, uint64_t a, uint64_t b)
{
	uint64_t result = a * x + b;
	result = (result & 0x7FFFFFFF) + (result >> 31);

	if(result >= 0x7FFFFFFF)
	{
		return (uint32_t) (result - 0x7FFFFFFF);
	}

	return (uint32_t) result;
}

void cms_init(uint32_t width, uint32_t depth)
{
	m_cms = (cms*) malloc(sizeof(cms));

	m_cms->width = width;
	m_cms->depth = depth;
	m_cms->width_minus_one = width - 1;
	m_cms->st_length = 0;

	m_cms->sketch = (int16_t**) malloc(depth * sizeof(int16_t*));

	for(size_t i = 0; i < depth; i++)
	{
		m_cms->sketch[i] = (int16_t*) malloc(width * sizeof(int16_t));
		memset(m_cms->sketch[i], 0, width * sizeof(int16_t));
	}

	m_cms->seeds = (uint64_t*) malloc(depth * sizeof(uint64_t) << 1);

	//time_t t;
	//srand((unsigned) time(&t));

	for(size_t i = 0; i < depth; i++)
	{
		m_cms->seeds[(i << 1)] = my_sgx_rand();
		while(m_cms->seeds[(i << 1)] == 0)
		{
			m_cms->seeds[(i << 1)] = my_sgx_rand();
		}
		m_cms->seeds[(i << 1) + 1] = my_sgx_rand();
	}
}

void cms_update_var(uint64_t item, int16_t count)
{
	uint32_t hash;
//	uint32_t pos;
	volatile uint32_t pos;
	m_cms->st_length = m_cms->st_length + count;

	size_t i;
	for(i = 0; i < m_cms->depth; i++)
	{
		hash = cal_hash(item, m_cms->seeds[i << 1], m_cms->seeds[(i << 1) + 1]);
		pos = hash & m_cms->width_minus_one;

		if(m_cms->sketch[i][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_cms->sketch[i][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_cms->sketch[i][pos] = m_cms->sketch[i][pos] + count;
	}
}

void cms_free()
{
	for(size_t i = 0; i < m_cms->depth; i++)
	{
		free(m_cms->sketch[i]);
	}

	free(m_cms->sketch);
	if(m_cms->seeds != NULL)
	{
		free(m_cms->seeds);
	}
}

int16_t cms_query_median_odd(uint64_t item)
{
	int16_t* values;
	int16_t median;
	uint32_t hash;
	uint32_t pos;
	uint16_t log_width = __builtin_ctz(m_cms->width);

	values = (int16_t*) malloc(m_cms->depth * sizeof(int16_t));

	for(size_t i = 0; i < m_cms->depth; i++)
	{
		hash = cal_hash(item, m_cms->seeds[i << 1], m_cms->seeds[(i << 1) + 1]);
		pos = hash & m_cms->width_minus_one;
		values[i] = m_cms->sketch[i][pos];

		// Guarantee unbiased query
		values[i] -= ((m_cms->st_length - values[i]) >> log_width);
	}

	// Sort values
	qsort(values, m_cms->depth, sizeof(int16_t), cmpfunc_int16);

	// Get median of values
	median = values[m_cms->depth / 2];

	// Free memory
	free(values);

	return median;
}

int16_t cms_query_median_even(uint64_t item)
{
	int16_t* values;
	int16_t median;
	uint32_t hash;
	uint32_t pos;
	uint16_t log_width = __builtin_ctz(m_cms->width);

	values = (int16_t*) malloc(m_cms->depth * sizeof(int16_t));

	for(size_t i = 0; i < m_cms->depth; i++)
	{
		hash = cal_hash(item, m_cms->seeds[i << 1], m_cms->seeds[(i << 1) + 1]);
		pos = hash & m_cms->width_minus_one;
		values[i] = m_cms->sketch[i][pos];

		// Guarantee unbiased query
		values[i] -= ((m_cms->st_length - values[i]) >> log_width);
	}

	// Sort values
	qsort(values, m_cms->depth, sizeof(int16_t), cmpfunc_int16);

	// Get median of values
	if(values[m_cms->depth / 2] < 0)
	{
		median = values[m_cms->depth / 2 - 1];
	}
	else if(values[m_cms->depth / 2 - 1] > 0)
	{
		median = values[m_cms->depth / 2];
	}
	else
	{
		median = (values[m_cms->depth / 2 - 1] + values[m_cms->depth / 2]) / 2;
	}

	// Free memory
	free(values);

	return median;
}
