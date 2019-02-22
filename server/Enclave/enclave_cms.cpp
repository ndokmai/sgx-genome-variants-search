#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include "util.h"
#include "enclave_cms.h"

struct cms* m_cms = NULL;

void cms_init_param(uint32_t width, uint32_t depth)
{
	m_cms = (cms*) malloc(sizeof(cms));
	m_cms->width = width;
	m_cms->depth = depth;
	m_cms->width_minus_one = width - 1;
	m_cms->seeds = NULL;
	m_cms->st_length = 0;
	m_cms->s_thres = 200;
}

void cms_init_seeds()
{
	m_cms->seeds = (uint64_t*) malloc(m_cms->depth * sizeof(uint64_t) << 1);

	for(size_t i = 0; i < m_cms->depth; i++)
	{
		m_cms->seeds[(i << 1)] = my_sgx_rand();
		while(m_cms->seeds[(i << 1)] == 0)
		{
			m_cms->seeds[(i << 1)] = my_sgx_rand();
		}
		m_cms->seeds[(i << 1) + 1] = my_sgx_rand();
	}
}

void cms_init(uint32_t width, uint32_t depth)
{
	cms_init_param(width, depth);
	
	m_cms->sketch = (int16_t**) malloc(depth * sizeof(int16_t*));
	for(size_t i = 0; i < depth; i++)
	{
		m_cms->sketch[i] = (int16_t*) malloc(width * sizeof(int16_t));
		memset(m_cms->sketch[i], 0, width * sizeof(int16_t));
	}

	cms_init_seeds();
}

void cms_setsth(int new_threshold)
{
	m_cms->s_thres = new_threshold;
}

void cms_update_var(uint64_t item, int16_t count)
{
	uint32_t hash;
	uint32_t pos;
	m_cms->st_length = m_cms->st_length + count;

	size_t i;
	for(i = 0; i < m_cms->depth; i++)
	{
		hash = cal_hash(item, m_cms->seeds[i << 1], m_cms->seeds[(i << 1) + 1]);
		pos = hash & m_cms->width_minus_one;

		if(m_cms->sketch[i][pos] >= HASH_MAX_16 && count > 0)
		{
			continue;
		}
		if(m_cms->sketch[i][pos] <= HASH_MIN_16 && count < 0)
		{
			continue;
		}

		m_cms->sketch[i][pos] = m_cms->sketch[i][pos] + count;
	}
}

/***** Test function *****/
void cms_update_var_row(uint64_t item, int16_t count, size_t row)
{
	uint32_t hash;
	uint32_t pos;
	m_cms->st_length = m_cms->st_length + count;

	hash = cal_hash(item, m_cms->seeds[row << 1], m_cms->seeds[(row << 1) + 1]);
	pos = hash & m_cms->width_minus_one;

	if(m_cms->sketch[row][pos] >= HASH_MAX_16 && count > 0)
	{
		return;
	}
	if(m_cms->sketch[row][pos] <= HASH_MIN_16 && count < 0)
	{
		return;
	}

	m_cms->sketch[row][pos] = m_cms->sketch[row][pos] + count;
}
/***** END: Test function *****/

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
	if(values[m_cms->depth / 2] < -(m_cms->s_thres))
	{
		median = values[m_cms->depth / 2 - 1];
	}
	else if(values[m_cms->depth / 2 - 1] > m_cms->s_thres)
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
