#include <stdlib.h>
#include <string.h>
#include <sgx_trts.h>
#include "enclave_csk.h"
#include "util.h"

struct csk* m_csk = NULL;

void csk_init(uint32_t width, uint32_t depth)
{
	m_csk = (csk*) malloc(sizeof(csk));

	m_csk->width = width;
	m_csk->depth = depth;
	m_csk->width_minus_one = width - 1;
	m_csk->seeds = NULL;
	m_csk->s_thres = 200;

	m_csk->sketch = (int16_t**) malloc(depth * sizeof(int16_t*));
	m_csk->sketchf = NULL;

	for(size_t i = 0; i < depth; i++)
	{
		m_csk->sketch[i] = (int16_t*) malloc(width * sizeof(int16_t));
		memset(m_csk->sketch[i], 0, width * sizeof(int16_t));
	}

	m_csk->seeds = (uint64_t*) malloc(depth * sizeof(uint64_t) << 2);

	for(size_t i = 0; i < depth << 1; i++)
	{
		m_csk->seeds[(i << 1)] = my_sgx_rand();
		while(m_csk->seeds[(i << 1)] == 0)
		{
			m_csk->seeds[(i << 1)] = my_sgx_rand();
		}
		m_csk->seeds[(i << 1) + 1] = my_sgx_rand();
	}
}

void csk_init_f(uint32_t width, uint32_t depth)
{
	m_csk = (csk*) malloc(sizeof(csk));

	m_csk->width = width;
	m_csk->depth = depth;
	m_csk->width_minus_one = width - 1;
	m_csk->seeds = NULL;
	m_csk->s_thres = 200;

	m_csk->sketch = NULL;
	m_csk->sketchf = (float**) malloc(depth * sizeof(float*));

	for(size_t i = 0; i < depth; i++)
	{
		m_csk->sketchf[i] = (float*) malloc(width * sizeof(float));
		memset(m_csk->sketchf[i], 0, width * sizeof(float));
	}

	m_csk->seeds = (uint64_t*) malloc(depth * sizeof(uint64_t) << 2);

	for(size_t i = 0; i < depth << 1; i++)
	{
		m_csk->seeds[(i << 1)] = my_sgx_rand();
		while(m_csk->seeds[(i << 1)] == 0)
		{
			m_csk->seeds[(i << 1)] = my_sgx_rand();
		}
		m_csk->seeds[(i << 1) + 1] = my_sgx_rand();
	}
}

void csk_free()
{
	if(m_csk->seeds != NULL)
	{
		free(m_csk->seeds);
	}

	if(m_csk->sketch != NULL)
	{
		for(size_t i = 0; i < m_csk->depth; i++)
		{
			free(m_csk->sketch[i]);
		}
		free(m_csk->sketch);
	}

	if(m_csk->sketchf != NULL)
	{
		for(size_t i = 0; i < m_csk->depth; i++)
		{
			free(m_csk->sketchf[i]);
		}
		free(m_csk->sketchf);
	}
}

void csk_setsth(int new_threshold)
{
	m_csk->s_thres = new_threshold;
}

void csk_update_var(uint64_t item, int16_t count)
{
	uint32_t hash;
	uint32_t pos;
	int16_t count_;

	for(size_t i = 0; i < m_csk->depth; i++)
	{
		hash = cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

		if(m_csk->sketch[i][pos] >= HASH_MAX_16 && count_ > 0)
		{
			continue;
		}
		if(m_csk->sketch[i][pos] <= HASH_MIN_16 && count_ < 0)
		{
			continue;
		}
		m_csk->sketch[i][pos] = m_csk->sketch[i][pos] + count_;
	}
}

void csk_update_var_f(uint64_t item, float count)
{
	uint32_t hash;
	uint32_t pos;

	for(size_t i = 0; i < m_csk->depth; i++)
	{
		hash = cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		if((hash & 0x1) == 0)
		{
			m_csk->sketchf[i][pos] = m_csk->sketchf[i][pos] - count;
		}
		else
		{
			m_csk->sketchf[i][pos] = m_csk->sketchf[i][pos] + count;
		}
	}
}

/***** Test function *****/
void cms_update_var_row(uint64_t item, int16_t count, size_t row)
{
	uint32_t hash;
	uint32_t pos;

	hash = cal_hash(item, m_csk->seeds[row << 1], m_csk->seeds[(row << 1) + 1]);
	pos = hash & m_csk->width_minus_one;
	hash = cal_hash(item, m_csk->seeds[(row + m_csk->depth) << 1], m_csk->seeds[((row + m_csk->depth) << 1) + 1]);
	int16_t count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

	if(m_csk->sketch[row][pos] >= HASH_MAX_16 && count_ > 0)
	{
		return;
	}

	if(m_csk->sketch[row][pos] <= HASH_MIN_16 && count_ < 0)
	{
		return;
	}

	m_csk->sketch[row][pos] = m_csk->sketch[row][pos] + count_;
}

void cms_update_var_row_f(uint64_t item, float count, size_t row)
{
	uint32_t hash;
	uint32_t pos;

	hash = cal_hash(item, m_csk->seeds[row << 1], m_csk->seeds[(row << 1) + 1]);
	pos = hash & m_csk->width_minus_one;
	hash = cal_hash(item, m_csk->seeds[(row + m_csk->depth) << 1], m_csk->seeds[((row + m_csk->depth) << 1) + 1]);

	if((hash & 0x1) == 0)
	{
		m_csk->sketchf[row][pos] = m_csk->sketchf[row][pos] - count;
	}
	else
	{
		m_csk->sketchf[row][pos] = m_csk->sketchf[row][pos] + count;
	}
}
/***** END: Test function *****/

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
		hash = cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;
		hash = cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		sign = ((hash & 0x1) == 0) ? -1 : 1;
		values[i] = m_csk->sketch[i][pos] * sign;
	}

	// Sort values
	qsort(values, m_csk->depth, sizeof(int16_t), cmpfunc_int16);

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
		hash = cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;
		hash = cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		sign = ((hash & 0x1) == 0) ? -1 : 1;
		values[i] = m_csk->sketch[i][pos] * sign;
	}

	// Sort values
	qsort(values, m_csk->depth, sizeof(int16_t), cmpfunc_int16);

	// Get median of values
	if(values[m_csk->depth / 2] < -s_thres)
	{
		median = values[m_csk->depth / 2 - 1];
	}
	else if(values[m_csk->depth / 2 - 1] > s_thres)
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

float csk_query_median_odd_f(uint64_t item)
{
	float* values;
	float median;
	uint32_t hash;
	uint32_t pos;
	//int sign;

	values = (float*) malloc(m_csk->depth * sizeof(float));

	for(size_t i = 0; i < m_csk->depth; i++)
	{
		hash = cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;
		hash = cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		//sign = ((hash & 0x1) == 0) ? -1 : 1;
		if((hash & 0x1) == 0)
		{
			values[i] = -m_csk->sketchf[i][pos];
		}
		else
		{
			values[i] = m_csk->sketchf[i][pos];
		}
		//values[i] = m_csk->sketchf[i][pos] * sign;
	}

	// Sort values
	qsort(values, m_csk->depth, sizeof(float), cmpfunc_float);

	// Get median of values
	median = values[m_csk->depth / 2];

	// Free memory
	free(values);

	return median;
}

float csk_query_median_even_f(uint64_t item)
{
	float* values;
	float median;
	uint32_t hash;
	uint32_t pos;
	//int sign;

	values = (float*) malloc(m_csk->depth * sizeof(float));

	for(size_t i = 0; i < m_csk->depth; i++)
	{
		hash = cal_hash(item, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
		pos = hash & m_csk->width_minus_one;
		hash = cal_hash(item, m_csk->seeds[(i + m_csk->depth) << 1], m_csk->seeds[((i + m_csk->depth) << 1) + 1]);
		//sign = ((hash & 0x1) == 0) ? -1 : 1;
		//values[i] = m_csk->sketch32[i][pos] * sign;
		if((hash & 0x1) == 0)
		{
			values[i] = -m_csk->sketchf[i][pos];
		}
		else
		{
			values[i] = m_csk->sketchf[i][pos];
		}
	}

	// Sort values
	qsort(values, m_csk->depth, sizeof(float), cmpfunc_float);

	// Get median of values
	if(values[m_csk->depth / 2] + s_thres < 0.0)
	{
		median = values[m_csk->depth / 2 - 1];
	}
	else if(values[m_csk->depth / 2 - 1] - s_thres > 0.0)
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
