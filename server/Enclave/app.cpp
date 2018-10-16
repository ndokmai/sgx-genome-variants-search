#include <stdlib.h>
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include "config.h"
#include "Enclave_t.h"
#include "enclave_crypto.h"
#include "math.h"

#define	ENC_OUTBUF_LEN	256
uint32_t enclave_output_buffer[ENC_OUTBUF_LEN];
uint32_t res_buf[10];

/*************** BEGIN: Robin Hood Hash Table ***************/
#define RHHT_INIT_CAPACITY	8388608
#define LOAD_FACTOR_PERCENT	95

struct elem
{
	uint32_t key;
	uint16_t case_count;
	uint16_t control_count;
};

struct hash_table
{
	struct elem* buffer;
	uint32_t num_elems;
	uint32_t capacity;
	uint32_t resize_threshold;
};

// Hash Table for SNPs, initially NULL
struct hash_table* snp_table = NULL;

// Allocate memory for SNP hash table
void allocate_table(uint32_t capacity)
{
	// Allocate memory for the top hash_table structure
	snp_table = (struct hash_table*) malloc(sizeof(struct hash_table));

	// Initialization
	snp_table->num_elems = 0;
	snp_table->capacity = capacity;
	snp_table->resize_threshold = (capacity * LOAD_FACTOR_PERCENT) / 100;

	// Allocate memory for the actual element buffer 
	snp_table->buffer = (struct elem*) malloc(capacity * sizeof(struct elem));

	// Mark all elements as unused
	for(uint32_t i = 0; i < capacity; i++)
	{
		snp_table->buffer[i].key = 0;
	}
}

void construct(uint32_t index, uint32_t key, uint16_t case_count, uint16_t control_count)
{
	snp_table->buffer[index].key = key;
	snp_table->buffer[index].case_count = case_count;
	snp_table->buffer[index].control_count = control_count;
}

uint32_t probe_distance(uint32_t key, uint32_t slot_index)
{
	//uint32_t hash = key % snp_table->capacity;
	uint32_t hash = key & ((snp_table->capacity) - 1);
	return (slot_index + snp_table->capacity - hash);
}

inline void insert_helper(uint32_t hash, uint32_t key, uint16_t case_count, uint16_t control_count)
{
	uint32_t pos = hash;
	uint32_t dist = 0;
	for(;;)
	{
		//if((snp_table->buffer[pos].key % snp_table->capacity) == 0)
		if((snp_table->buffer[pos].key & ((snp_table->capacity) - 1)) == 0)
		{
			construct(pos, key, case_count, control_count);
			return;
		}

		uint32_t existing_elem_probe_dist = probe_distance(snp_table->buffer[pos].key, pos);
		if(existing_elem_probe_dist < dist)
		{
			//uint32_t temp_hash = snp_table->buffer[pos].hash;
			uint32_t temp_key = snp_table->buffer[pos].key;
			uint16_t temp_case_count = snp_table->buffer[pos].case_count;
			uint16_t temp_control_count = snp_table->buffer[pos].control_count;
			//snp_table->buffer[pos].hash = hash;
			snp_table->buffer[pos].key = key;
			snp_table->buffer[pos].case_count = case_count;
			snp_table->buffer[pos].control_count = control_count;
			//hash = temp_hash;
			key = temp_key;
			case_count = temp_case_count;
			control_count = temp_control_count;

			dist = existing_elem_probe_dist;
		}

		pos = pos + 1;
		dist = dist + 1;
	}
}

// Expand the hash table if the number of elements exceed the resize threshold
void grow()
{
	//ocall_print_string("Error: This should not have happened for this run!!!\n");

	struct elem* old_elems = snp_table->buffer;
	uint32_t old_capacity = snp_table->capacity;

	uint32_t new_capacity = old_capacity * 2;
	allocate_table(new_capacity);

	for(uint32_t i = 0; i < old_capacity; i++)
	{
		struct elem e = old_elems[i];
		uint32_t key = e.key;
		//uint32_t hash = key % new_capacity;
		uint32_t hash = key & (new_capacity - 1);
		if(key != 0)
		{
			insert_helper(hash, e.key, e.case_count, e.control_count);
		}
	}
	free(old_elems);
}

inline void insert(uint32_t key, uint8_t allele_type, uint8_t patient_status)
{
	snp_table->num_elems = snp_table->num_elems + 1;
	if(snp_table->num_elems >= snp_table->resize_threshold)
	{
		grow();
	}

	//uint32_t hash = key % snp_table->capacity;
	uint32_t hash = key & ((snp_table->capacity) - 1);
	if(patient_status == 0)
	{
		insert_helper(hash, key, 0, (uint32_t) allele_type);
	}
	else
	{
		insert_helper(hash, key, (uint32_t) allele_type, 0);
	}
}

int32_t lookup_index(uint32_t key)
{
	//uint32_t hash = key % snp_table->capacity;
	uint32_t hash = key & ((snp_table->capacity) - 1);
	uint32_t pos = hash;
	uint32_t dist = 0;
	for(;;)
	{
		//uint32_t curr_hash = snp_table->buffer[pos].key % snp_table->capacity;
		uint32_t curr_hash = snp_table->buffer[pos].key & ((snp_table->capacity) - 1);
		if(curr_hash == 0)
		{
			return -1;
		}
		else if(dist > probe_distance(snp_table->buffer[pos].key, pos))
		{
			return -1;
		}
		else if(curr_hash == hash && snp_table->buffer[pos].key == key)
		{
			return pos;
		}

		pos = pos + 1;
		dist = dist + 1;
	}
}

int32_t find(uint32_t key)
{
	return lookup_index(key);
}

void enclave_init_rhht()
{
	allocate_table((uint32_t) RHHT_INIT_CAPACITY);
}

void enclave_decrypt_process_rhht(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len, uint32_t type)// uint32_t chunk_num)
{
	// Buffer to hold the secret key
    uint8_t sk[16];

	// Buffer to hold the decrypted plaintext
	// Plaintext length can't be longer than the ciphertext length
	uint8_t* plaintext = new uint8_t[ciphertext_len];

	// Internal Enclave function to fetch the secret key
    enclave_getkey(sk);

	// Decrypt the ciphertext, place it inside the plaintext buffer and return the length of the plaintext
    size_t plaintext_len = enclave_decrypt(ciphertext, ciphertext_len, sk, plaintext);

	uint32_t num_elems = plaintext_len / 4;

	// Process data
	/*
	size_t i;
	for(i = 2; i < num_elems; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		uint32_t index = find(elem_id);

		if(index != -1)
		{
			snp_table->buffer[index].case_count = snp_table->buffer[index].case_count + 1;
		}
		else
		{
			insert(elem_id, 1, 1);
		}
	}
	*/

	size_t i;
	uint32_t het_start_idx = ((uint32_t*) plaintext) [1];
	for(i = 2; i < het_start_idx + 2; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		uint32_t index = find(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			if(type == 1)
			{
				snp_table->buffer[index].case_count = snp_table->buffer[index].case_count + 2;
			}
			else
			{
				snp_table->buffer[index].control_count = snp_table->buffer[index].control_count + 2;
			}
		}
		else
		{
			if(type == 1)
			{
				insert(elem_id, 2, 1);
			}
			else
			{
				insert(elem_id, 2, 0);
			}
		}
	}

	for(i = het_start_idx + 2; i < num_elems; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		uint32_t index = find(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			if(type == 1)
			{
				snp_table->buffer[index].case_count = snp_table->buffer[index].case_count + 1;
			}
			else
			{
				snp_table->buffer[index].control_count = snp_table->buffer[index].control_count + 1;
			}
		}
		else
		{
			if(type == 1)
			{
				insert(elem_id, 1, 1);
			}
			else
			{
				insert(elem_id, 1, 0);
			}
		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}
/*************** END: Robin Hood Hash Table ***************/

/*************** BEGIN: Chi-Squared Test Functions **************/

// poz(): probability of normal z value
// This function was taken from an adaptation of: 
// Ibbetson D, Algorithm 209 Collected Algorithms of the CACM 1963 p. 616
// Adaptation source: stat.uchicago.edu/~mcpeek/software/dhsmap/se.c
double poz(double z)
{
	double x = 0.0;
	if(z != 0.0)
	{
		double y = 0.5 * fabs(z);
		if(y >= 3.0)
		{
			x = 1.0;
		}
		else if(y < 1.0)
		{
			double w = y * y;
			x = ((((((((0.000124818987 * w
			  -0.001075204047) * w +0.005198775019) * w
			  -0.019198292004) * w +0.059054035642) * w
			  -0.151968751364) * w +0.319152932694) * w
			  -0.531923007300) * w +0.797884560593) * y * 2.0;
		}
		else
		{
			y = y - 2.0;
			x = (((((((((((((-0.000045255659 * y
			  +0.000152529290) * y -0.000019538132) * y
			  -0.000676904986) * y +0.001390604284) * y
			  -0.000794620820) * y -0.002034254874) * y
			  +0.006549791214) * y -0.010557625006) * y
			  +0.011630447319) * y -0.009279453341) * y
			  +0.005353579108) * y -0.002141268741) * y
			  +0.000535310849) * y +0.999936657524;
		}
	}
	return (z > 0.0 ? ((x + 1.0) * 0.5) : ((1.0 - x) * 0.5));
}

// pochisq()L probability of chi squared value
// Taken from an adaptation of:
// Hill, I. D. and Pike, M. C. Algorithm 299
// Collected Algorithms for the CACM 1967 p. 243
// Updated for rounding errors based on remark in ACM TOMS June 1985, page 185
// Adaptation source: stat.uchicago.edu/~mcpeek/software/dhsmap/se.c
double pochisq(double x)
{
	if(x <= 0.0)
	{
		return 1.0;
	}
	else
	{
		return 2.0 * poz(-sqrt(x));
	}
}

float chi_sq(uint16_t case_min, uint16_t control_min, uint16_t case_total, uint16_t control_total)
{
	//mysgx_printf("%d\t%d\t%d\t%d\n", case_min, control_min, case_total, control_total);
	uint16_t case_maj = case_total - case_min;
	uint16_t control_maj = control_total - control_min;
	uint16_t pop_total = case_total + control_total;

	/* Compute observed frequencies */
	float case_maj_f = (float) case_maj / pop_total;
	float case_min_f = (float) case_min / pop_total;
	float control_maj_f = (float) control_maj / pop_total;
	float control_min_f = (float) control_min / pop_total;
	float obs_freq[4];
	obs_freq[0] = case_maj_f;
	obs_freq[1] = case_min_f;
	obs_freq[2] = control_maj_f;
	obs_freq[3] = control_min_f;
	//mysgx_printf("%f\t%f\t%f\t%f\n", case_maj_f, case_min_f, control_maj_f, control_min_f);

	/* Compute expected frequencies */
	float case_total_f = (float) case_total / pop_total;
	float control_total_f = (float) control_total / pop_total;
	float maj_total_f = case_maj_f + control_maj_f;
	float min_total_f = case_min_f + control_min_f;
	float pop_total_f = (float) pop_total / pop_total;
	float exp_freq[4];
	exp_freq[0] = case_total_f * maj_total_f;
	exp_freq[1] = case_total_f * min_total_f;
	exp_freq[2] = control_total_f * maj_total_f;
	exp_freq[3] = control_total_f * min_total_f;
	//mysgx_printf("%f\t%f\t%f\t%f\n", exp_freq[0], exp_freq[1], exp_freq[2], exp_freq[3]);

	/* Compute expected counts */
	float exp_count[4];
	exp_count[0] = exp_freq[0] * pop_total;
	exp_count[1] = exp_freq[1] * pop_total;
	exp_count[2] = exp_freq[2] * pop_total;
	exp_count[3] = exp_freq[3] * pop_total;
	//mysgx_printf("%f\t%f\t%f\t%f\n", exp_count[0], exp_count[1], exp_count[2], exp_count[3]);
	/* Compute the Chi-Squared Value */
	float chi_sq_val = 0;
	chi_sq_val = chi_sq_val + ((case_maj - exp_count[0]) * (case_maj - exp_count[0]) / exp_count[0]);
	chi_sq_val = chi_sq_val + ((case_min - exp_count[1]) * (case_min - exp_count[1]) / exp_count[1]);
	chi_sq_val = chi_sq_val + ((control_maj - exp_count[2]) * (control_maj - exp_count[2]) / exp_count[2]);
	chi_sq_val = chi_sq_val + ((control_min - exp_count[3]) * (control_min - exp_count[3]) / exp_count[3]);
	//mysgx_printf("%f\n", chi_sq_val);

	return chi_sq_val;
}

void init_chi_sq(uint16_t case_total, uint16_t control_total)
{
	uint32_t top_k_ids[10];
	float top_k_chi_sq[10];
	uint8_t num_used = 0;
	float chi_sq_val;
	for(uint32_t i = 0; i < snp_table->capacity; i++)
	{
		if(snp_table->buffer[i].key != 0)
		{
			/* Calculate the chi squared value */
			chi_sq_val = chi_sq(snp_table->buffer[i].case_count, snp_table->buffer[i].control_count, case_total, control_total);
			//double pval = pochisq((double) chi_sq_val);
			//mysgx_printf("%d\t%f\t%.12f\n", snp_table->buffer[i].key, chi_sq_val, pval);

			/* If the top-k array is not full, add current snp without any checks */
			if(num_used < 10)
			{
				top_k_ids[num_used] = snp_table->buffer[i].key;
				top_k_chi_sq[num_used] = chi_sq_val;
				num_used = num_used + 1;
			}
			else
			{
				/* Find the index of the minimum chi squared value in the top-k array */
				uint8_t index_min = 0;
				for(uint8_t j = 1; j < 10; j++)
				{
					if(top_k_chi_sq[j] < top_k_chi_sq[index_min])
					{
						index_min = j;
					}
				}

				/* If the chi squared value of the current element is greater than that of index min, replace */
				if(chi_sq_val > top_k_chi_sq[index_min])
				{
					top_k_ids[index_min] = snp_table->buffer[i].key;
					top_k_chi_sq[index_min] = chi_sq_val;
				}
			}
		}
	}
	
	//mysgx_printf("\nTop-10 SNPs with Chi-Squared Values and P-Values\n\n");
	for(uint8_t i = 0; i < 10; i++)
	{
		double pval = pochisq((double) top_k_chi_sq[i]);
		//mysgx_printf("rs%-30d\t%-30f\t%-30.8f\n", top_k_ids[i], top_k_chi_sq[i], pval);

		// Proper output test
		res_buf[i] = top_k_ids[i];
	}
	//mysgx_printf("\n");
}
/*************** END: Chi-Sqaured Test Functions ***************/

/*************** BEGIN: Enclave Test Program Functions ***************/
uint64_t sum;

void enclave_init_sum()
{
	sum = 0;
}

void enclave_get_result(uint64_t* result)
{
	memcpy(result, &sum, sizeof(uint64_t));
}

void enclave_get_res_buf(uint32_t* res)
{
	memcpy(res, &res_buf, 10 * sizeof(uint32_t));
}

/*void enclave_out_function(char* buf, size_t len)
{
	if(len <= (size_t) MAX_BUF_LEN)
	{
		memcpy(buf, enclave_buffer, len);
	}
}*/

int enclave_decrypt_for_me(sgx_ra_context_t ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, uint8_t* _sk)
{
    uint8_t sk[16];
    enclave_getkey(sk);
    // This is done to print out the key. In the real use key sk should not be leaked from the enclave.
    memcpy(_sk, sk, 16);
    size_t plen = enclave_decrypt(ciphertext, ciphertext_len, sk, plaintext);
    return plen;
}

void enclave_decrypt_process(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
{
	// Buffer to hold the secret key
    uint8_t sk[16];

	// Buffer to hold the decrypted plaintext
	// Plaintext length can't be longer than the ciphertext length
	uint8_t* plaintext = new uint8_t[ciphertext_len];

	// Internal Enclave function to fetch the secret key
    enclave_getkey(sk);

	// Decrypt the ciphertext, place it inside the plaintext buffer and return the length of the plaintext
    size_t plaintext_len = enclave_decrypt(ciphertext, ciphertext_len, sk, plaintext);

	// Process data
	for(size_t i = 0; i < plaintext_len / 4; i++)
	{
		sum = sum + ((uint32_t*) plaintext)[i];
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}
