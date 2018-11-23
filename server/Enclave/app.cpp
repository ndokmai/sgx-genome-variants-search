#include <stdlib.h>
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include "config.h"
#include "Enclave_t.h"
#include "enclave_crypto.h"
#include "math.h"
#include "enclave_mh.h"
#include "enclave_oa.h"
#include "enclave_rhht.h"
#include "enclave_cmtf.h"
#include "enclave_csk.h"
#include "enclave_cms.h"

#define ALLELE_HETEROZYGOUS	1
#define	ALLELE_HOMOZYGOUS	2

#define	MH_INIT_CAPACITY	(1 << 17)

#define	ENC_RES_BUF_LEN		(1 << 17)

#define OA_INIT_CAPACITY	(1 << 23)
#define RHHT_INIT_CAPACITY	(1 << 23)
#define CMTF_NUM_BUCKETS	(1 << 23)

#define CMS_WIDTH			(1 << 18)
#define	CMS_DEPTH			8

#define	CSK_WIDTH			(1 << 21)
#define	CSK_DEPTH			8

// Global Enclave Buffers
// TODO: Dynamically allocating and keeping track of this might be a good idea
uint32_t enclave_res_buf[ENC_RES_BUF_LEN];
uint8_t* ptxt;
uint8_t ptxt_len;

sgx_status_t ecall_thread_cms(int thread_num)
{
	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = ptxt_len / 4;

	// Get the meta information first
	uint32_t patient_status = ((uint32_t*) ptxt) [0];
	uint32_t num_het_start = ((uint32_t*) ptxt) [1];

	// Sign is +1 for case and -1 for control
	int16_t sign = 1;
	if(patient_status == 0)
	{
		sign = -1;
	}

	// Update the current row of the CMS
	int16_t count = ALLELE_HOMOZYGOUS * sign;
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];
		//cms_update_var(rs_id_uint, ALLELE_HOMOZYGOUS * sign);

		uint32_t hash;
		uint32_t pos;
		m_cms->st_length = m_cms->st_length + count;

		hash = cal_hash(rs_id_uint, m_cms->seeds[thread_num << 1], m_cms->seeds[(thread_num << 1) + 1]);
		pos = hash & m_cms->width_minus_one;

		if(m_cms->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_cms->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_cms->sketch[thread_num][pos] = m_cms->sketch[thread_num][pos] + count;
	}

	count = ALLELE_HETEROZYGOUS * sign;
	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];
		//cms_update_var(rs_id_uint, ALLELE_HETEROZYGOUS * sign);

		uint32_t hash;
		uint32_t pos;
		m_cms->st_length = m_cms->st_length + count;

		hash = cal_hash(rs_id_uint, m_cms->seeds[thread_num << 1], m_cms->seeds[(thread_num << 1) + 1]);
		pos = hash & m_cms->width_minus_one;

		if(m_cms->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_cms->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_cms->sketch[thread_num][pos] = m_cms->sketch[thread_num][pos] + count;
	}
	return SGX_SUCCESS;
}

sgx_status_t ecall_thread_csk(int thread_num)
{
	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = ptxt_len / 4;

	// Get the meta information first
	uint32_t patient_status = ((uint32_t*) ptxt) [0];
	uint32_t num_het_start = ((uint32_t*) ptxt) [1];

	// Sign is +1 for case and -1 for control
	int16_t sign = 1;
	if(patient_status == 0)
	{
		sign = -1;
	}

	// Update the current row of the CSK
	int16_t count = ALLELE_HOMOZYGOUS * sign;
	int16_t count_;
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[thread_num << 1], m_csk->seeds[(thread_num << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[(thread_num + m_csk->depth) << 1], m_csk->seeds[((thread_num + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

		if(m_csk->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_csk->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_csk->sketch[thread_num][pos] = m_csk->sketch[thread_num][pos] + count;
	}

	count = ALLELE_HETEROZYGOUS * sign;
	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[thread_num << 1], m_csk->seeds[(thread_num << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[(thread_num + m_csk->depth) << 1], m_csk->seeds[((thread_num + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

		if(m_csk->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_csk->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_csk->sketch[thread_num][pos] = m_csk->sketch[thread_num][pos] + count;
	}

	return SGX_SUCCESS;
}

/***** BEGIN: Enclave Count-Min-Sketch Public Interface *****/
void enclave_init_cms()
{
	cms_init(CMS_WIDTH, CMS_DEPTH);
}

void enclave_decrypt_store_cms(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
{
	// Buffer to hold the secret key
    uint8_t sk[16];

	// Plaintext length can't be longer than the ciphertext length
	ptxt = (uint8_t*) malloc(sizeof(uint8_t) * ciphertext_len);

	// Internal Enclave function to fetch the secret key
    enclave_getkey(sk);

	// Decrypt the ciphertext, place it inside the plaintext buffer and return the true length of the plaintext
    ptxt_len = enclave_decrypt(ciphertext, ciphertext_len, sk, ptxt);
}

void enclave_clear_cms(sgx_ra_context_t ctx)
{
	free(ptxt);
}

void enclave_update_cms(sgx_ra_context_t ctx, uint32_t thread_num)
{
	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = ptxt_len / 4;

	// Get the meta information first
	uint32_t patient_status = ((uint32_t*) ptxt) [0];
	uint32_t num_het_start = ((uint32_t*) ptxt) [1];

	// Sign is +1 for case and -1 for control
	int16_t sign = 1;
	if(patient_status == 0)
	{
		sign = -1;
	}

	// Update the current row of the CMS
	int16_t count = ALLELE_HOMOZYGOUS * sign;
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];
		//cms_update_var(rs_id_uint, ALLELE_HOMOZYGOUS * sign);

		uint32_t hash;
		uint32_t pos;
		m_cms->st_length = m_cms->st_length + count;

		hash = cal_hash(rs_id_uint, m_cms->seeds[thread_num << 1], m_cms->seeds[(thread_num << 1) + 1]);
		pos = hash & m_cms->width_minus_one;

		if(m_cms->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_cms->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_cms->sketch[thread_num][pos] = m_cms->sketch[thread_num][pos] + count;
	}

	count = ALLELE_HETEROZYGOUS * sign;
	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];
		//cms_update_var(rs_id_uint, ALLELE_HETEROZYGOUS * sign);

		uint32_t hash;
		uint32_t pos;
		m_cms->st_length = m_cms->st_length + count;

		hash = cal_hash(rs_id_uint, m_cms->seeds[thread_num << 1], m_cms->seeds[(thread_num << 1) + 1]);
		pos = hash & m_cms->width_minus_one;

		if(m_cms->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_cms->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_cms->sketch[thread_num][pos] = m_cms->sketch[thread_num][pos] + count;
	}
}

void enclave_decrypt_update_cms(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = plaintext_len / 4;

	// Get the meta information first
	uint32_t patient_status = ((uint32_t*) plaintext) [0];
	uint32_t num_het_start = ((uint32_t*) plaintext) [1];

	// Sign is +1 for case and -1 for control
	int16_t sign = 1;
	if(patient_status == 0)
	{
		sign = -1;
	}

	// Update the CMS for every element
	/*
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		cms_update_var(rs_id_uint, ALLELE_HOMOZYGOUS * sign);
	}

	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		cms_update_var(rs_id_uint, ALLELE_HETEROZYGOUS * sign);
	}
	*/

	size_t i;
	size_t j;
	uint64_t rs_id_uint;
	for(i = 0; i < m_cms->depth; i++)
	{
		for(j = 2; j < num_het_start + 2; j++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [j];
			cms_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i);
		}

		for(j = num_het_start + 2; j < num_elems; j++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [j];
			cms_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i);
		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_decrypt_query_cms(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = plaintext_len / 4;

	// Get the CMS depth
	uint32_t cms_depth = m_cms->depth;
	
	// Query the CMS for every element
	if(cms_depth % 2 == 0)
	{
		// CMS depth is even
		size_t i;
		int16_t est_diff;
		uint64_t rs_id_uint;

		for(i = 0; i < num_elems; i++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
			est_diff = cms_query_median_even(rs_id_uint);
			if(est_diff < 0)
			{
				est_diff = est_diff * -1;
			}

			// Try to insert the element into the min heap
			// If the heap is full, inserted if its absolute difference is larger than the root
			mh_insert(rs_id_uint, est_diff);
		}
	}
	else
	{
		// CMS depth is odd
		size_t i;
		int16_t est_diff;
		uint64_t rs_id_uint;

		for(i = 0; i < num_elems; i++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
			est_diff = cms_query_median_odd(rs_id_uint);
			if(est_diff < 0)
			{
				est_diff = est_diff * -1;
			}

			// Try to insert the element into the min heap
			// If the heap is full, inserted if its absolute difference is larger than the root
			mh_insert(rs_id_uint, est_diff);
		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}
/***** END: Enclave Count-Min-Sketch Public Interface *****/

/***** BEGIN: Enclave Count-Sketch Public Interface *****/
void enclave_init_csk()
{
	csk_init(CSK_WIDTH, CSK_DEPTH);
}

void enclave_decrypt_store_csk(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
{
	// Buffer to hold the secret key
    uint8_t sk[16];

	// Plaintext length can't be longer than the ciphertext length
	ptxt = (uint8_t*) malloc(sizeof(uint8_t) * ciphertext_len);

	// Internal Enclave function to fetch the secret key
    enclave_getkey(sk);

	// Decrypt the ciphertext, place it inside the plaintext buffer and return the true length of the plaintext
    ptxt_len = enclave_decrypt(ciphertext, ciphertext_len, sk, ptxt);
}

void enclave_clear_csk(sgx_ra_context_t ctx)
{
	free(ptxt);
}

void enclave_update_csk(sgx_ra_context_t ctx, uint32_t thread_num)
{
	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = ptxt_len / 4;

	// Get the meta information first
	uint32_t patient_status = ((uint32_t*) ptxt) [0];
	uint32_t num_het_start = ((uint32_t*) ptxt) [1];

	// Sign is +1 for case and -1 for control
	int16_t sign = 1;
	if(patient_status == 0)
	{
		sign = -1;
	}

	// Update the current row of the CSK
	int16_t count = ALLELE_HOMOZYGOUS * sign;
	int16_t count_;
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[thread_num << 1], m_csk->seeds[(thread_num << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[(thread_num + m_csk->depth) << 1], m_csk->seeds[((thread_num + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

		if(m_csk->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_csk->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_csk->sketch[thread_num][pos] = m_csk->sketch[thread_num][pos] + count;
	}

	count = ALLELE_HETEROZYGOUS * sign;
	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[thread_num << 1], m_csk->seeds[(thread_num << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = csk_cal_hash(rs_id_uint, m_csk->seeds[(thread_num + m_csk->depth) << 1], m_csk->seeds[((thread_num + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

		if(m_csk->sketch[thread_num][pos] >= HASH_MAX && count > 0)
		{
			continue;
		}

		if(m_csk->sketch[thread_num][pos] <= HASH_MIN && count < 0)
		{
			continue;
		}

		m_csk->sketch[thread_num][pos] = m_csk->sketch[thread_num][pos] + count;
	}
}

void enclave_decrypt_update_csk(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = plaintext_len / 4;

	// Get the meta information first
	uint32_t patient_status = ((uint32_t*) plaintext) [0];
	uint32_t num_het_start = ((uint32_t*) plaintext) [1];

	// Sign is +1 for case and -1 for control
	int16_t sign = 1;
	if(patient_status == 0)
	{
		sign = -1;
	}

	// Update the CSK for every element
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		csk_update_var(rs_id_uint, ALLELE_HOMOZYGOUS * sign);

	}

	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		csk_update_var(rs_id_uint, ALLELE_HETEROZYGOUS * sign);

	}

	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_decrypt_query_csk(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = plaintext_len / 4;

	// Get the CSK depth
	uint32_t csk_depth = m_csk->depth;

	// Query the CSK for every element
	if(csk_depth % 2 == 0)
	{
		// CSK depth is even
		size_t i;
		int16_t est_diff;
		uint64_t rs_id_uint;

		for(i = 0; i < num_elems; i++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
			est_diff = csk_query_median_even(rs_id_uint);
			if(est_diff < 0)
			{
				est_diff = est_diff * -1;
			}

			// Try to insert the element into the min heap
			// Updated if already in
			// If the heap is full, inserted if its absolute difference is larger than the root
			mh_insert(rs_id_uint, est_diff);
		}
	}
	else
	{
		// CSK depth is odd
		size_t i;
		int16_t est_diff;
		uint64_t rs_id_uint;

		for(i = 0; i < num_elems; i++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
			est_diff = csk_query_median_odd(rs_id_uint);
			if(est_diff < 0)
			{
				est_diff = est_diff * -1;
			}

			// Try to insert the element into the min heap
			// Updated if already in
			// If the heap is full, inserted if its absolute difference is larger than the root
			mh_insert(rs_id_uint, est_diff);
		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}
/***** END: Enclave Count-Sketch Public Interface *****/
	
/***** BEGIN: Enclave Open-Addressing Hash Table Public Interface *****/
void enclave_init_oa()
{
	oa_allocate_table(OA_INIT_CAPACITY);
}

void enclave_decrypt_process_oa(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = plaintext_len / 4;

	// Get the meta-information first
	uint32_t patient_status = ((uint32_t*) plaintext) [0];
	uint32_t het_start_idx = ((uint32_t*) plaintext) [1];

	size_t i;
	for(i = 2; i < het_start_idx + 2; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		int32_t index = oa_find(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			if(patient_status == 1)
			{
				oaht->buffer[index].case_count = oaht->buffer[index].case_count + 2;
			}
			else
			{
				oaht->buffer[index].control_count = oaht->buffer[index].control_count + 2;
			}
		}
		else
		{
			if(patient_status == 1)
			{
				oa_insert(elem_id, 2, 1);
			}
			else
			{
				oa_insert(elem_id, 2, 0);
			}
		}
	}

	for(i = het_start_idx + 2; i < num_elems; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		int32_t index = oa_find(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			if(patient_status == 1)
			{
				oaht->buffer[index].case_count = oaht->buffer[index].case_count + 1;
			}
			else
			{
				oaht->buffer[index].control_count = oaht->buffer[index].control_count + 1;
			}
		}
		else
		{
			if(patient_status == 1)
			{
				oa_insert(elem_id, 1, 1);
			}
			else
			{
				oa_insert(elem_id, 1, 0);
			}
		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}
/***** END: Enclave Open-Addressing Hash Table Public Interface *****/

/***** BEGIN: Enclave Robin-Hood Hash Table Public Interface *****/
void enclave_init_rhht()
{
	allocate_table(RHHT_INIT_CAPACITY);
}

void enclave_decrypt_process_rhht(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = plaintext_len / 4;

	// Get the meta-information first
	uint32_t patient_status = ((uint32_t*) plaintext) [0];
	uint32_t het_start_idx = ((uint32_t*) plaintext) [1];

	size_t i;
	for(i = 2; i < het_start_idx + 2; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		int32_t index = find(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			if(patient_status == 1)
			{
				rhht_snp_table->buffer[index].case_count = rhht_snp_table->buffer[index].case_count + 2;
			}
			else
			{
				rhht_snp_table->buffer[index].control_count = rhht_snp_table->buffer[index].control_count + 2;
			}
		}
		else
		{
			if(patient_status == 1)
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

		int32_t index = find(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			if(patient_status == 1)
			{
				rhht_snp_table->buffer[index].case_count = rhht_snp_table->buffer[index].case_count + 1;
			}
			else
			{
				rhht_snp_table->buffer[index].control_count = rhht_snp_table->buffer[index].control_count + 1;
			}
		}
		else
		{
			if(patient_status == 1)
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
/***** END: Enclave Robin-Hood Hash Table Public Interface *****/

/***** BEGIN: Enclave Chained-Move-to-Front Hash Table Public Interface *****/
void enclave_init_cmtf()
{
	cmtf_allocate_table(CMTF_NUM_BUCKETS);
}

void enclave_decrypt_process_cmtf(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len, uint32_t type)// uint32_t chunk_num)
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

	// Since each ID in our dataset is a 4-byte unsigned integer, we can get the number of elements
	uint32_t num_elems = plaintext_len / 4;

	size_t i;
	uint32_t het_start_idx = ((uint32_t*) plaintext) [1];
	for(i = 2; i < het_start_idx + 2; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		// Compute the hash of the SNP-ID
		uint32_t hash = elem_id & ((cmtf_snp_table->num_buckets) - 1);

		// Linked List search and update with move-to-front
		struct node** head_ptr = &(cmtf_snp_table->buckets[hash]);
		struct node* temp = *head_ptr;
		struct node* prev = *head_ptr;

		// Empty bucket, initialize and insert
		if(*head_ptr == NULL)
		{
			struct node* new_elem = (struct node*) malloc(sizeof(struct node));
			new_elem->key = elem_id;
			if(type == 1)
			{
				new_elem->case_count = 2;
			}
			else
			{
				new_elem->control_count = 2;
			}
			new_elem->next = NULL;
			*head_ptr = new_elem;

			cmtf_snp_table->num_buckets_used = cmtf_snp_table->num_buckets_used + 1;
			cmtf_snp_table->num_elements = cmtf_snp_table->num_elements + 1;
			continue;
		}

		// Non-empty bucket, search for the element with the given key
		// Update if found and move-to-front
		uint8_t elem_found = 0;
		while(temp != NULL)
		{
			if(temp->key == elem_id)
			{
				if(type == 1)
				{
					temp->case_count = temp->case_count + 2;
				}
				else
				{
					temp->control_count = temp->control_count + 2;
				}

				if(temp != *head_ptr)
				{
					prev->next = temp->next;
					temp->next = *head_ptr;
					*head_ptr = temp;
				}
				elem_found = 1;
				break;
			}
			else
			{
				prev = temp;
				temp = temp->next;
			}
		}

		if(elem_found)
		{
			continue;
		}

		// Reached the end of the chain, element not found
		// Initialize new element and insert to the front of the list
		struct node* new_elem = (struct node*) malloc(sizeof(struct node));
		new_elem->key = elem_id;
		if(type == 1)
		{
			new_elem->case_count = 2;
		}
		else
		{
			new_elem->control_count = 2;
		}
		new_elem->next = *head_ptr;
		*head_ptr = new_elem;
		cmtf_snp_table->num_elements = cmtf_snp_table->num_elements + 1;
	}

	for(i = het_start_idx + 2; i < num_elems; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		// Compute the hash of the SNP-ID
		uint32_t hash = elem_id & ((cmtf_snp_table->num_buckets) - 1);

		// Linked List search and update with move-to-front
		struct node** head_ptr = &(cmtf_snp_table->buckets[hash]);
		struct node* temp = *head_ptr;
		struct node* prev = *head_ptr;

		// Empty bucket, initialize and insert
		if(*head_ptr == NULL)
		{
			struct node* new_elem = (struct node*) malloc(sizeof(struct node));
			new_elem->key = elem_id;
			if(type == 1)
			{
				new_elem->case_count = 1;
			}
			else
			{
				new_elem->control_count = 1;
			}
			new_elem->next = NULL;
			*head_ptr = new_elem;

			cmtf_snp_table->num_buckets_used = cmtf_snp_table->num_buckets_used + 1;
			cmtf_snp_table->num_elements = cmtf_snp_table->num_elements + 1;
			continue;
		}

		// Non-empty bucket, search for the element with the given key
		// Update if found and move-to-front
		uint8_t elem_found = 0;
		while(temp != NULL)
		{
			if(temp->key == elem_id)
			{
				if(type == 1)
				{
					temp->case_count = temp->case_count + 1;
				}
				else
				{
					temp->control_count = temp->control_count + 1;
				}

				if(temp != *head_ptr)
				{
					prev->next = temp->next;
					temp->next = *head_ptr;
					*head_ptr = temp;
				}
				elem_found = 1;
				break;
			}
			else
			{
				prev = temp;
				temp = temp->next;
			}
		}

		if(elem_found)
		{
			continue;
		}

		// Reached the end of the chain, element not found
		// Initialize new element and insert to the front of the list
		struct node* new_elem = (struct node*) malloc(sizeof(struct node));
		new_elem->key = elem_id;
		if(type == 1)
		{
			new_elem->case_count = 1;
		}
		else
		{
			new_elem->control_count = 1;
		}
		new_elem->next = *head_ptr;
		*head_ptr = new_elem;
		cmtf_snp_table->num_elements = cmtf_snp_table->num_elements + 1;
	}
}

/***** END: Enclave Chained-Move-to-Front Hash Table Public Interface *****/

/***** BEGIN: Enclave Chi-Squared Test Functions *****/

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
	uint16_t case_maj = case_total - case_min;
	uint16_t control_maj = control_total - control_min;
	uint16_t pop_total = case_total + control_total;

	// Compute the observed frequencies
	float case_maj_f = (float) case_maj / pop_total;
	float case_min_f = (float) case_min / pop_total;
	float control_maj_f = (float) control_maj / pop_total;
	float control_min_f = (float) control_min / pop_total;
	float obs_freq[4];
	obs_freq[0] = case_maj_f;
	obs_freq[1] = case_min_f;
	obs_freq[2] = control_maj_f;
	obs_freq[3] = control_min_f;

	// Compute expected frequencies
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

	// Compute expected counts
	float exp_count[4];
	exp_count[0] = exp_freq[0] * pop_total;
	exp_count[1] = exp_freq[1] * pop_total;
	exp_count[2] = exp_freq[2] * pop_total;
	exp_count[3] = exp_freq[3] * pop_total;

	// Compute the Chi-Squared Value
	float chi_sq_val = 0;
	chi_sq_val = chi_sq_val + ((case_maj - exp_count[0]) * (case_maj - exp_count[0]) / exp_count[0]);
	chi_sq_val = chi_sq_val + ((case_min - exp_count[1]) * (case_min - exp_count[1]) / exp_count[1]);
	chi_sq_val = chi_sq_val + ((control_maj - exp_count[2]) * (control_maj - exp_count[2]) / exp_count[2]);
	chi_sq_val = chi_sq_val + ((control_min - exp_count[3]) * (control_min - exp_count[3]) / exp_count[3]);

	return chi_sq_val;
}

void rhht_init_chi_sq(uint16_t case_total, uint16_t control_total)
{
	uint32_t top_k_ids[10];
	float top_k_chi_sq[10];
	uint8_t num_used = 0;
	float chi_sq_val;
	for(uint32_t i = 0; i < rhht_snp_table->capacity; i++)
	{
		if(rhht_snp_table->buffer[i].key != 0)
		{
			// Calculate the chi squared value
			chi_sq_val = chi_sq(rhht_snp_table->buffer[i].case_count, rhht_snp_table->buffer[i].control_count, case_total, control_total);

			// If the top-k array is not full, add current snp without any checks
			if(num_used < 10)
			{
				top_k_ids[num_used] = rhht_snp_table->buffer[i].key;
				top_k_chi_sq[num_used] = chi_sq_val;
				num_used = num_used + 1;
			}
			else
			{
				// Find the index of the minimum chi squared value in the top-k array
				uint8_t index_min = 0;
				for(uint8_t j = 1; j < 10; j++)
				{
					if(top_k_chi_sq[j] < top_k_chi_sq[index_min])
					{
						index_min = j;
					}
				}

				// If the chi squared value of the current element is greater than that of index min, replace
				if(chi_sq_val > top_k_chi_sq[index_min])
				{
					top_k_ids[index_min] = rhht_snp_table->buffer[i].key;
					top_k_chi_sq[index_min] = chi_sq_val;
				}
			}
		}
	}
	
	for(uint8_t i = 0; i < 10; i++)
	{
		double pval = pochisq((double) top_k_chi_sq[i]);

		// Proper output test
		//enclave_res_buf[i] = top_k_ids[i];
	}
}

void cmtf_init_chi_sq(uint16_t case_total, uint16_t control_total)
{
	uint32_t top_k_ids[10];
	float top_k_chi_sq[10];
	uint8_t num_used = 0;
	float chi_sq_val;
	for(uint32_t i = 0; i < cmtf_snp_table->num_buckets; i++)
	{
		if(cmtf_snp_table->buckets[i] != NULL)
		{
			struct node* temp = cmtf_snp_table->buckets[i];
			while(temp != NULL)
			{
				// Calculate the chi squared value
				chi_sq_val = chi_sq(temp->case_count, temp->control_count, case_total, control_total);

				// If the top-k array is not full, add current snp without any checks
				if(num_used < 10)
				{
					top_k_ids[num_used] = temp->key;
					top_k_chi_sq[num_used] = chi_sq_val;
					num_used = num_used + 1;
				}
				else
				{
					// Find the index of the minimum chi squared value in the top-k array
					uint8_t index_min = 0;
					for(uint8_t j = 1; j < 10; j++)
					{
						if(top_k_chi_sq[j] < top_k_chi_sq[index_min])
						{
							index_min = j;
						}
					}

					// If the chi squared value of the current element is greater than that of index min, replace
					if(chi_sq_val > top_k_chi_sq[index_min])
					{
						top_k_ids[index_min] = temp->key;
						top_k_chi_sq[index_min] = chi_sq_val;
					}
				}
				temp = temp->next;
			}
		}
	}

	for(uint8_t i = 0; i < 10; i++)
	{
		double pval = pochisq((double) top_k_chi_sq[i]);

		// Proper output test
		//enclave_res_buf[i] = top_k_ids[i];
	}
}

void oa_init_chi_sq(uint16_t case_total, uint16_t control_total)
{
	uint32_t top_k_ids[10];
	float top_k_chi_sq[10];
	uint8_t num_used = 0;
	float chi_sq_val;
	for(uint32_t i = 0; i < oaht->capacity; i++)
	{
		if(oaht->buffer[i].key != 0)
		{
			// Calculate the chi squared value
			chi_sq_val = chi_sq(oaht->buffer[i].case_count, oaht->buffer[i].control_count, case_total, control_total);

			// If the top-k array is not full, add current snp without any checks
			if(num_used < 10)
			{
				top_k_ids[num_used] = oaht->buffer[i].key;
				top_k_chi_sq[num_used] = chi_sq_val;
				num_used = num_used + 1;
			}
			else
			{
				// Find the index of the minimum chi squared value in the top-k array
				uint8_t index_min = 0;
				for(uint8_t j = 1; j < 10; j++)
				{
					if(top_k_chi_sq[j] < top_k_chi_sq[index_min])
					{
						index_min = j;
					}
				}

				// If the chi squared value of the current element is greater than that of index min, replace
				if(chi_sq_val > top_k_chi_sq[index_min])
				{
					top_k_ids[index_min] = oaht->buffer[i].key;
					top_k_chi_sq[index_min] = chi_sq_val;
				}
			}
		}
	}
	for(uint8_t i = 0; i < 10; i++)
	{
		double pval = pochisq((double) top_k_chi_sq[i]);

		// Proper output test
		//enclave_res_buf[i] = top_k_ids[i];
	}
}
/***** END: Enclave Chi-Sqaured Test Functions *****/

/***** BEGIN: Enclave Min-Heap Public ECALL Interface *****/
void enclave_init_mh()
{
	allocate_heap(MH_INIT_CAPACITY);
}
/***** END: Enclave Min-Heap Public ECALL Interface *****/

/***** BEGIN: Enclave Result/Output Public ECALL Interface *****/
void enclave_get_res(uint32_t* res)
{
	for(size_t i = 0; i < mh->curr_heap_size; i++)
	{
		res[i] = mh->mh_array[i].key;
	}
}
/***** END: Enclave Result/Output Public ECALL Interface *****/
