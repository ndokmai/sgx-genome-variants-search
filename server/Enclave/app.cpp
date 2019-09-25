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
#include "enclave_mcsk.h"
#include "svd.h"
#include "util.h"

#define ALLELE_HETEROZYGOUS	1
#define	ALLELE_HOMOZYGOUS	2

#define L1_CACHE_SIZE		(1 << 14)
#define	L2_CACHE_SIZE		(1 << 17)
#define	PARTITION_SIZE		(1 << 18)

// Global Enclave Buffers and Variables
//For testing the SVD correctness
//float enclave_mcsk_buf[2001];
float enclave_eig_buf[8000];
//float ortho_res[6];
uint8_t *ptxt;
uint32_t ptxt_len;
uint32_t file_idx = 0;
float *phenotypes;
float *u;
float **enclave_eig;
uint32_t *enc_id_buf = NULL;
float *enc_res_buf = NULL;
float *enc_temp_buf = NULL;
int cms_st_length_inflation = 0;
int MCSK_WIDTH = 0;
int MCSK_DEPTH = 0;
int MCSK_NUM_PC = 0;
//int test = 0;

void enclave_reset_file_idx()
{
	file_idx = 0;
}

/*void mcsk_pull_row()
{
	for(size_t  i = 0 ; i < 2001; i++)
	{
		enclave_mcsk_buf[i] = m_mcsk->msketchf[0][i];
	}
}*/

void enclave_init_mcsk(int MCSK_WIDTH, int MCSK_NUM_PC, float MCSK_EPS)
{
	mcsk_init(MCSK_WIDTH, MCSK_NUM_PC, MCSK_EPS);
	phenotypes = (float*) malloc(MCSK_WIDTH * sizeof(float));
}

void enclave_decrypt_update_mcsk(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Set initial phenotype
	phenotypes[file_idx] = -1.0;
	if(patient_status == 0)
	{
		phenotypes[file_idx] = 1.0;
	}

	// Update the MCSK for every element
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		mcsk_update_var(rs_id_uint, file_idx, 2.0);
	}

	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		mcsk_update_var(rs_id_uint, file_idx, 1.0);
	}

	// We've processed the data, now clear it
	delete[] plaintext;

	// Increment column number
	file_idx = file_idx + 1;
}

void enclave_mcsk_mean_centering()
{
	mcsk_mean_centering();
}

void enclave_svd()
{
	MCSK_WIDTH = m_mcsk->m;
	MCSK_DEPTH = m_mcsk->depth;
	MCSK_NUM_PC = m_mcsk->k;
	float** A = getmsk();
	u = (float*) malloc(MCSK_WIDTH * sizeof(float));

	if (MCSK_WIDTH < MCSK_DEPTH) 
	{
		float* S = (float*) malloc(MCSK_WIDTH * sizeof(float));
		float** Q = (float**) malloc(MCSK_WIDTH * sizeof(float*));
		for(size_t i = 0; i < MCSK_WIDTH; i++)
		{
			Q[i] = (float*) malloc(MCSK_WIDTH * sizeof(float));
		}

		// Compute SVD A = USV^T; V stored in Q
		int retval = svdcomp_t(A, MCSK_DEPTH, MCSK_WIDTH, S, Q);

		// Copy k rows of Q to A.
		for (int i = 0; i < MCSK_NUM_PC; i++)
		{
			memcpy(A[i], Q[i], MCSK_WIDTH * sizeof(float));
		}
		
		// Compute VV^T * phenotype vector and VV^T * all one vector
		memset(A[MCSK_NUM_PC], 0, MCSK_WIDTH * sizeof(float));
		matrix_ortho_proj(A, phenotypes, A[MCSK_NUM_PC], MCSK_NUM_PC, MCSK_WIDTH);
		for(size_t i = 0; i < MCSK_WIDTH; i++)
		{
			// Should be replaced by daxpy
			A[MCSK_NUM_PC][i] = phenotypes[i] - A[MCSK_NUM_PC][i];
			u[i] = 1.0;
		}
		memcpy(phenotypes, A[MCSK_NUM_PC], MCSK_WIDTH * sizeof(float));
		memset(A[MCSK_NUM_PC + 1], 0, MCSK_WIDTH * sizeof(float));
		matrix_ortho_proj(A, u, A[MCSK_NUM_PC + 1], MCSK_NUM_PC, MCSK_WIDTH);
		memcpy(u, A[MCSK_NUM_PC + 1], MCSK_WIDTH * sizeof(float));
		
		// Free allocated memories
		for (int i = 0; i < MCSK_WIDTH; i++)
		{
			free(Q[i]);
		}
		free(Q);
		free(S);
	}
	else 
	{
		float* S = (float*) malloc(MCSK_DEPTH * sizeof(float));
		float** Q = (float**) malloc(MCSK_DEPTH * sizeof(float*));
		for(size_t i = 0; i < MCSK_DEPTH; i++)
		{
			Q[i] = (float*) malloc(MCSK_DEPTH * sizeof(float));
		}

		// Compute SVD A = USV^T; V stored in Q
		int retval = svdcomp_a(A, MCSK_WIDTH, MCSK_DEPTH, S, Q);

		// Compute VV^T * phenotype vector and VV^T * all one vector
		memset(A[MCSK_NUM_PC], 0, MCSK_WIDTH * sizeof(float));
		matrix_ortho_proj(A, phenotypes, A[MCSK_NUM_PC], MCSK_NUM_PC, MCSK_WIDTH);
		for(size_t i = 0; i < MCSK_WIDTH; i++)
		{
			// Should be replaced by daxpy
			A[MCSK_NUM_PC][i] = phenotypes[i] - A[MCSK_NUM_PC][i];
			u[i] = 1.0;
		}
		memcpy(phenotypes, A[MCSK_NUM_PC], MCSK_WIDTH * sizeof(float));
		memset(A[MCSK_NUM_PC + 1], 0, MCSK_WIDTH * sizeof(float));
		matrix_ortho_proj(A, u, A[MCSK_NUM_PC + 1], MCSK_NUM_PC, MCSK_WIDTH);
		memcpy(u, A[MCSK_NUM_PC + 1], MCSK_WIDTH * sizeof(float));

		// Free allocated memories
		for (int i = 0; i < MCSK_DEPTH; i++)
		{
			free(Q[i]);
		}
		free(Q);
		free(S);
	}

	// Keep only the first k rows of V, now stroed in the first k rows of A
	enclave_eig = (float**) malloc(MCSK_NUM_PC * sizeof(float*));
	for(int pc = 0; pc < MCSK_NUM_PC; pc++)
	{
		enclave_eig[pc] = (float*) malloc(MCSK_WIDTH * sizeof(float));
		memcpy(enclave_eig[pc], A[pc], MCSK_WIDTH * sizeof(float));
	}

	// Free the sketch matrix
	mcsk_free();
	free(m_mcsk);
}

sgx_status_t ecall_thread_cms(int thread_num, int nrows_per_thread)
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

		uint32_t hash;
		uint32_t pos;
		uint32_t row;

		if(thread_num == 0)
		{
			m_cms->st_length = m_cms->st_length + count;
		}
		
		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_cms->seeds[row << 1], m_cms->seeds[(row << 1) + 1]);
			pos = hash & m_cms->width_minus_one;

			if(m_cms->sketch[row][pos] >= HASH_MAX_16 && count > 0)
			{
				continue;
			}

			if(m_cms->sketch[row][pos] <= HASH_MIN_16 && count < 0)
			{
				continue;
			}

			m_cms->sketch[row][pos] = m_cms->sketch[row][pos] + count;
		}
	}

	count = ALLELE_HETEROZYGOUS * sign;

	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;
		uint32_t row;

		if(thread_num == 0)
		{
			m_cms->st_length = m_cms->st_length + count;
		}

		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_cms->seeds[row << 1], m_cms->seeds[(row << 1) + 1]);
			pos = hash & m_cms->width_minus_one;

			if(m_cms->sketch[row][pos] >= HASH_MAX_16 && count > 0)
			{
				continue;
			}

			if(m_cms->sketch[row][pos] <= HASH_MIN_16 && count < 0)
			{
				continue;
			}

			m_cms->sketch[row][pos] = m_cms->sketch[row][pos] + count;
		}
	}
	return SGX_SUCCESS;
}

sgx_status_t ecall_thread_cms_ca(int thread_num, int nrows_per_thread, int part_num)
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

	// Update the current row of the CMS for the given partition
	int16_t count = ALLELE_HOMOZYGOUS * sign;
	size_t i;
	uint64_t rs_id_uint;

	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;
		uint32_t row;

		if(thread_num == 0)
		{
			m_cms->st_length = m_cms->st_length + count;
		}

		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_cms->seeds[row << 1], m_cms->seeds[(row << 1) + 1]);
			pos = hash & m_cms->width_minus_one;

			if(pos >= (part_num * PARTITION_SIZE) && pos < ((part_num + 1) * PARTITION_SIZE))
			{

				if(m_cms->sketch[row][pos] >= HASH_MAX_16 && count > 0)
				{
					continue;
				}

				if(m_cms->sketch[row][pos] <= HASH_MIN_16 && count < 0)
				{
					continue;
				}

				m_cms->sketch[row][pos] = m_cms->sketch[row][pos] + count;
			}
		}
	}

	count = ALLELE_HETEROZYGOUS * sign;
	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;
		uint32_t row;

		if(thread_num == 0)
		{
			m_cms->st_length = m_cms->st_length + count;
		}

		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_cms->seeds[row << 1], m_cms->seeds[(row << 1) + 1]);
			pos = hash & m_cms->width_minus_one;

			if(pos >= (part_num * PARTITION_SIZE) && pos < ((part_num + 1) * PARTITION_SIZE))
			{
				if(m_cms->sketch[row][pos] >= HASH_MAX_16 && count > 0)
				{
					continue;
				}

				if(m_cms->sketch[row][pos] <= HASH_MIN_16 && count < 0)
				{
					continue;
				}

				m_cms->sketch[row][pos] = m_cms->sketch[row][pos] + count;
			}
		}
	}
	return SGX_SUCCESS;
}

sgx_status_t ecall_thread_csk(int thread_num, int nrows_per_thread)
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
		uint32_t row;

		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_csk->seeds[row << 1], m_csk->seeds[(row << 1) + 1]);
			pos = hash & m_csk->width_minus_one;

			hash = cal_hash(rs_id_uint, m_csk->seeds[(row + m_csk->depth) << 1], 
					m_csk->seeds[((row + m_csk->depth) << 1) + 1]);
			count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

			if(m_csk->sketch[row][pos] >= HASH_MAX_16 && count_ > 0)
			{
				continue;
			}

			if(m_csk->sketch[row][pos] <= HASH_MIN_16 && count_ < 0)
			{
				continue;
			}

			m_csk->sketch[row][pos] = m_csk->sketch[row][pos] + count_;
		}
	}

	count = ALLELE_HETEROZYGOUS * sign;
	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;
		uint32_t row;

		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_csk->seeds[row << 1], m_csk->seeds[(row << 1) + 1]);
			pos = hash & m_csk->width_minus_one;

			hash = cal_hash(rs_id_uint, m_csk->seeds[(row+ m_csk->depth) << 1], 
					m_csk->seeds[((row + m_csk->depth) << 1) + 1]);
			count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

			if(m_csk->sketch[row][pos] >= HASH_MAX_16 && count_ > 0)
			{
				continue;
			}

			if(m_csk->sketch[row][pos] <= HASH_MIN_16 && count_ < 0)
			{
				continue;
			}

			m_csk->sketch[row][pos] = m_csk->sketch[row][pos] + count_;
		}
	}

	return SGX_SUCCESS;
}

sgx_status_t ecall_thread_csk_ca(int thread_num, int nrows_per_thread, int part_num)
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
		uint32_t row;

		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_csk->seeds[row << 1], m_csk->seeds[(row << 1) + 1]);
			pos = hash & m_csk->width_minus_one;

			hash = cal_hash(rs_id_uint, m_csk->seeds[(row + m_csk->depth) << 1], 
					m_csk->seeds[((row + m_csk->depth) << 1) + 1]);
			count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

			if(pos >= (part_num * PARTITION_SIZE) && pos < ((part_num + 1) * PARTITION_SIZE))
			{
				if(m_csk->sketch[row][pos] >= HASH_MAX_16 && count_ > 0)
				{
					continue;
				}

				if(m_csk->sketch[row][pos] <= HASH_MIN_16 && count_ < 0)
				{
					continue;
				}

				m_csk->sketch[row][pos] = m_csk->sketch[row][pos] + count_;
			}
		}
	}

	count = ALLELE_HETEROZYGOUS * sign;
	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) ptxt) [i];

		uint32_t hash;
		uint32_t pos;
		uint32_t row;

		for(int j = 0; j < nrows_per_thread; j++)
		{
			row = thread_num * nrows_per_thread + j;
			hash = cal_hash(rs_id_uint, m_csk->seeds[row << 1], m_csk->seeds[(row << 1) + 1]);
			pos = hash & m_csk->width_minus_one;

			hash = cal_hash(rs_id_uint, m_csk->seeds[(row+ m_csk->depth) << 1], 
					m_csk->seeds[((row + m_csk->depth) << 1) + 1]);
			count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

			if(pos >= (part_num * PARTITION_SIZE) && pos < ((part_num + 1) * PARTITION_SIZE))
			{

				if(m_csk->sketch[row][pos] >= HASH_MAX_16 && count_ > 0)
				{
					continue;
				}

				if(m_csk->sketch[row][pos] <= HASH_MIN_16 && count_ < 0)
				{
					continue;
				}

				m_csk->sketch[row][pos] = m_csk->sketch[row][pos] + count_;
			}
		}
	}

	return SGX_SUCCESS;
}

/***** BEGIN: SNP Ranking Using Sketch and RHHT *****/
void enclave_init_sketch_rhht(int MH_INIT_CAPACITY)
{
	// Allocate enclave Robin-Hood hash table
	// TODO: Allow growing (currently not)
	allocate_table(MH_INIT_CAPACITY * 2);

	// Insert keys, initialize allele counts to be 0
	size_t i;
	for(i = 0; i < MH_INIT_CAPACITY; i++)
	{
		// NOTE: Setting allele_type to 0 is normally meaningless, this is a hack.
		insert(mh->mh_array[i].key, 0, 0);
	}

	// Deallocate min heap
	free_heap();

	// Possibly outside enclave_init_sketch_rhht()
	// Deallocate sketches
}

void enclave_decrypt_process_sketch_rhht(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_init_rhht_pcc(int MH_INIT_CAPACITY)
{
	// Allocate enclave Robin-Hood hash table
	// TODO: Allow growing (currently not)
	allocate_table_pcc(MH_INIT_CAPACITY * 2, MCSK_NUM_PC);

	// Insert keys, initialize allele counts to be 0
	for(size_t i = 0; i < MH_INIT_CAPACITY; i++)
	{
		// NOTE: Setting allele_type to 0 is normally meaningless, this is a hack.
		insert_pcc(mh->mh_array_f[i].key);
	}

	// Deallocate min heap
	free_heap();

	// Possibly outside enclave_init_sketch_rhht()
	// Deallocate sketches
}

void enclave_decrypt_process_rhht_pcc(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

		int32_t index = find_pcc(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			rhht_snp_table_pcc->buffer[index].ssqg += 4;
			rhht_snp_table_pcc->buffer[index].dotprod += (phenotypes[file_idx] * 2);
			rhht_snp_table_pcc->buffer[index].sx += (2 * (1.0 - u[file_idx]));
			for(int pc = 0; pc < MCSK_NUM_PC; pc++)
			{
				rhht_snp_table_pcc->buffer[index].pc_projections[pc] += (enclave_eig[pc][file_idx] * 2);
			}
		}
	}

	for(i = het_start_idx + 2; i < num_elems; i++)
	{
		uint32_t elem_id = ((uint32_t*) plaintext) [i];

		int32_t index = find_pcc(elem_id);

		// If found, update entry based on allele type
		if(index != -1)
		{
			rhht_snp_table_pcc->buffer[index].ssqg += 1;
			rhht_snp_table_pcc->buffer[index].dotprod += phenotypes[file_idx];
			rhht_snp_table_pcc->buffer[index].sx += (1.0 - u[file_idx]);
			for(int pc = 0; pc < MCSK_NUM_PC; pc++)
			{
				rhht_snp_table_pcc->buffer[index].pc_projections[pc] += enclave_eig[pc][file_idx];
			}
		}
	}

	file_idx = file_idx + 1;
	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_decrypt_init_rhht_pcc(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Allocate enclave Robin-Hood hash table
	// TODO: Allow growing (currently not)
	allocate_table_pcc(1 << 20, MCSK_NUM_PC);

	// Insert keys, initialize allele counts to be 0
	uint32_t i;
	uint32_t rs_id_uint;
	for(i = 0; i < num_elems; i++)
	{
		rs_id_uint = ((uint32_t*) plaintext) [i];
		insert_pcc(rs_id_uint);
	}
	
	// We've processed the data, now clear it
	delete[] plaintext;
}
/**** END: SNP Ranking Using Sketch and RHHT *****/

/***** BEGIN: Enclave Count-Min-Sketch Public Interface *****/
void enclave_init_cms(int CMS_WIDTH, int CMS_DEPTH)
{
	cms_init(CMS_WIDTH, CMS_DEPTH);
	cms_st_length_inflation = CMS_DEPTH >> 2;
}

void enclave_free_cms()
{
	cms_free();
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

//
/*void enclave_update_cms(sgx_ra_context_t ctx, uint32_t thread_num)
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

		if(m_cms->sketch[thread_num][pos] >= HASH_MAX_16 && count > 0)
		{
			continue;
		}

		if(m_cms->sketch[thread_num][pos] <= HASH_MIN_16 && count < 0)
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

		if(m_cms->sketch[thread_num][pos] >= HASH_MAX_16 && count > 0)
		{
			continue;
		}

		if(m_cms->sketch[thread_num][pos] <= HASH_MIN_16 && count < 0)
		{
			continue;
		}

		m_cms->sketch[thread_num][pos] = m_cms->sketch[thread_num][pos] + count;
	}
}*/

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

	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_decrypt_update_cms_row(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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
	size_t i;
	//size_t j;
	size_t k;
	uint64_t rs_id_uint;
	//int16_t count;
	//uint32_t hash;
	//uint32_t pos;
	for(i = 0; i < m_cms->depth; i += 4)
	{
//		for(j = 0; j < (m_cms->width / PARTITION_SIZE); j++)
//		{ 
			//count = ALLELE_HOMOZYGOUS * sign;
			for(k = 2; k < num_het_start + 2; k++)
			{
				rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [k];
				cms_update_st_length(ALLELE_HOMOZYGOUS * sign);
				cms_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i);
				cms_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i + 1);
				cms_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i + 2);
				cms_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i + 3);

				/* CACHE AWARE TEST
				hash = cal_hash(rs_id_uint, m_cms->seeds[i << 1], m_cms->seeds[(i << 1) + 1]);
				pos = hash & m_cms->width_minus_one;
				if(pos > (j * PARTITION_SIZE) && pos < ((j + 1) * PARTITION_SIZE))
				{
					if(m_cms->sketch[i][pos] >= HASH_MAX && count > 0)
					{
						return;
					}

					if(m_cms->sketch[i][pos] <= HASH_MIN && count < 0)
					{
						return;
					}

					m_cms->sketch[i][pos] = m_cms->sketch[i][pos] + count;
					m_cms->st_length = m_cms->st_length + count;
				}
				*/
			}

			//count = ALLELE_HETEROZYGOUS * sign;
			for(k = num_het_start + 2; k < num_elems; k++)
			{
				rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [k];
				cms_update_st_length(ALLELE_HOMOZYGOUS * sign);
				cms_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i);
				cms_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i + 1);
				cms_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i + 2);
				cms_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i + 3);

				// CACHE AWARE TEST
				/*
				hash = cal_hash(rs_id_uint, m_cms->seeds[i << 1], m_cms->seeds[(i << 1) + 1]);
				pos = hash & m_cms->width_minus_one;
				if(pos > (j * PARTITION_SIZE) && pos < ((j + 1) * PARTITION_SIZE))
				{
					if(m_cms->sketch[i][pos] >= HASH_MAX && count > 0)
					{
						return;
					}

					if(m_cms->sketch[i][pos] <= HASH_MIN && count < 0)
					{
						return;
					}

					m_cms->sketch[i][pos] = m_cms->sketch[i][pos] + count;
					m_cms->st_length = m_cms->st_length + count;
				}
				*/
			}
//		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_normalize_cms_st_length()
{
	cms_normalize_st_length(cms_st_length_inflation);
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

			/*if(test_i < 10)
			{
				enc_temp_buf[test_i] = est_diff;
				test_i++;
			}*/
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
void enclave_init_csk(int CSK_WIDTH, int CSK_DEPTH)
{
	csk_init(CSK_WIDTH, CSK_DEPTH);
}

void enclave_init_csk_f(int CSK_WIDTH, int CSK_DEPTH)
{
	csk_init_f(CSK_WIDTH, CSK_DEPTH);
}

void enclave_free_csk()
{
	csk_free();
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

		hash = cal_hash(rs_id_uint, m_csk->seeds[thread_num << 1], m_csk->seeds[(thread_num << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = cal_hash(rs_id_uint, m_csk->seeds[(thread_num + m_csk->depth) << 1], m_csk->seeds[((thread_num + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

		if(m_csk->sketch[thread_num][pos] >= HASH_MAX_16 && count > 0)
		{
			continue;
		}

		if(m_csk->sketch[thread_num][pos] <= HASH_MIN_16 && count < 0)
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

		hash = cal_hash(rs_id_uint, m_csk->seeds[thread_num << 1], m_csk->seeds[(thread_num << 1) + 1]);
		pos = hash & m_csk->width_minus_one;

		hash = cal_hash(rs_id_uint, m_csk->seeds[(thread_num + m_csk->depth) << 1], m_csk->seeds[((thread_num + m_csk->depth) << 1) + 1]);
		count_ = (((hash & 0x1) == 0) ? -1 : 1) * count;

		if(m_csk->sketch[thread_num][pos] >= HASH_MAX_16 && count > 0)
		{
			continue;
		}

		if(m_csk->sketch[thread_num][pos] <= HASH_MIN_16 && count < 0)
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

void enclave_decrypt_update_csk_row(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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
	size_t i;
	//size_t j;
	size_t k;
	uint64_t rs_id_uint;
	//int16_t count;
	//uint32_t hash;
	//uint32_t pos;
	for(i = 0; i < m_csk->depth; i = i + 4)
	{
//		for(j = 0; j < (m_csk->width / PARTITION_SIZE); j++)
//		{ 
			//count = ALLELE_HOMOZYGOUS * sign;
			for(k = 2; k < num_het_start + 2; k++)
			{
				rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [k];
				csk_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i);
				csk_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i + 1);
				csk_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i + 2);
				csk_update_var_row(rs_id_uint, ALLELE_HOMOZYGOUS * sign, i + 3);

				/* CACHE AWARE TEST
				hash = cal_hash(rs_id_uint, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
				pos = hash & m_csk->width_minus_one;
				if(pos > (j * PARTITION_SIZE) && pos < ((j + 1) * PARTITION_SIZE))
				{
					if(m_csk->sketch[i][pos] >= HASH_MAX && count > 0)
					{
						return;
					}

					if(m_csk->sketch[i][pos] <= HASH_MIN && count < 0)
					{
						return;
					}

					m_csk->sketch[i][pos] = m_csk->sketch[i][pos] + count;
					m_csk->st_length = m_csk->st_length + count;
				}
				*/
			}

			//count = ALLELE_HETEROZYGOUS * sign;
			for(k = num_het_start + 2; k < num_elems; k++)
			{
				rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [k];
				csk_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i);
				csk_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i + 1);
				csk_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i + 2);
				csk_update_var_row(rs_id_uint, ALLELE_HETEROZYGOUS * sign, i + 3);

				// CACHE AWARE TEST
				/*
				hash = cal_hash(rs_id_uint, m_csk->seeds[i << 1], m_csk->seeds[(i << 1) + 1]);
				pos = hash & m_csk->width_minus_one;
				if(pos > (j * PARTITION_SIZE) && pos < ((j + 1) * PARTITION_SIZE))
				{
					if(m_csk->sketch[i][pos] >= HASH_MAX && count > 0)
					{
						return;
					}

					if(m_csk->sketch[i][pos] <= HASH_MIN && count < 0)
					{
						return;
					}

					m_csk->sketch[i][pos] = m_csk->sketch[i][pos] + count;
					m_csk->st_length = m_csk->st_length + count;
				}
				*/
			}
//		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_decrypt_update_csk_f(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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

	// Update the CSK for every element
	size_t i;
	uint64_t rs_id_uint;
	for(i = 2; i < num_het_start + 2; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		csk_update_var_f(rs_id_uint, ALLELE_HOMOZYGOUS * phenotypes[file_idx]);
	}

	for(i = num_het_start + 2; i < num_elems; i++)
	{
		rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
		csk_update_var_f(rs_id_uint, ALLELE_HETEROZYGOUS * phenotypes[file_idx]);
	}

	// We've processed the data, now clear it
	delete[] plaintext;

	file_idx = file_idx + 1;
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

void enclave_decrypt_query_csk_f(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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
		float est_diff;
		uint64_t rs_id_uint;

		for(i = 0; i < num_elems; i++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
			
			est_diff = csk_query_median_even_f(rs_id_uint);
			if(est_diff < 0)
			{
				est_diff = -est_diff;
			}

			// Try to insert the element into the min heap
			// Updated if already in
			// If the heap is full, inserted if its absolute difference is larger than the root
			mh_insert_f(rs_id_uint, est_diff);
		}
	}
	else
	{
		// CSK depth is odd
		size_t i;
		float est_diff;
		uint64_t rs_id_uint;

		for(i = 0; i < num_elems; i++)
		{
			rs_id_uint = (uint64_t) ((uint32_t*) plaintext) [i];
			est_diff = csk_query_median_odd_f(rs_id_uint);
			if(est_diff < 0)
			{
				est_diff = -est_diff;
			}

			// Try to insert the element into the min heap
			// Updated if already in
			// If the heap is full, inserted if its absolute difference is larger than the root
//			enc_id_buf[i] = rs_id_uint;
//			enc_res_buf[i] = est_diff;
			mh_insert_f(rs_id_uint, est_diff);
//			if(i == 1000)
//			{
//				break;
//			}
		}
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}
/***** END: Enclave Count-Sketch Public Interface *****/
	
/***** BEGIN: Enclave Open-Addressing Hash Table Public Interface *****/
void enclave_init_oa(int OA_INIT_CAPACITY)
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

void enclave_free_oa()
{
	oa_deallocate_table();
}
/***** END: Enclave Open-Addressing Hash Table Public Interface *****/

/***** BEGIN: Enclave Robin-Hood Hash Table Public Interface *****/
void enclave_init_rhht(int RHHT_INIT_CAPACITY)
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

void enclave_free_rhht()
{
	deallocate_table();
}
/***** END: Enclave Robin-Hood Hash Table Public Interface *****/

/***** BEGIN: Enclave Chained-Move-to-Front Hash Table Public Interface *****/
void enclave_init_cmtf(int CMTF_NUM_BUCKETS)
{
	cmtf_allocate_table(CMTF_NUM_BUCKETS);
}

void enclave_decrypt_process_cmtf(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
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
			if(patient_status == 1)
			{
				new_elem->case_count = 2;
				new_elem->control_count = 0;
			}
			else
			{
				new_elem->control_count = 2;
				new_elem->case_count = 0;
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
				if(patient_status == 1)
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
		if(patient_status == 1)
		{
			new_elem->case_count = 2;
			new_elem->control_count = 0;
		}
		else
		{
			new_elem->control_count = 2;
			new_elem->case_count = 0;
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
			if(patient_status == 1)
			{
				new_elem->case_count = 1;
				new_elem->control_count = 0;
			}
			else
			{
				new_elem->control_count = 1;
				new_elem->case_count = 0;
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
				if(patient_status == 1)
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
		if(patient_status == 1)
		{
			new_elem->case_count = 1;
			new_elem->control_count = 0;
		}
		else
		{
			new_elem->control_count = 1;
			new_elem->case_count = 0;
		}
		new_elem->next = *head_ptr;
		*head_ptr = new_elem;
		cmtf_snp_table->num_elements = cmtf_snp_table->num_elements + 1;
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}

void enclave_free_cmtf()
{
	cmtf_deallocate_table();
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

float cat_chi_sq(uint16_t ssqg, uint16_t total, float dotprod, float sx, float sy, float sy2, float *pc_projections)
{
	float chi_sq_val = 0, sx2 = 0;
	sx2 = ssqg;
	for(int pc = 0; pc < MCSK_NUM_PC; pc++)
	{
		sx2 -= (pc_projections[pc] * pc_projections[pc]);
	}
	chi_sq_val = total * dotprod - sx * sy;
	chi_sq_val = (chi_sq_val * chi_sq_val) * total / ((total * sx2 - sx * sx) * (total * sy2 - sy * sy));
	/*if(isnan(chi_sq_val) && test == 0)
	{
		enc_temp_buf[0] = ssqg;
		enc_temp_buf[1] = total;
		enc_temp_buf[2] = dotprod;
		enc_temp_buf[3] = sx;
		enc_temp_buf[4] = sy;
		enc_temp_buf[5] = sy2;
		enc_temp_buf[6] = pc_projections[0];
		enc_temp_buf[7] = pc_projections[1];
		test = 1;
	}*/
	return chi_sq_val;
}

void rhht_init_chi_sq(uint16_t case_total, uint16_t control_total, int k)
{
	int num_used = 0;
	float chi_sq_val;
	for(uint32_t i = 0; i < rhht_snp_table->capacity; i++)
	{
		if(rhht_snp_table->buffer[i].key != 0)
		{
			// Calculate the chi squared value
			chi_sq_val = chi_sq(rhht_snp_table->buffer[i].case_count, rhht_snp_table->buffer[i].control_count, case_total, control_total);

			// If the top-k array is not full, add current snp without any checks
			if(num_used < k)
			{
				enc_id_buf[num_used] = rhht_snp_table->buffer[i].key;
				enc_res_buf[num_used] = chi_sq_val;
				num_used = num_used + 1;
			}
			else
			{
				// Find the index of the minimum chi squared value in the top-k array
				int index_min = 0;
				for(int j = 1; j < k; j++)
				{
					if(enc_res_buf[j] < enc_res_buf[index_min])
					{
						index_min = j;
					}
				}

				// If the chi squared value of the current element is greater than that of index_min
				// Replace the element at index_min by the current element 
				if(chi_sq_val > enc_res_buf[index_min])
				{
					enc_id_buf[index_min] = rhht_snp_table->buffer[i].key;
					enc_res_buf[index_min] = chi_sq_val;
				}
			}
		}
	}	
}

void rhht_init_cat_chi_sq(uint16_t total, int k)
{
	int num_used = 0;
	float chi_sq_val;

	float sy = 0;
	for(uint16_t i = 0; i < total; i++)
	{
		sy += phenotypes[i];
	}

	float sy2 = dot_prod(phenotypes, phenotypes, total);
	for(uint32_t i = 0; i < rhht_snp_table_pcc->capacity; i++)
	{
		if(rhht_snp_table_pcc->buffer[i].key != 0)
		{
			// Calculate the chi squared value
			chi_sq_val = cat_chi_sq(rhht_snp_table_pcc->buffer[i].ssqg, total, rhht_snp_table_pcc->buffer[i].dotprod, \
						rhht_snp_table_pcc->buffer[i].sx, sy, sy2, rhht_snp_table_pcc->buffer[i].pc_projections);
			if(isnan(chi_sq_val))
			{
				continue;
			}
			// If the top-k array is not full, add current snp without any checks
			if(num_used < k)
			{
				enc_id_buf[num_used] = rhht_snp_table_pcc->buffer[i].key;
				enc_res_buf[num_used] = chi_sq_val;
				num_used = num_used + 1;
			}
			else
			{
				// Find the index of the minimum chi squared value in the top-k array
				int index_min = 0;
				for(uint32_t j = 1; j < k; j++)
				{
					if(enc_res_buf[j] < enc_res_buf[index_min])
					{
						index_min = j;
					}
				}

				// If the chi squared value of the current element is greater than that of index_min
				// Replace the element at index_min by the current element
				if(chi_sq_val > enc_res_buf[index_min])
				{
					enc_id_buf[index_min] = rhht_snp_table_pcc->buffer[i].key;
					enc_res_buf[index_min] = chi_sq_val;
				}
			}
		}
	}
}

void enclave_free_rhht_pcc()
{
	deallocate_table_pcc();
}

void cmtf_init_chi_sq(uint16_t case_total, uint16_t control_total, int k)
{
	int num_used = 0;
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
				if(num_used < k)
				{
					enc_id_buf[num_used] = temp->key;
					enc_res_buf[num_used] = chi_sq_val;
					num_used = num_used + 1;
				}
				else
				{
					// Find the index of the minimum chi squared value in the top-k array
					int index_min = 0;
					for(int j = 1; j < k; j++)
					{
						if(enc_res_buf[j] < enc_res_buf[index_min])
						{
							index_min = j;
						}
					}

					// If the chi squared value of the current element is greater than that of index_min
					// Replace the element at index_min by the current element
					if(chi_sq_val > enc_res_buf[index_min])
					{
						enc_id_buf[index_min] = temp->key;
						enc_res_buf[index_min] = chi_sq_val;
					}
				}
				temp = temp->next;
			}
		}
	}
}

void oa_init_chi_sq(uint16_t case_total, uint16_t control_total, int k)
{
	int num_used = 0;
	float chi_sq_val;
	for(uint32_t i = 0; i < oaht->capacity; i++)
	{
		if(oaht->buffer[i].key != 0)
		{
			// Calculate the chi squared value
			chi_sq_val = chi_sq(oaht->buffer[i].case_count, oaht->buffer[i].control_count, case_total, control_total);

			// If the top-k array is not full, add current snp without any checks
			if(num_used < k)
			{
				enc_id_buf[num_used] = oaht->buffer[i].key;
				enc_res_buf[num_used] = chi_sq_val;
				num_used = num_used + 1;
			}
			else
			{
				// Find the index of the minimum chi squared value in the top-k array
				int index_min = 0;
				for(int j = 1; j < k; j++)
				{
					if(enc_res_buf[j] < enc_res_buf[index_min])
					{
						index_min = j;
					}
				}

				// If the chi squared value of the current element is greater than that of index_min
				// Replace the element at index_min by the current element
				if(chi_sq_val > enc_res_buf[index_min])
				{
					enc_id_buf[index_min] = oaht->buffer[i].key;
					enc_res_buf[index_min] = chi_sq_val;
				}
			}
		}
	}
}
/***** END: Enclave Chi-Sqaured Test Functions *****/

/***** BEGIN: Enclave Min-Heap Public ECALL Interface *****/
void enclave_init_mh(int MH_INIT_CAPACITY)
{
	allocate_heap(MH_INIT_CAPACITY);
}

void enclave_init_mh_f(int MH_INIT_CAPACITY)
{
	allocate_heap_f(MH_INIT_CAPACITY);
}

void enclave_free_mh()
{
	free_heap();
}
/***** END: Enclave Min-Heap Public ECALL Interface *****/

/***** BEGIN: Enclave Result/Output Public ECALL Interface *****/
/*void enclave_get_res(uint32_t* res)
{
	for(size_t i = 0; i < mh->curr_heap_size; i++)
	{
		res[i] = mh->mh_array[i].key;
	}
}*/

/*void enclave_get_mcsk_res(float* my_res)
{
	for(size_t i = 0; i < 2001; i++)
	{
		my_res[i] = enclave_mcsk_buf[i];
	}
}*/

/*void enclave_get_mcsk_sigma(float* my_res)
{
	for(size_t i = 0; i < 2000; i++)
	{
		my_res[i] = enclave_mcsk_buf[i];
	}
}*/

void enclave_get_eig_buf(float* my_res)
{
	for(size_t i = 0; i < 8000; i++)
	{
		my_res[i] = enclave_eig_buf[i];
	}
}

/*void enclave_ortho(float* my_res)
{
	for(size_t i = 0; i < 6; i++)
	{
		my_res[i] = ortho_res[i];
	}
}*/

/*void enclave_get_mem_used(uint32_t* mem_usage)
{
	mem_usage[0] = mem_used;
}*/

void enclave_init_id_buf(int ENC_BUFF_LEN)
{
	enc_id_buf = (uint32_t*) malloc(ENC_BUFF_LEN * sizeof(uint32_t));
}

void enclave_get_id_buf(uint32_t* id, int k)
{
	for(int i = 0; i < k; i++)
	{
		id[i] = enc_id_buf[i];
	}
}

void enclave_free_id_buf()
{
	free(enc_id_buf);
}

void enclave_init_res_buf(int ENC_BUFF_LEN)
{
	enc_res_buf = (float*) malloc(ENC_BUFF_LEN * sizeof(float));
}

void enclave_get_res_buf(float* countf, int k)
{
	for(int i = 0; i < k; i++)
	{
		countf[i] = enc_res_buf[i];
	}
}

void enclave_get_res_pairs(res_pair* pairs, int k)
{
	for(int i = 0; i < k; i++)
	{
		pairs[i].key = enc_id_buf[i];
		pairs[i].value = enc_res_buf[i];
	}
}

void enclave_free_res_buf()
{
	free(enc_res_buf);
}

void enclave_init_temp_buf(int ENC_BUFF_LEN)
{
	enc_temp_buf = (float*) malloc(ENC_BUFF_LEN * sizeof(float));
}

void enclave_get_temp_buf(float *res, int len)
{
	for(int i = 0; i < len; i++)
	{
		res[i] = enc_temp_buf[i];
	}
}

void enclave_free_temp_buf()
{
	free(enc_temp_buf);
}

void enclave_get_mh_ids(uint32_t* ids, int l)
{
	get_mh_keys(ids, l);
}

void enclave_get_mh_vals(uint16_t* vals, int l)
{
	get_mh_vals(vals, l);
}

void enclave_get_mh_pairs(res_pair* pairs, int l)
{
	get_mh_pairs(pairs, l);
}
/***** END: Enclave Result/Output Public ECALL Interface *****/
