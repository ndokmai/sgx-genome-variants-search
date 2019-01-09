void enclave_init_sketch_rhht()
{
	// Allocate enclave Robin-Hood hash table
	// TODO: Allow growing (currently not)
	allocate_table(MH_INIT_CAPACITY << 1);

	// Insert keys, initialize allele counts to be 0
	size_t i;
	struct mh_node* mh_array_ = get_mh_array();
	uint32_t key;
	for(i = 0; i < MH_INIT_CAPACITY; i++)
	{
		rhht_snp_table->num_elems = rhht_snp_table->num_elems + 1;
		key = mh_array_[i] -> key;
		uint32_t hash = key & ((rhht_snp_table->capacity) - 1);
		insert_helper(hash, key, 0, 0);
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
