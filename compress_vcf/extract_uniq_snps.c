#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "rhht.h"

#define	MAX_FNAME			96
#define	RHHT_INIT_CAPACITY	(1 << 27)

int main(int argc, char** argv)
{
	/* Check command line arguments */
	if(argc < 4)
	{
		fprintf(stderr, "Usage:\t%s\t<Bin DIR>\t<Num Files>\t<Output Filename>\n", argv[0]);
		return 0;
	}

	/* Start program */
	fprintf(stderr, "Extracting unique SNPs from VCF files ...\n");

	// 2D array to hold filenames within the directory
	int num_files = atoi(argv[2]);
	char filenames[num_files][MAX_FNAME];

	// Directory traversal variables
	DIR* dir;
	struct dirent* ent;
	struct stat st;

	int i = 0;
	// Check if the input case/control VCF directory exists
	char* file_dir = argv[1];
	if((dir = opendir(file_dir)) != NULL)
	{
		// Process each entry in the directory
		while((ent = readdir(dir)) != NULL)
		{
			// Ignore current and parent dirs
			if(ent->d_name[0] != '.' && i < num_files)
			{			
				// Prepare file path
				strncpy(filenames[i], file_dir, strlen(file_dir) + 1);
				strncat(filenames[i], "/", strlen("/"));
				strncat(filenames[i], ent->d_name, strlen(ent->d_name));

				// Increment file index
				i++;
			}
		}
		closedir(dir);
	}
	else
	{
		fprintf(stderr, "Error opening input VCF directory\n");
		return 1;
	}
	
	// Allocate RHHT to keep the SNP IDs
	allocate_table(RHHT_INIT_CAPACITY);

	// Now, read and process the files
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "%d\n", i);
		if(stat(filenames[i], &st) != -1)
		{
			// Open input binary file for reading
			FILE* file = fopen(filenames[i], "rb");
			if(file == NULL)
			{
				fprintf(stderr, "Error opening file\n");
			}
			fprintf(stderr, "Processing file: %s\n", filenames[i]);

			// Move the file pointer to the end of the file
			fseek(file, 0, SEEK_END);

			// Get the size of the file (in bytes)
			uint32_t file_size = (uint32_t) ftell(file);
			//fprintf(stderr, "\tSize of file: %d bytes.\n", file_size);

			// Move the file pointer back to the beginning of the file
			rewind(file);

			// Each element in the file should be a 32-bit unsigned integer
			// Therefore we can calculate the total number of elements to be sent for the file
			uint32_t num_elems = file_size / sizeof(uint32_t);

			// Allocate memory for the file contents
			uint32_t* contents = (uint32_t*) malloc(sizeof(uint32_t) * num_elems);
			if(contents == NULL)
			{
				fprintf(stderr, "Error: malloc() failed ...\n");
			}

			// Read the file contents
			uint32_t elems_read = fread(contents, sizeof(uint32_t), num_elems, file);
			if(elems_read != num_elems)
			{
				fprintf(stderr, "Error: elems_read (%d) != num_elems (%d) ...\n", elems_read, num_elems);
			}
			
			for(size_t j = 2; j < num_elems; j++)
			{
				uint32_t elem_id = contents[j];
				//fprintf(stderr, "%lu, %lu\n", j, (unsigned long) elem_id);

				// Search the element in the rhht
				// If it exists, do nothing, otherwise insert
				int32_t index = find(elem_id);
				if(index != -1)
				{
					// For this application, we don't need to do any updates
				}
				else
				{
					// Doesn't matter which values we initialize with for this application
					// We're only interested in getting the set of SNPs for this dataset
					insert(elem_id, 2);
				}
			}

			// Close file
			fclose(file);

			// Free memory
			free(contents);
		}
	}

	FILE* f_snps_uniq;
	f_snps_uniq = fopen(argv[3], "wb");

	// We've processed all files, now output the set of unique SNPs for the given dataset
	uint32_t next_uniq_id;
	for(i = 0; i < RHHT_INIT_CAPACITY; i++)
	{
		next_uniq_id = rhht_snp_table->buffer[i].key;
		if(next_uniq_id != 0)
		{
			//fprintf(stdout, "%lu\n", (unsigned long) rhht_snp_table->buffer[i].key);
			fwrite(&next_uniq_id, sizeof(uint32_t), 1, f_snps_uniq);
		}
	}

	fclose(f_snps_uniq);

	return 0;
}
