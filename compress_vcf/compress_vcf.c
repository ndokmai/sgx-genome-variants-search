#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define MAX_BUFFER_SIZE	500000
#define	MAX_FNAME		64

void strip_ext(char* fname)
{
	char* end = fname + strlen(fname);
	while(end > fname && *end != '.' && *end != '\\' && *end != '/')
	{
		--end;
	}

	if(end > fname && *end == '.')
	{
		*end = '\0';
	}
}

int main(int argc, char** argv)
{
	/* Check command line arguments */
	if(argc < 3)
	{
		fprintf(stderr, "Usage:\t%s\t<Input VCF>\t<CASE(1)/CONTROL(0)>\n", argv[0]);
		return 0;
	}

	/* Start program */
	fprintf(stderr, "Compressing VCF file provided for idash-2017 ...\n");
	
	/* Prepare filenames */
	char in_fname[MAX_FNAME];
	char out_fname[MAX_FNAME];

	/* First, remove the extension from the original filename */
	strncpy(in_fname, argv[1], strlen(argv[1]) + 1);
	strip_ext(in_fname);

	/* Copy stripped filename to temporary buffers */
	strcpy(out_fname, in_fname);

	/* Add new file extensions */
	strcat(out_fname, ".ckz0");

	/* Open input file for reading */
	FILE* infile = fopen(argv[1], "r");
	if(infile == NULL)
	{
		fprintf(stderr, "Error opening input file\n");
		return 1;
	}

	/* Write this to the output file as the first 4 bytes so that the reader program later
	 * can figure out how many lines it has to read until the allele types of the SNPs become
	 * heterozygous.
	 */
	uint32_t line_start_heterozygous = 0;

	/* Buffers for homozygous and heterozygous SNPs */
	uint32_t buffer_homozygous[MAX_BUFFER_SIZE] = {0};
	uint32_t buffer_heterozygous[MAX_BUFFER_SIZE] = {0};
	uint32_t num_heterozygous = 0;

	/* Read and process file line by line */
	/* Remember: fgets doesn't strip the terminating \n */
	char line[256];
	while(fgets(line, sizeof(line), infile))
	{
		/* Ignore comment lines */
		if(line[0] == '#')
		{
			continue;
		}

		/* SNP id as a char[]. We will convert these to 32-bit integers to save space */
		char rs_id[16];
		char* dummy;
		unsigned long temp = 0;
		uint32_t rs_id_int = 0;

		char* token;
		token = strtok(line, "\t");
		while(token != NULL)
		{
			if(token[0] == 'r' && token[1] == 's')
			{
				strncpy(rs_id, token + 2, sizeof(rs_id));
				temp = strtoul(rs_id, &dummy, 10);
				rs_id_int = (uint32_t) temp;
			}
			else if(strcmp(token, "homozygous\n") == 0)
			{
				/* Add to the first buffer */
				buffer_homozygous[line_start_heterozygous] = rs_id_int;
				line_start_heterozygous = line_start_heterozygous + 1;
			}
			else if(strcmp(token, "heterozygous\n") == 0)
			{
				/* Add to the second buffer */
				buffer_heterozygous[num_heterozygous] = rs_id_int;
				num_heterozygous = num_heterozygous + 1;
			}
			token = strtok(NULL, "\t");
		}
	}

	/* Open output file for writing in binary mode */
	FILE* outfile;
	outfile = fopen(out_fname, "wb");
	if(outfile == NULL)
	{
		fprintf(stderr, "Error opening output file\n");
		return 1;
	}

	/* Output case/control status */
	uint32_t status = (uint32_t) atoi(argv[2]);
	fwrite(&status, sizeof(uint32_t), 1, outfile);

	/* Output line_start_heterozygous */
	fwrite(&line_start_heterozygous, sizeof(line_start_heterozygous), 1, outfile);

	/* Flush buffers */
	fwrite(&buffer_homozygous, sizeof(uint32_t), line_start_heterozygous, outfile);
	fwrite(&buffer_heterozygous, sizeof(uint32_t), num_heterozygous, outfile);

	/* Close input/output files */
	fclose(infile);
	fclose(outfile);

	/* Terminate program */
	return 0;
}
