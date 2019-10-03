#!/bin/bash

case_indir="/workspace/sgx-genome-variants-search/test-data/case/"
control_indir="/workspace/sgx-genome-variants-search/test-data/control/"

outdir="/workspace/sgx-genome-variants-search/test-data/bin/"

unique_snp_output="/workspace/sgx-genome-variants-search/test-data/unique_snps.bin"

for fname in "$case_indir"*.vcf; do
	./compress_vcf "$fname" "1"
done

mv "$case_indir"*.bin "$outdir"

for fname in "$control_indir"*.vcf; do
	./compress_vcf "$fname" "0"
done

mv "$control_indir"*.bin "$outdir"

./extract_uniq_snps "$outdir" "1000" "$unique_snp_output"
