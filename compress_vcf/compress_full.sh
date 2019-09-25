#!/bin/bash

case_indir="/mnt/big_part/ckockan/test-data/sampled_chr_ckz0/case/"
control_indir="/mnt/big_part/ckockan/test-data/sampled_chr_ckz0/control/"

outdir="/mnt/big_part/ckockan/test-data/bin/"

unique_snp_output="/mnt/big_part/ckockan/test-data/unique_snps_64k.bin"

for fname in "$case_indir"*.vcf; do
	./compress_vcf "$fname" "1"
done

mv "$case_indir"*.bin "$outdir"

for fname in "$control_indir"*.vcf; do
	./compress_vcf "$fname" "0"
done

mv "$control_indir"*.bin "$outdir"

./extract_uniq_snps "$outdir" "2000" "$unique_snp_output"
