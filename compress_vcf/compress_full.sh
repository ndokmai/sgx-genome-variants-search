#!/bin/bash

case_indir="/home/ckockan/test-data/case/"
control_indir="/home/ckockan/test-data/control/"

case_outdir="/home/ckockan/test-data/case_ckz0/"
control_outdir="/home/ckockan/test-data/control_ckz0/"

for fname in "$case_indir"*.vcf; do
	./compress_vcf "$fname" "1"
done

mv "$case_indir"*.ckz0 "$case_outdir"

for fname in "$control_indir"*.vcf; do
	./compress_vcf "$fname" "0"
done

mv "$control_indir"*.ckz0 "$control_outdir"
