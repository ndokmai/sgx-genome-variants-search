all: 
	gcc -c -O3 -Wall extract_uniq_snps.c -o extract_uniq_snps.o
	gcc -c -O3 -Wall rhht.c -o rhht.o
	gcc -c -O3 -Wall compress_vcf.c -o compress_vcf.o
	gcc extract_uniq_snps.o rhht.o -o extract_uniq_snps
	gcc compress_vcf.o -o compress_vcf
	rm -rf *.o

clean:
	rm -rf compress_vcf extract_uniq_snps *.o *~
