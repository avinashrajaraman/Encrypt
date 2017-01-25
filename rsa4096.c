#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <string.h>
#include <time.h>
#include "cryptogator.h"
#define length 16
#define blklen 512

void rsa4096(char *fileName, int num)
{
	clock_t start_RSA4096, end_RSA4096;
	char *buf;
	char* outputBuf;
	buf = (char*) malloc(blklen);
	outputBuf = (char*) malloc((blklen*2));
	double EncTime[100]; double DecTime[100];
	gcry_error_t err;
	gcry_sexp_t params;
    gcry_sexp_t keypair;
    size_t len;
    FILE *enc;
    double t;
    int k,sizeRead;
    enc = fopen(fileName, "rb");
	printf("LOLOLOLOLOL");
	for(k=0; k<num; k++)
	{
		gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits 4:4096)))");  //build 1024 bit RSA keys


		gcry_pk_genkey(&keypair, params);
		
		gcry_sexp_t pubk = gcry_sexp_find_token(keypair, "public-key", 0); // take the public and private keys
    	gcry_sexp_t privk = gcry_sexp_find_token(keypair, "private-key", 0);
		
		
		FILE *output4096 = fopen("OutputRSA4096.txt","w");
		
		
	   
	    start_RSA4096 = clock();
	    while( !feof(enc) )
	    {	
	    	gcry_mpi_t msg;
   			gcry_mpi_t out_msg;

			gcry_sexp_t data;
			gcry_sexp_t ciph;
			gcry_sexp_t plain;
	    	
	    	sizeRead = fread(buf, sizeof(char), blklen, enc); //add padding
	    	
	    	
	    	gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, buf, sizeRead, NULL); // convert text into MPI .
	    	
	    	
	    	gcry_sexp_build(&data, NULL,"(data (flags raw) (value %m))", msg); // convert from MPI to S-Expression.
	    	
	    	
	    	gcry_pk_encrypt(&ciph, data, pubk);
	    	 
	    	
	    	gcry_pk_decrypt(&plain, ciph, privk);
	    	
			
			out_msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG); // Convert from S-Expression to MPI.
			
			unsigned char obuf[128] = { 0 };
    		gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char*) &obuf, sizeof(obuf), NULL, out_msg);
    			
	    	
   			 fprintf(output4096, "%s",obuf );
	    	

	    	gcry_sexp_release(data);
		    gcry_sexp_release(ciph);
		    gcry_sexp_release(plain);
		    gcry_mpi_release(msg);
    		gcry_mpi_release(out_msg);
	    }
	    fclose(output4096);
	   	
    	
	    
	    end_RSA4096 = clock();

	   	t = (double)(end_RSA4096 - start_RSA4096)/CLOCKS_PER_SEC; 

	    EncTime[k] = t;
	    gcry_sexp_release(keypair);
	    gcry_sexp_release(pubk);
	    gcry_sexp_release(privk);
   		rewind(enc); // resets the pointer to beginning of the file
	} // end of n iterations.
	double Total_Enc_Time=0;
	for(k=0;k<num;k++)
	{
		Total_Enc_Time = Total_Enc_Time + EncTime[k];
	}
	double meanEnc = Total_Enc_Time/num;
	double medianEnc =  calculateMedian(EncTime, num);
	printf("Mean Encryption and Decryption Time for RSA 4096 %d iterations is: %lf seconds \n",k, meanEnc);
	printf("The Median value for Encryption and Decryption RSA 4096 after %d Iterations is: %lf seconds \n",num, medianEnc);




}
