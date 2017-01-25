#include<stdio.h>
#include<stdlib.h>
#include<gcrypt.h>
#include<string.h>
#include<time.h>
#include "cryptogator.h"
#define GCRYPT_VERSION "1.6.4"



void hmac_sha1(char *fileName, int numOfIte)
{

//Code for HMAC_MD5


FILE *enc;                                      // file used for HMAC_SHA1


size_t hash_size = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
size_t fl_rd_v;     //FIle Reading variable



double HMAC_SH1[100]; //Array storing Time for each Encryption and Decryption


clock_t start_HSH1, end_HSH1;  //Clock Functions variables store start and end times


//gcrypt version check

void grcrypt_init(){

	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("LibGrycpt version doesn't match\n");
	   exit(-1);
	 }
	}


int j,k;              //Counters for loop
int bytes;          //Scan file Byte by Byte
char *key;
char *buf_HSH1;

gcry_md_hd_t handle_SH1;
gcry_md_open(&handle_SH1,GCRY_MD_SHA1,GCRY_MD_FLAG_HMAC|GCRY_MD_FLAG_SECURE);


for(j=0; j<numOfIte;j++){

//Creating key

key = randomKey(32);
printf("HMAC SHA1 key for Iteration No %d is : %s  ",j+1, key);


printf("\n\n");

gcry_md_setkey(handle_SH1, key, strlen(key));


enc = fopen(fileName, "rb");
fseek(enc,0,SEEK_END);
long int fileSize = ftell(enc);


buf_HSH1 = malloc(sizeof(char) *fileSize);
unsigned char *lenDig_HSH1 = NULL;


start_HSH1 = clock();                                      //Clock for HMAC Starts

    int bytes = fread(buf_HSH1, sizeof(char), fileSize-1, enc);
    gcry_md_write(handle_SH1, buf_HSH1, fl_rd_v);;

    gcry_md_final(handle_SH1);

lenDig_HSH1 = gcry_md_read(handle_SH1, GCRY_MD_SHA1);     // digests message length, "int algo  = 0"
int i;
printf("The Hash Generate using HMAC SHA1 is: \n");
for(i=0;i<strlen(lenDig_HSH1);i++)
{
printf("%02x",lenDig_HSH1[i]);
}
printf("\n");

end_HSH1 = clock();
double total_SH1 = (double)(end_HSH1-start_HSH1)/CLOCKS_PER_SEC*1000000000;
printf("\nTotal time taken for Hash Generation : %.2lf nano-seconds \n", total_SH1);
printf("--------------------------------------------------------------------------------\n");
HMAC_SH1[j] = total_SH1;


}

gcry_md_close(handle_SH1);

free(buf_HSH1);

double Total_SH1_Time=0.0;

for(k=0;k<numOfIte;k++)
{
Total_SH1_Time = Total_SH1_Time + HMAC_SH1[k];

}

printf("Total HASH Time (HMAC_SHA1) for %d iterations is: %.2lf nano-seconds \n\n",k, Total_SH1_Time);

double meanSH1_time = Total_SH1_Time/numOfIte;

printf("Mean Hash Time for (HMAC_SHA1) %d iterations is: %.2lf nano-seconds \n\n",k, meanSH1_time);


double medianSH1 =  calculateMedian(HMAC_SH1, numOfIte);
printf("The Median Hash Time for (HMAC_SHA1) after %d Iterations is: %.2lf nano-seconds \n\n",numOfIte, medianSH1);


}
