#include<stdio.h>
#include<stdlib.h>
#include<gcrypt.h>
#include<string.h>
#include<time.h>
#include "cryptogator.h"
#define GCRYPT_VERSION "1.6.4"


void hmac_MD5(char *fileName, int num)
{

//Code for HMAC_MD5


FILE *enc;                                      // file used for HMAC_MD5

size_t hash_size = gcry_md_get_algo_dlen(GCRY_MD_MD5);
size_t fl_rd_v;     //variable to read the file



double HMAC_MD5[100]; //Array stores Time for each Encryption and Decryption


clock_t start_HMD5, end_HMD5;  //Clock Functions variables store start and end times

//gcrypt version check

void grcrypt_init(){

	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("LibGrycpt version doesn't match\n");
	   exit(-1);
	 }
	}


int j,k;              //counters for loop
int bytes;          //Scan file Byte by Byte
char *key;
char *buffer_HMD5;
double Total_HMD5_Time=0;

gcry_md_hd_t handle_MD5;
gcry_md_open(&handle_MD5,GCRY_MD_MD5,GCRY_MD_FLAG_HMAC|GCRY_MD_FLAG_SECURE);



for(j=0; j<num;j++){

//Creating key

key = randomKey(32);
printf("HMAC MD5 key for Iteration No %d is : %s  ",j+1, key);
printf("\n\n");

gcry_md_setkey(handle_MD5, key, strlen(key));



enc = fopen(fileName, "rb");
fseek(enc,0,SEEK_END);
long int fileSize = ftell(enc);

buffer_HMD5 = malloc(sizeof(char) *fileSize);
unsigned char *lDigest_HMD5 = NULL;


start_HMD5 = clock();                                      //Clock Starts

    int bytes = fread(buffer_HMD5, sizeof(char), fileSize-1, enc);
    gcry_md_write(handle_MD5, buffer_HMD5, fl_rd_v);;

    gcry_md_final(handle_MD5);

lDigest_HMD5 = gcry_md_read(handle_MD5, GCRY_MD_MD5);     // digests message length, "int algo  = 0"
int i;
printf("The Hash Generated using HMAC MD5 is: \n");
for(i=0;i<strlen(lDigest_HMD5);i++)
{
printf("%x",lDigest_HMD5[i]);
}
printf("\n");

end_HMD5 = clock();
double total_HMD5 = (double)(end_HMD5-start_HMD5)/CLOCKS_PER_SEC*1000000000;
printf("\nTotal time taken for Hash Generation : %.2lf nano-seconds \n", total_HMD5);
printf("--------------------------------------------------------------------------------\n");
HMAC_MD5[j] = total_HMD5;



}

gcry_md_close(handle_MD5);

free(buffer_HMD5);



for(k=0;k<num;k++)
{
Total_HMD5_Time = Total_HMD5_Time + HMAC_MD5[k];

}

printf("Total HASH Time (HMAC_MD5) for %d iterations is: %.2lf nano-seconds \n\n",k, Total_HMD5_Time);

double meanHMD5_time = Total_HMD5_Time/num;

printf("Mean Hash Time for (HMAC_MD5) %d iterations is: %.2lf nano-seconds \n\n",k, meanHMD5_time);


double medianHMD5 =  calculateMedian(HMAC_MD5, num);
printf("The Median Hash Time for (HMAC_MD5) after %d Iterations is: %.2lf nano-seconds \n\n",num, medianHMD5);


}
