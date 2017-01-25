#include<stdio.h>
#include<stdlib.h>
#include<gcrypt.h>
#include<string.h>
#include<time.h>
#include "cryptogator.h"
#define GCRYPT_VERSION "1.6.4"
void aes256(char *fileName, int num)
{

//Code for AES256_CTR Encryption


FILE *enc, *dec;                                        // files used for Encryption & Decryption
int blckSize = 16;                                      // Block Size for AES
int algoEnc = GCRY_CIPHER_AES256;                    // Algo Used is aes256
char initV[16];                                   // Initializing Vector
char *buf = malloc(blckSize);                          //buffer to store file in memory before encryption
char *key;                       // Key for Encryption
clock_t start_Enc256, end_Enc256, start_Dec256, end_Dec256;  //Clock Functions variables store start and end times
int keylength = 32;
int blckLength = 16;
int mode = GCRY_CIPHER_MODE_CTR;
double EncTime[100]; double DecTime[100]; //Array stroing Time for each Encryption and Decryption
//gcrypt version check

void grcrypt_init(){

	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("LibGrycpt version doesn't match\n");
	   exit(-1);
	 }
	}

//AES256_CTR Encryption Starts

gcry_cipher_hd_t hd;

int j,k;              //To run loop
int bytes;          //Scan file Byte by Byte
int padBytes;       //Add padding 


for(j=0; j<num;j++){

//Getting the value of key

key = randomKey(32);
printf("Encryption(AES256 CTR Mode) Iteration No %d : \n Key:    ",j+1);
for(k=0;k<32;k++)
{
printf("%c",key[k]);        //Printing key used for each Encryption/Decryption
}
printf("\n");




start_Enc256 = clock();                                      //Clock for Encryption Starts

memset(initV, 0, 16);

enc = fopen(fileName, "rb");
dec = fopen("AES256_Encrypt_LOL", "wb");

gcry_cipher_open(&hd, algoEnc, mode, 0);
gcry_cipher_setkey(hd, key, keylength);
gcry_cipher_setiv(hd, initV, blckLength);


while(!feof(enc))
    {
    padBytes = 0;
    bytes = fread(buf, 1, blckSize, enc);
        if(!bytes){break;}
   padBytes = bytes;
    while(padBytes<blckSize)
         padBytes++;

    while(bytes < blckSize)
        buf[bytes++] = padBytes;

    gcry_cipher_encrypt(hd, buf, blckSize, NULL, 0);
    bytes = fwrite(buf, 1, blckSize, dec);
    }
end_Enc256 = clock();
double total_EA256 = (double)(end_Enc256-start_Enc256)/CLOCKS_PER_SEC*1000000;
printf("Total time taken for Encrypption : %.2lf nano-seconds \n\n",total_EA256);
EncTime[j] = total_EA256;

//}

gcry_cipher_close(hd);
fclose(enc);
fclose(dec);



    //AES256_CTR Decryption Starts

printf("Decryption(AES256 CTR Mode) Iteration No %d : \n Key:    ",j+1);
for(k=0;k<32;k++)
{
printf("%c",key[k]);
}
printf("\n");


start_Dec256 = clock();

gcry_cipher_open(&hd, algoEnc, mode, 0);
gcry_cipher_setkey(hd, key, keylength);
gcry_cipher_setiv(hd, initV, blckLength);

enc = fopen("AES256_Encrypt_LOL", "rb") ;
dec = fopen("AES256_Decrypt_LOL", "wb");
        while(!feof(enc))
        {
           bytes = fread(buf, 1, blckSize, enc);
            if(!bytes){break;}

    gcry_cipher_decrypt(hd, buf, blckLength, NULL, 0);
    bytes = fwrite(buf, 1, blckSize, dec);
        }

end_Dec256 = clock();
double total_DA256 = (double)(end_Dec256-start_Dec256)/CLOCKS_PER_SEC*1000000;
printf("Total time taken for Decrypption : %.2lf nano-seconds \n\n",total_DA256);

DecTime[j] = total_DA256;

gcry_cipher_close(hd);

}
double Total_Enc_Time=0.0, Total_Dec_Time=0.0;

for(k=0;k<num;k++)
{
Total_Enc_Time = Total_Enc_Time + EncTime[k];
Total_Dec_Time = Total_Dec_Time + DecTime[k];
}

printf("Total Encryption Time (AES256) for %d iterations is: %.2lf nano-seconds \n",k, Total_Enc_Time);
printf("Total Decryption Time (AES256) for %d iterations is: %.2lf nano-seconds \n\n",k, Total_Dec_Time);

double meanEnc = Total_Enc_Time/num;
double meanDec = Total_Dec_Time/num;

printf("Mean Encryption Time (AES256) for %d iterations is: %.2lf nano-seconds \n",k, meanEnc);
printf("Mean Decryption Time (AES256) for %d iterations is: %.2lf nano-seconds \n\n",k, meanDec);


free(buf);
buf = NULL;

double medianEnc =  calculateMedian(EncTime, num);
printf("The Median value for Encryption (AES256) after %d Iterations is: %.2lf nano-seconds \n",num, medianEnc);

double medianDec =  calculateMedian(DecTime, num);
printf("The Median value for Decryption (AES256) after %d Iterations is: %.2lf nano-seconds \n\n",num, medianDec);

}

