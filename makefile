#Make file for Cryptogator
#Author: Avinash Rajaraman
#Run make to compile

Compiler=gcc
Cflags=
LIBS=-lgcrypt
cryptogator:
	$(Compiler) $(Cflags) cryptogator.c -o cryptogator Aes128.c Aes256.c HMAC_SHA1.c HMAC_SHA256.c HMAC_MD5.c rsa1024.c rsa4096.c  $(LIBS)
clean:
	rm cryptogator AES128_Decrypt AES256_Decrypt AES128_Encrypt AES256_Encrypt
