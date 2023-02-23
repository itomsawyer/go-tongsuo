#ifndef _TONGSUO_BLOCK_H_
#define _TONGSUO_BLOCK_H_

#include <openssl/evp.h>
#include <openssl/err.h>

int block_encrypt(EVP_CIPHER *cipher, unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int block_decrypt(EVP_CIPHER *cipher, unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);
#endif
