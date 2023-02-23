#ifndef _TONGSUO_SM4_GCM_H_
#define _TONGSUO_SM4_GCM_H_

#include <openssl/evp.h>

int sm4_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                	unsigned char *aad, int aad_len,
                	unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *ciphertext,
               	 	unsigned char *tag);

int sm4_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                	unsigned char *aad, int aad_len,
                	unsigned char *tag,
               		unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *plaintext);

#endif
