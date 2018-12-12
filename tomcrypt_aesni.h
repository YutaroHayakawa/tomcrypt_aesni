#pragma once

#include <tomcrypt.h>

extern struct ltc_cipher_descriptor aesni_desc;

extern int aesni_ecb_setup(const unsigned char *key, int keylen,
    int num_rounds, symmetric_key *skey);
extern int aesni_accel_ecb_encrypt(const unsigned char *pt, unsigned char *ct,
    unsigned long blocks, symmetric_key *skey);
extern int aesni_accel_ecb_decrypt(const unsigned char *ct, unsigned char *pt,
    unsigned long blocks, symmetric_key *skey);
extern void ltc_aesni_overwrite_aes(void);
