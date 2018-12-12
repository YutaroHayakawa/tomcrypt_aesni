struct test_struct {
  int keylen;
  unsigned char key[32], pt[16], ct[16];
};

static void
test_dump(int keylen, unsigned char *key, unsigned char *pt, unsigned char *ct)
{
  printf("-------- key --------\n");
  for (int i = 0; i < keylen / 8; i++) {
    printf("%x %x %x %x %x %x %x %x\n",
        key[i * 0], key[i * 1], key[i * 2], key[i * 3],
        key[i * 4], key[i * 5], key[i * 6], key[i * 7]);
  }

  printf("-------- pt --------\n");
  for (int i = 0; i < 2; i++) {
    printf("%x %x %x %x %x %x %x %x\n",
        pt[i * 0], pt[i * 1], pt[i * 2], pt[i * 3],
        pt[i * 4], pt[i * 5], pt[i * 6], pt[i * 7]);
  }

  printf("-------- ct --------\n");
  for (int i = 0; i < 2; i++) {
    printf("%x %x %x %x %x %x %x %x\n",
        ct[i * 0], ct[i * 1], ct[i * 2], ct[i * 3],
        ct[i * 4], ct[i * 5], ct[i * 6], ct[i * 7]);
  }
}

static int
aesni_ecb_test(void)
{
 int err;
 static const struct test_struct tests[] = {
   /*
    { 16,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }
    }
    , {
      24,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }
    }, {
    */
    
   { 32,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }
    }
 };

  symmetric_key key;
  unsigned char tmp[2][16];
  int i, y;

  for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
    zeromem(&key, sizeof(key));
    /*
    if ((err = rijndael_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) {
       return err;
    }
    */

    if ((err = aesni_ecb_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) {
       return err;
    }

    /*
    aesni_set_enckey(tests[i].key, key.rijndael.eK, key.rijndael.Nr);
    aesni_set_deckey(key.rijndael.eK, key.rijndael.dK, key.rijndael.Nr);
    */

    printf("Before encrypt\n\n");
    test_dump(tests[i].keylen, tests[i].key, tests[i].pt, tests[i].ct);
  
    // aesni_ecb_encrypt(tests[i].pt, tmp[0], &key);
    // aesni_encrypt_ecb(key.rijndael.Nr, key.rijndael.eK, 16, tests[i].pt, tmp[0]);
    aesni_accel_ecb_encrypt(tests[i].pt, tmp[0], 16, &key);
    printf("\nAfter aes-ni encrypt\n\n");
    test_dump(tests[i].keylen, tests[i].key, tests[i].pt, tmp[0]);

    /*
    rijndael_ecb_encrypt(tests[i].pt, tmp[0], &key);
    printf("\nAfter aes encrypt\n\n");
    test_dump(tests[i].keylen, tests[i].key, tests[i].pt, tmp[0]);
    */

    // aesni_ecb_decrypt(tmp[0], tmp[1], &key);
    // aesni_decrypt_ecb(key.rijndael.Nr, key.rijndael.dK, 16, tmp[0], tmp[1]);
    aesni_accel_ecb_decrypt(tmp[0], tmp[1], 16, &key);
    printf("\nAfter aes-ni decrypt\n\n");
    test_dump(tests[i].keylen, tests[i].key, tmp[1], tmp[0]);

    /*
    rijndael_ecb_decrypt(tmp[0], tmp[1], &key);
    printf("\nAfter aes decrypt\n\n");
    test_dump(tests[i].keylen, tests[i].key, tmp[1], tmp[0]);
    */

    if (compare_testvector(tmp[0], 16, tests[i].ct, 16, "AES Encrypt", i) ||
          compare_testvector(tmp[1], 16, tests[i].pt, 16, "AES Decrypt", i)) {

        return CRYPT_FAIL_TESTVECTOR;
    }

    /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
    for (y = 0; y < 16; y++) tmp[0][y] = 0;
    for (y = 0; y < 1000; y++) rijndael_ecb_encrypt(tmp[0], tmp[0], &key);
    for (y = 0; y < 1000; y++) rijndael_ecb_decrypt(tmp[0], tmp[0], &key);
    for (y = 0; y < 16; y++) if (tmp[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;
  }
  return CRYPT_OK;
}

static struct ltc_cipher_descriptor aesni_desc;

int
main(void)
{
  memcpy(&aesni_desc, &aes_desc, sizeof(aesni_desc));

  // aesni_desc.setup = aesni_ecb_setup;
  // aesni_desc.ecb_encrypt = aesni_ecb_encrypt;
  // aesni_desc.ecb_decrypt = aesni_ecb_decrypt;
  aesni_desc.test = aesni_ecb_test;

  unregister_cipher(&aes_desc);
  register_cipher(&aesni_desc);

  int result = aesni_desc.test();
  if (result == CRYPT_OK) {
    printf("Success!\n");
  } else {
    printf("Failed!\n");
  }

  return 0;
}
