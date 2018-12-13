#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <tomcrypt.h>

#include "tomcrypt_aesni.h"

static void
die(const char *msg)
{
  perror(msg);
  exit(EXIT_FAILURE);
}

static int
_aes_test(uint8_t *pt, uint8_t *ct, int nblocks, uint8_t *key, int key_len)
{
  int error;
  symmetric_key skey;

  if ((error = rijndael_setup(key, key_len, 0, &skey)) != CRYPT_OK) {
    return error;
  }

  for (int i = 0; i < nblocks; i++) {
    error = rijndael_ecb_encrypt(pt + i * 16, ct + i * 16, &skey);
    if (error) {
      return error;
    }
  }

  for (int i = 0; i < nblocks; i++) {
    error = rijndael_ecb_decrypt(ct + i * 16, pt + i * 16, &skey);
    if (error) {
      return error;
    }
  }

  return 0;
}

static int
_aesni_test(uint8_t *pt, uint8_t *ct, int nblocks, uint8_t *key, int key_len)
{
  int error;
  symmetric_key skey;

  ltc_aesni_overwrite_aes();

  if ((error = aesni_desc.setup(key, key_len, 0, &skey)) != CRYPT_OK) {
    return error;
  }

  for (int i = 0; i < nblocks; i++) {
    error = aesni_desc.ecb_encrypt(pt + i * 16, ct + i * 16, &skey);
    if (error) {
      return error;
    }
  }

  for (int i = 0; i < nblocks; i++) {
    error = aesni_desc.ecb_decrypt(ct + i * 16, pt + i * 16, &skey);
    if (error) {
      return error;
    }
  }

  return 0;
}

static int
_aesni_accel_test(uint8_t *pt, uint8_t *ct, int nblocks, uint8_t *key, int key_len)
{
  int error;
  symmetric_key skey;

  ltc_aesni_overwrite_aes();

  if ((error = aesni_desc.setup(key, key_len, 0, &skey)) != CRYPT_OK) {
    return error;
  }

  error = aesni_desc.accel_ecb_encrypt(pt, ct, nblocks, &skey);
  if (error) {
    return error;
  }

  error = aesni_desc.accel_ecb_decrypt(ct, pt, nblocks, &skey);
  if (error) {
    return error;
  }

  return 0;
}


#ifdef DEBUG
static int
print_result(uint8_t *pt, int nblocks)
{
  for (int i = 0; i < nblocks * 16; i++) {
    printf("%c", (char)pt[i]);
  }
}
#endif

int
main(int argc, char **argv)
{
  int error, opt, nblocks = 0, key_len = 0;
  char *target;
  int (*test_func)(uint8_t *, uint8_t *, int, uint8_t *, int);

  while ((opt = getopt(argc, argv, "b:l:f:")) != -1) {
    switch (opt) {
      case 'b':
        nblocks = atoi(optarg);
        break;

      case 'l':
        key_len = atoi(optarg) / 8;
        if (key_len != 16 && key_len != 24 && key_len != 32) {
          fprintf(stderr, "Invalid key length (please specify 128 | 192 | 256\n");
          return EXIT_FAILURE;
        }

        break;

      case 'f':
        if (strcmp(optarg, "aes") == 0) {
          test_func = _aes_test;
        } else if (strcmp(optarg, "aesni") == 0) {
          test_func = _aesni_test;
        } else if (strcmp(optarg, "aesni_accel") == 0) {
          test_func = _aesni_accel_test;
        } else {
          fprintf(stderr, "Invalid function (please specify aes | aesni\n");
          return EXIT_FAILURE;
        }

        target = strdup(optarg);
        if (target == NULL) {
          die("strdup");
        }

        break;

      default:
        fprintf(stderr, "Invalid option -%c\n", opt);
        return EXIT_FAILURE;
    }
  }

  printf("testing with \"%s\" key_len: %d nblocks: %d\n", target, key_len, nblocks);

  srand((unsigned int)time(NULL));

  /* Generate random key */
  uint8_t key[key_len];
  for (int i = 0; i < key_len; i++) {
    key[i] = (uint8_t)rand();
  }

  /* Generate plain texts */
  uint8_t *pt = calloc(16, nblocks);
  if (pt == NULL) {
    die("calloc");
  }

  for (int i = 0; i < 16 * nblocks; i += 8) {
    memcpy(pt + i, "deadbeef", 8);
  }

  uint8_t *ct = calloc(16, nblocks);
  if (ct == NULL) {
    die("calloc");
  }

  test_func(pt, ct, nblocks, key, key_len);

#ifdef DEBUG
  print_result(pt, nblocks);
#endif

  return 0;
}
