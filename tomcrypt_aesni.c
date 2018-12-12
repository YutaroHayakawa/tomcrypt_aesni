#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <x86intrin.h>

#include "tomcrypt_aesni.h"

struct blocks8 {
      __m128i    blk[8];
} __attribute__((packed));

/* from aeskeys_amd64.S */
void aesni_set_enckey(const uint8_t *userkey,
        uint8_t *encrypt_schedule /*__aligned(16)*/, int number_of_rounds);
void aesni_set_deckey(const uint8_t *encrypt_schedule /*__aligned(16)*/,
        uint8_t *decrypt_schedule /*__aligned(16)*/, int number_of_rounds);

#define AES_BLOCK_LEN 16

static inline void
aesni_enc8(int rounds, const __m128i *keysched, __m128i a,
    __m128i b, __m128i c, __m128i d, __m128i e, __m128i f, __m128i g,
    __m128i h, __m128i out[8])
{
    int i;

    a ^= keysched[0];
    b ^= keysched[0];
    c ^= keysched[0];
    d ^= keysched[0];
    e ^= keysched[0];
    f ^= keysched[0];
    g ^= keysched[0];
    h ^= keysched[0];

    for (i = 0; i < rounds; i++) {
        a = _mm_aesenc_si128(a, keysched[i + 1]);
        b = _mm_aesenc_si128(b, keysched[i + 1]);
        c = _mm_aesenc_si128(c, keysched[i + 1]);
        d = _mm_aesenc_si128(d, keysched[i + 1]);
        e = _mm_aesenc_si128(e, keysched[i + 1]);
        f = _mm_aesenc_si128(f, keysched[i + 1]);
        g = _mm_aesenc_si128(g, keysched[i + 1]);
        h = _mm_aesenc_si128(h, keysched[i + 1]);
    }

    out[0] = _mm_aesenclast_si128(a, keysched[i + 1]);
    out[1] = _mm_aesenclast_si128(b, keysched[i + 1]);
    out[2] = _mm_aesenclast_si128(c, keysched[i + 1]);
    out[3] = _mm_aesenclast_si128(d, keysched[i + 1]);
    out[4] = _mm_aesenclast_si128(e, keysched[i + 1]);
    out[5] = _mm_aesenclast_si128(f, keysched[i + 1]);
    out[6] = _mm_aesenclast_si128(g, keysched[i + 1]);
    out[7] = _mm_aesenclast_si128(h, keysched[i + 1]);
}

static inline void
aesni_dec8(int rounds, const __m128i *keysched, __m128i a,
    __m128i b, __m128i c, __m128i d, __m128i e, __m128i f, __m128i g,
    __m128i h, __m128i out[8])
{
    int i;

    a ^= keysched[0];
    b ^= keysched[0];
    c ^= keysched[0];
    d ^= keysched[0];
    e ^= keysched[0];
    f ^= keysched[0];
    g ^= keysched[0];
    h ^= keysched[0];

    for (i = 0; i < rounds; i++) {
        a = _mm_aesdec_si128(a, keysched[i + 1]);
        b = _mm_aesdec_si128(b, keysched[i + 1]);
        c = _mm_aesdec_si128(c, keysched[i + 1]);
        d = _mm_aesdec_si128(d, keysched[i + 1]);
        e = _mm_aesdec_si128(e, keysched[i + 1]);
        f = _mm_aesdec_si128(f, keysched[i + 1]);
        g = _mm_aesdec_si128(g, keysched[i + 1]);
        h = _mm_aesdec_si128(h, keysched[i + 1]);
    }

    out[0] = _mm_aesdeclast_si128(a, keysched[i + 1]);
    out[1] = _mm_aesdeclast_si128(b, keysched[i + 1]);
    out[2] = _mm_aesdeclast_si128(c, keysched[i + 1]);
    out[3] = _mm_aesdeclast_si128(d, keysched[i + 1]);
    out[4] = _mm_aesdeclast_si128(e, keysched[i + 1]);
    out[5] = _mm_aesdeclast_si128(f, keysched[i + 1]);
    out[6] = _mm_aesdeclast_si128(g, keysched[i + 1]);
    out[7] = _mm_aesdeclast_si128(h, keysched[i + 1]);
}

/* rounds is passed in as rounds - 1 */
static inline __m128i
aesni_enc(int rounds, const __m128i *keysched, const __m128i from)
{
    __m128i tmp;
    int i;

    tmp = from ^ keysched[0];
    for (i = 1; i < rounds; i += 2) {
        tmp = _mm_aesenc_si128(tmp, keysched[i]);
        tmp = _mm_aesenc_si128(tmp, keysched[i + 1]);
    }

    tmp = _mm_aesenc_si128(tmp, keysched[rounds]);
    return _mm_aesenclast_si128(tmp, keysched[rounds + 1]);
}

static inline __m128i
aesni_dec(int rounds, const __m128i *keysched, const __m128i from)
{
    __m128i tmp;
    int i;

    tmp = from ^ keysched[0];

    for (i = 1; i < rounds; i += 2) {
        tmp = _mm_aesdec_si128(tmp, keysched[i]);
        tmp = _mm_aesdec_si128(tmp, keysched[i + 1]);
    }

    tmp = _mm_aesdec_si128(tmp, keysched[rounds]);
    return _mm_aesdeclast_si128(tmp, keysched[rounds + 1]);
}

static inline void
aesni_encrypt_ecb(int rounds, const void *key_schedule, size_t len,
    const uint8_t *from, uint8_t *to)
{
    __m128i tot;
    __m128i tout[8];
    struct blocks8 *top;
    const struct blocks8 *blks;
    size_t i, cnt;

    cnt = len / AES_BLOCK_LEN / 8;
    for (i = 0; i < cnt; i++) {
        blks = (const struct blocks8 *)from;
        top = (struct blocks8 *)to;
        aesni_enc8(rounds - 1, key_schedule, blks->blk[0], blks->blk[1],
            blks->blk[2], blks->blk[3], blks->blk[4], blks->blk[5],
            blks->blk[6], blks->blk[7], tout);
        top->blk[0] = tout[0];
        top->blk[1] = tout[1];
        top->blk[2] = tout[2];
        top->blk[3] = tout[3];
        top->blk[4] = tout[4];
        top->blk[5] = tout[5];
        top->blk[6] = tout[6];
        top->blk[7] = tout[7];
        from += AES_BLOCK_LEN * 8;
        to += AES_BLOCK_LEN * 8;
    }
    i *= 8;
    cnt = len / AES_BLOCK_LEN;
    for (; i < cnt; i++) {
        tot = aesni_enc(rounds - 1, key_schedule,
            _mm_loadu_si128((const __m128i *)from));
        _mm_storeu_si128((__m128i *)to, tot);
        from += AES_BLOCK_LEN;
        to += AES_BLOCK_LEN;
    }
}

static inline void
aesni_decrypt_ecb(int rounds, const void *key_schedule, size_t len,
    const uint8_t from[AES_BLOCK_LEN], uint8_t to[AES_BLOCK_LEN])
{
    __m128i tot;
    __m128i tout[8];
    const struct blocks8 *blks;
    struct blocks8 *top;
    size_t i, cnt;

    cnt = len / AES_BLOCK_LEN / 8;
    for (i = 0; i < cnt; i++) {
        blks = (const struct blocks8 *)from;
        top = (struct blocks8 *)to;
        aesni_dec8(rounds - 1, key_schedule, blks->blk[0], blks->blk[1],
            blks->blk[2], blks->blk[3], blks->blk[4], blks->blk[5],
            blks->blk[6], blks->blk[7], tout);
        top->blk[0] = tout[0];
        top->blk[1] = tout[1];
        top->blk[2] = tout[2];
        top->blk[3] = tout[3];
        top->blk[4] = tout[4];
        top->blk[5] = tout[5];
        top->blk[6] = tout[6];
        top->blk[7] = tout[7];
        from += AES_BLOCK_LEN * 8;
        to += AES_BLOCK_LEN * 8;
    }
    i *= 8;
    cnt = len / AES_BLOCK_LEN;
    for (; i < cnt; i++) {
        tot = aesni_dec(rounds - 1, key_schedule,
            _mm_loadu_si128((const __m128i *)from));
        _mm_storeu_si128((__m128i *)to, tot);
        from += AES_BLOCK_LEN;
        to += AES_BLOCK_LEN;
    }
}

int
aesni_ecb_setup(const unsigned char *key, int keylen, int num_rounds,
    symmetric_key *skey)
{
  int i;
  ulong32 temp, *rk;

  LTC_ARGCHK(key  != NULL);
  LTC_ARGCHK(skey != NULL);

  if (keylen != 16 && keylen != 24 && keylen != 32) {
     return CRYPT_INVALID_KEYSIZE;
  }

  if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2)) {
     return CRYPT_INVALID_ROUNDS;
  }

  skey->rijndael.Nr = 10 + ((keylen/8)-2)*2;

  aesni_set_enckey(key, (uint8_t *)skey->rijndael.eK, skey->rijndael.Nr);
  aesni_set_deckey((uint8_t *)skey->rijndael.eK, (uint8_t *)skey->rijndael.dK, skey->rijndael.Nr);

  return CRYPT_OK;
}

int
aesni_accel_ecb_encrypt(const unsigned char *pt, unsigned char *ct,
    unsigned long blocks, symmetric_key *skey)
{
  aesni_encrypt_ecb(skey->rijndael.Nr, skey->rijndael.eK, blocks, pt, ct);
  return CRYPT_OK;
}

int
aesni_accel_ecb_decrypt(const unsigned char *ct, unsigned char *pt,
    unsigned long blocks, symmetric_key *skey)
{
  aesni_decrypt_ecb(skey->rijndael.Nr, skey->rijndael.dK, blocks, ct, pt);
  return CRYPT_OK;
}

void
ltc_aesni_overwrite_aes(void)
{
  static struct ltc_cipher_descriptor aesni_desc;
  memcpy(&aesni_desc, &aes_desc, sizeof(struct ltc_cipher_descriptor));

  aesni_desc.setup = aesni_ecb_setup;
  aesni_desc.accel_ecb_encrypt = aesni_accel_ecb_encrypt;
  aesni_desc.accel_ecb_decrypt = aesni_accel_ecb_decrypt;

  unregister_cipher(&aes_desc);
  register_cipher(&aesni_desc);
}
