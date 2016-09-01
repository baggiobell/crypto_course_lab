/**
 * \file bunny24.c
 * \brief AES-like cipher.
 *
 * A simple implementation of bunny24, an AES-like cipher working on a smaller
 * space (𝔽₂₄).
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "field.h"
#include "bunny24.h"


const int8 e = 0x2;
/**
 * The primitive polynomial, as defined from the cipher, is
 *      1 + x + x⁴ + x⁴  + x⁶
 * , which, in binary form, is equal to
 *      "1011011"
 */
const int8 primitive = 0x5b;

#define RB(n)    f2rot(n, 6, -1)

/*
 * +--------------------------+
 * | Miscellanoous Utilities. |
 * +--------------------------+
 */

int8* xor(int8* dest, const int8* v, const int8* key)
{
  size_t i;

  for (i=0; i!=4; i++)
    dest[i] = v[i] ^ key[i];

  return dest;
}

char* cxor(char* dest, const char* a, const char* b)
{
  size_t i;

  for (i=0; i!=3; i++)
    dest[i] = a[i] ^ b[i];
  return dest;
}

/**
 * \brief maps (𝔽₈)³ → (𝔽₆)⁴
 *
 * \param  dest[out]  a vector of int8s of length 4;
 * \param  bytes[in]  a vector of 3 bytes;
 *
 * \return dest
 */
int8* bytes_to_block(int8* dest, const char* bytes)
{

  int8* v = (int8 *) bytes;

  dest[0] = v[0] >> 2;
  dest[1] = v[1] >> 4 | (v[0] & 0x3) << 4;
  dest[2] = (v[1] & 0xf) << 2 | (v[2] & 0xc0) >> 6;
  dest[3] = v[2] & 0x3f;

  return dest;
}

/**
 * \brief maps (𝔽₈)³ → (𝔽₆)⁴
 *
 * \param  dest[out]  a vector of int8s of length 4;
 * \param  bytes[in]  a vector of 3 bytes;
 *
 * \return dest
 */
char* block_to_bytes(char* dest, const int8* v)
{
  dest[0] = v[0] << 2 | v[1] >> 4;
  dest[1] = v[1] << 4 | v[2] >> 2;
  dest[2] = v[2] << 6 | v[3];

  return dest;
}


/*
 * +-------+
 * | S-Box |
 * +-------+
 */
#define sbox1(v) f2exp(primitive, 6, v, 62)
#define sbox2(v) f2exp(primitive, 6, v, 5)
#define sbox3(v) f2exp(primitive, 6, v, 17)
#define sbox4(v) f2sum(6, f2exp(primitive, 6, v, 62),  \
                          f2exp(primitive, 6, e, 2))


#define isbox1(v) f2exp(primitive, 6, v, 62)
#define isbox2(v) f2exp(primitive, 6, v, 38)
#define isbox3(v) f2exp(primitive, 6, v, 26)
#define isbox4(v) f2exp(primitive, 6, \
                        f2sum(6, v, f2exp(primitive, 6, e, 2)), 62)


int8 insbox(int i, int8 v)
{
  switch (i) {
    case 0:
      return isbox1(v);
    case 1:
      return isbox2(v);
    case 2:
      return isbox3(v);
    case 3:
      return isbox4(v);
    }
  return 0;
}

int8* sbox(int8 *dest, int8 *v)
{
  dest[0] = sbox1(v[0]);
  dest[1] = sbox2(v[1]);
  dest[2] = sbox3(v[2]);
  dest[3] = sbox4(v[3]);

  return dest;
}

int8* inverse_sbox(int8* dest, int8* v)
{
  dest[0] = isbox1(v[0]);
  dest[1] = isbox2(v[1]);
  dest[2] = isbox3(v[2]);
  dest[3] = isbox4(v[3]);

  return dest;
}


/*
 * +--------------+
 * | Mixing Layer |
 * +--------------+
 */

int8* mixing_layer(int8 *dest, int8* v)
{
  size_t i, j;
  int8 m;
  static const int8 mixing_matrix[4][4] = {
    {0x23, 0x3b, 0x38, 0x3d},
    {0xd,  0x3c, 0x16, 0x18},
    {0x3,  0x20, 0x17, 0x37},
    {0x2c, 0x26, 0x38, 0x13}
  };

  for (i=0; i!=4; i++)
    for (j=dest[i]=0; j!=4; j++)  {
      m = f2mul(primitive, 6, v[j], mixing_matrix[j][i]);
      dest[i] = f2sum(6, dest[i], m);
    }

  return dest;
}

int8* inverse_mixing_layer(int8* dest, int8* v)
{
  size_t i, j;
  int8 m;

  static const int8 inverse_mixing_matrix[4][4] = {
    {0x1d, 0x3,  0xb,  0x19},
    {0x11, 0x2f, 0x3e, 0x3d},
    {0x7,  0x17, 0x39, 0xc},
    {0xa,  0x3a, 0xd,  0x29},
  };

  for (i=0; i!=4; i++)
    for (j=dest[i]=0; j!=4; j++) {
      m = f2mul(primitive, 6, v[j], inverse_mixing_matrix[j][i]);
      dest[i] = f2sum(6, dest[i], m);
    }

  return dest;
}


/*
 * +-----------------+
 * | Round Functions |
 * +-----------------+
 */

int8* round_function(int8* dest, int8* v, int8* key)
{
  int8 safe_dest[4];

  sbox(dest, v);
  mixing_layer(safe_dest, dest);
  xor(dest, safe_dest, key);

  return dest;
}

int8* inverse_round_function(int8* dest, int8* c, int8* key)
{
  int8 safe_dest[4];

  xor(dest, c, key);
  inverse_mixing_layer(safe_dest, dest);
  inverse_sbox(dest, safe_dest);

  return dest;
}



/*
 * +----------------+
 * | Key Scheduling |
 * +----------------+
 */

int8** key_schedule(int8** rk, const char* k)
{
  int8 key[4];
  int8 w[8+20*4];
  size_t i,j;

  bytes_to_block(key, k);

  /* step 1 */
  w[0] = key[0];
  w[1] = key[1];
  w[2] = key[2];
  w[3] = key[3];

  w[4] = f2sum(6, sbox1(w[0]), w[1]);
  w[5] = f2sum(6, sbox2(w[1]), w[2]);
  w[6] = f2sum(6, sbox3(w[2]), w[3]);
  w[7] = f2sum(6, sbox4(w[3]), w[0]);

  /* step 2 */
  for(i=8; i!=8+20*4; i++) {
    if ((i+1) % 4 != 1) w[i] = f2sum(6, w[i-8], w[i-1]);
    if ((i+1) % 8 == 1) w[i] = f2sum(6, w[i-8], f2sum(6,
                                        sbox2(RB(w[i-1])),
                                        (int8) 0x2a));
    if ((i+1) % 8 == 5) w[i] = f2sum(6, w[i-8], sbox3(w[i-1]));
  }

  /* step 3 */
  for (i=0; i!=16; i++)
    for (j=0; j!=4; j++)
      rk[i][j] = w[8 + i/5 * 20 + i%5 + 5*j];

  return rk;
}


/*
 * +----------------------+
 * |Encryption/Decryption |
 * +----------------------+
 */

char* bunny24_decrypt(char* dest, const char* key, const char* ciphertext)
{
  int8 cipher[4];
  int8* round_keys[16];
  size_t i;

  for (i=0; i!=16; i++)
    round_keys[i] = malloc(4 * sizeof(int8));

  bytes_to_block(cipher, ciphertext);


  key_schedule(round_keys, key);
  for (i=15; i>0; i--)
    inverse_round_function(cipher, cipher, round_keys[i]);
  xor(cipher, cipher, round_keys[0]);

  for (i=0; i!=16; i++)
    free(round_keys[i]);

  return block_to_bytes(dest, cipher);
}


/**
 * \brief Encryption.
 *
 * Encrypt a message of 24 bits using a key of 24 bits, according to the BunnyTN algorithm.
 *
 * \param dest[out]     Where to store the ciphertext.
 * \param key[in]       24-bits key to be used as encryption key
 * \param message[in]   Message to be encrypted
 * \return dest
 *
 */
char* bunny24_encrypt(char* dest, const char* key, const char* message)
{
  int8 plaintext[4];
  size_t i;
  int8* round_keys[16];

  for (i=0; i!=16; i++)
    round_keys[i] = malloc(4 * sizeof(int8));

  /* map everything to 𝔽₆ */
  bytes_to_block(plaintext, message);

  key_schedule(round_keys, key);

  xor(plaintext, plaintext, round_keys[0]);
  for (i=1; i!=16; i++)
    round_function(plaintext, plaintext, round_keys[i]);

  block_to_bytes(dest, plaintext);

  for (i=0; i!=16; i++)
    free(round_keys[i]);

  return dest;
}



/**
 * \brief Reduced version of bunny24.
 *
 * A reduced version of BUNNY24 using only 3 rounds, and the same key for
 * each round.
 *
 */
#define REDUCED_ROUNDS 3

char *reduced_bunny24_encrypt(char *dest, const char *ckey, const char *message)
{
  int8 plaintext[4];
  int8 key[4];
  size_t i;

  /* map everything to 𝔽₆ */
  bytes_to_block(key, ckey);
  bytes_to_block(plaintext, message);

  xor(plaintext, plaintext, key);
  for (i=1; i!=REDUCED_ROUNDS; i++)
    round_function(plaintext, plaintext, key);

  return block_to_bytes(dest, plaintext);
}

char* reduced_bunny24_decrypt(char* dest, const char* ckey, const char* ciphertext)
{
  int8 cipher[4];
  int8 key[4];
  size_t i;

  bytes_to_block(key, ckey);
  bytes_to_block(cipher, ciphertext);
  for (i=1; i!=REDUCED_ROUNDS; i++)
    inverse_round_function(cipher, cipher, key);
  xor(cipher, cipher, key);

  return block_to_bytes(dest, cipher);
}

/*
 * +-----------------------+
 * | Cipher Block Chaining |
 * +-----------------------+
 */

char* _bunny24_cbc_decrypt(char* (*decrypt)(char *, const char*, const char*),
                          char* dest,
                          const char* iv,
                          const char* key,
                          const char* cipher,
                          size_t len)
{
  size_t i;
  char buf[3];

  (*decrypt)(buf, key, cipher);
  cxor(dest, iv, buf);

  for (i=3; i!=len+3*(len%3!=0); i+=3) {
    (*decrypt)(buf, key, cipher+i);
    cxor(dest+i, buf, cipher+i-3);
  }

  return dest;
}


char* _bunny24_cbc_encrypt(char* (*encrypt) (char*, const char*, const char*),
                           char* dest,
                           const char* iv,
                           const char* key,
                           const char* plaintext,
                           size_t len)
{
  size_t i;
  /*
   *  Cit:
   *  Note: if the message m has length not multiple of 24, then the message
   *  is completed by attaching 0's on the right of m until a multiple of
   *  24 is reached.
   *  So for example the message "ab" becomes "ab0000".
   *  This way the ciphertext c has always length multiple of 24.
   */
  char padding[3] = {0};
  char buf[3];

  cxor(buf, iv, plaintext);
  (*encrypt)(dest, key, buf);
  for (i=3; i+3<len; i+=3) {
    cxor(buf, plaintext+i, dest+i-3);
    (*encrypt)(dest+i, key, buf);
  }

  /*
   * XXX.
   * here we are filling the message with NUL bytes.
   * Probably is not safe, check.
   */
  if (i < len) {
    memcpy(padding, plaintext+i, (len-i) * sizeof(char));
    cxor(buf, padding, dest+i-3);
    (*encrypt)(dest+i, key, buf);
  }

  return dest;
}
