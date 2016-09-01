/**
 * \file rng.c
 * \brief random number generators
 *
 * A random number generator library, exporing (i) fast number generation, and
 * (ii) secure random number generation.
 *
 * Each of the two takes a destination, the length for the output, and a
 * seed. The seed is assumed of length 4, since
 * sizeof(int) ≥ 2, but usually sizeof(int) = 4.
 *
 *
 */
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "lfsr.h"
#include "bunny24.h"
#include "rng.h"

/**
 * Now, here we know that the seed should be cryptographically secure.
 * But that would take a shit load of time.
 */
#define RANDOM_DEVICE "/dev/urandom"
//#define RANDOM_DEVICE "/dev/random"

/*
 * +------------------+
 * | Mersenne Twister |
 * +------------------+
 */

static int MT[624];
static int frng_index = 0;

static void init_generator(int seed)
{
  size_t i;

  frng_index = 0;
  MT[0] = seed;
  for (i=1; i!=624; i++)
    MT[i] = 0xffff & (0x6c078965 * (MT[i-1] ^ ((MT[i-1] >> 30) + i)));

}

static void generate_untampered(void)
{
  size_t i;
  int y;

  for (i=0; i!=624; i++) {
    y = (MT[i] ^ 0x80000000) + (MT[(i+1) % 624] & 0x7fffffff);
    MT[i] = MT[(i + 397) % 624] ^ (y >> 1);
    if (y % 2) MT[i] ^= 0x9908b0df;
  }
}

static int extract_number(void) {
  int y;

  if (frng_index == 0) generate_untampered();
  y = MT[frng_index];
  y ^= (y >> 11);
  y ^= (y << 7) & 0x9d2c5680;
  y ^= (y << 15) & 0xefc60000;
  y ^= (y >> 18);

  frng_index = (frng_index+1) % 624;
  return y;
}


/**
 * \brief Fast Random Number Generator.
 *
 * Generates a random sequence of integers satisfying:
 *  - "good" statistical properties.
 *
 * \note it is not requested that from the output bits the state can be recovered.
 *
 * \param      seed the seeed to initialize the pseudorandom numer generation.
 *                  The \ref seed shall be of size 4, just as sizeof(int).
 * \param      len  length of he output to be produced
 * \param[out] dest pointer to the destination of the stream
 *
 * \return     \ref dest
 */
char* frng(char* dest, const char* seed, const size_t len)
{
  size_t i;
  int iseed = *((int *) seed);

  init_generator(iseed);
  for (i=0; i!=len; i++)
    dest[i] = extract_number();

  return dest;
}


/**
 * \brief safe random number generator.
 *
 * A random number generator satisfying:
 *  - "good" statistical properties;
 *  - security constraint;
 *  - from the output bits the initial state cannot be recovered.
 *
 * \note dest shall be capable of holding len/3*3 + 3*(len%3!=0)
 *
 * \param      seed the seed used to initialize the pseudorandom number generation.
 * \param      len length of the output to be produced.
 * \param[out] dest pointer to the destination of the strem
 *
 * \return     \ref dest
 */
char* srng(char* dest, const char* seed, size_t len)
{
  char iv[3] = {0};

  /*
   * Assuming that the seed given consists of 4bytes truly random,
   * we distribute the first three as key to the bunny24 algorithm,
   * and the last one as iv.
   */
  iv[0] = seed[3];
  bzero(dest, len * sizeof(char));
  bunny24_cbc_encrypt(dest, iv, seed, dest, len);

  return dest;
}



/**
 * \brief Bignum random number generator.
 *
 * Using the secure RNG in order to generate a stream of bytes used to represent
 * a BIGNUM.
 * The bignum is *surely* different from 0 and 1.
 *
 * \param[in][out] p If NULL, a new BIGNUM* is assigned to it.
 * \return p.
 */
BIGNUM* bn_rng(BIGNUM **p, int bits)
{
  int i = 0;
  int bytes_units;
  char seed[4];
  FILE *fp = fopen(RANDOM_DEVICE, "r");
  unsigned char *buf;

  if (!*p) *p = BN_new();

  bytes_units = bits / 8;
  bytes_units += 3 - bytes_units % 3;
  buf = malloc(bytes_units * sizeof(char));

  do {
    for (i=0; i!=4; i++) seed[i] = fgetc(fp);
    srng((char *) buf, seed, bytes_units);
    BN_bin2bn(buf, bytes_units, *p);
  } while (BN_is_zero(*p) || BN_is_one(*p));

  fclose(fp);
  free(buf);
  return *p;
}

/**
 * \brief A "safe" prime random number generator. *
 *
 */
BIGNUM* prng(BIGNUM** p, int bits)
{
  do {
    bn_rng(p, bits);
    if (!BN_is_odd(*p)) BN_add(*p, *p, BN_value_one());
  } while (!BN_is_prime(*p, 10, NULL, NULL, NULL));

  return *p;
}
