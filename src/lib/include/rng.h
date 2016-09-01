#ifndef _RNG_H_
#define _RNG_H_

#include <stdlib.h>
#include <openssl/bn.h>

char* frng(char* dest, const char* seed, size_t len);

char* srng(char* dest, const char* seed, size_t len);

BIGNUM* bn_rng(BIGNUM** n, int bits);

BIGNUM* prng(BIGNUM** dest, int bits);

#endif /* _RNG_H_ */
