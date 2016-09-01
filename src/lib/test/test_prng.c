#include <assert.h>
#include <stdio.h>

#include <openssl/bn.h>

#include "rng.h"


void test_prng(void)
{
  BIGNUM* a;
  prng(&a, 128);
  assert(BN_is_prime(a, 10, NULL, NULL, NULL));
  prng(&a, 256);
  assert(BN_is_prime(a, 10, NULL, NULL, NULL));
  prng(&a, 512);
  assert(BN_is_prime(a, 10, NULL, NULL, NULL));
}


int main(int argc, char **argv)
{
  test_prng();
  return 0;
}
