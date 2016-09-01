#include <assert.h>
#include <openssl/bn.h>

#include "rsa.h"
#include "rng.h"

void test_bn_rng(void)
{
  BIGNUM *n;

  bn_rng(&n, 16);
  assert(n);
  assert(!BN_is_zero(n));
  assert(!BN_is_one(n));

  BN_free(n);
}

void test_bn_prng(void)
{
  BIGNUM *n = NULL;
  prng(&n, 64);
  BN_print_fp(stdout, n);
  assert(BN_is_prime(n, 10, NULL, NULL, NULL));

  BN_free(n);
}

void test_rsa_genkey(void)
{
  BIGNUM
    *n = BN_new(),
    *phi = BN_new(),
    *e = BN_new(),
    *d = BN_new();

  rsa_genkey(128, n, phi, e, d);

  BN_free(n);
  BN_free(d);
  BN_free(phi);
  BN_free(e);
}

int main(int argc, char **argv)
{
  test_bn_rng();
  test_bn_prng();
  test_rsa_genkey();
  return 0;

}
