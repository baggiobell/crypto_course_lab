#include "rsa.h"
#include "rng.h"

void rsa_encrypt(BIGNUM* m, const BIGNUM* e, const BIGNUM* n) {
  BIGNUM* tmp;
  BN_CTX *ctx;

  ctx = BN_CTX_new();
  tmp = BN_new();

  BN_copy(tmp, m);
  BN_mod_exp(m, tmp, e, n, ctx);

  BN_free(tmp);
  BN_CTX_free(ctx);
}


void rsa_genkey(int bits, BIGNUM* n, BIGNUM* phi, BIGNUM* e, BIGNUM* d)
{
  BIGNUM
    *p,
    *q,
    *p1,
    *q1,
    *tmp;
  BN_CTX *ctx;


  p = BN_new();
  q = BN_new();
  tmp = BN_new();
  ctx = BN_CTX_new();
  p1 = BN_new();
  q1 = BN_new();

  while (1) {
    prng(&p, bits/2);
    BN_sub(p1, p, BN_value_one());
    BN_rshift1(tmp, p1);
    if (!BN_is_prime(tmp, 10, NULL, NULL, NULL)) continue;
    else break;
  }

  while (1) {
    prng(&q, bits/2);
    BN_sub(q1, q, BN_value_one());
    BN_rshift1(tmp, q1);
    if (!BN_is_prime(tmp, 10, NULL, NULL, NULL)) continue;
    else break;
  }

  BN_mul(n, p, q, ctx);
  BN_mul(phi, p1, q1, ctx);

  BN_zero(d);
  while (BN_is_zero(d)) {
    BN_zero(e);
    while (BN_num_bits(e) < bits/4) {
      bn_rng(&e, bits-1);
      if (BN_ucmp(e, phi) != -1) {
        BN_mod(tmp, e, phi, ctx);
        BN_copy(e, tmp);
      }
    }
    BN_mod_inverse(d, e, phi, ctx);
  }

  BN_CTX_free(ctx);
  BN_free(tmp);
  BN_free(p);
  BN_free(q);
  BN_free(p1);
  BN_free(q1);

}
