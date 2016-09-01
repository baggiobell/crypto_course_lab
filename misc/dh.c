/**
 *
 * \file dh.c
 * \brief Simple Diffie-Hellman implementation using openssl APIs.
 *
 */
#include <stdio.h>
#include <math.h>
#include <openssl/bn.h>

void print_bignum(BIGNUM* n)
{
  char * dec;

  dec = (char *) malloc(BN_num_bytes(n));
  dec = BN_bn2dec(n);
  printf("%s\n", dec);

  free(dec);
}

int main(int argc, char **argv)
{

  BN_CTX* ctx;
  BIGNUM *p, *g;
  BIGNUM *a, *b;
  BIGNUM *A, *B;
  BIGNUM *s_a, *s_b;

  ctx = BN_CTX_new();

  p = BN_new();
  g = BN_new();
  a = BN_new();
  b = BN_new();

  BN_generate_prime_ex(p, 56, 1, NULL, NULL, NULL);
  BN_generate_prime_ex(g, 56, 1, NULL, NULL, NULL);

  print_bignum(p);
  print_bignum(g);

  BN_set_word(a, 13);
  BN_set_word(b, 7);

  A = BN_new();
  B = BN_new();

  BN_mod_exp(A, g, a, p, ctx);
  BN_mod_exp(B, g, b, p, ctx);

  s_a = BN_new();
  s_b = BN_new();
  BN_mod_exp(s_a, B, a, p, ctx);
  BN_mod_exp(s_b, A, b, p, ctx);

  print_bignum(s_a);
  print_bignum(s_b);

  return 0;
}
