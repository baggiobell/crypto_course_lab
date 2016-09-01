/**
 * \file keys.c
 *
 * Generate RSA keys for the client and server.
 */
#include <stdio.h>

#include <openssl/bn.h>

#include "rsa.h"



void usage(void)
{
  fprintf(stderr, "Usage: ./key <bits>\n");
  exit(EXIT_FAILURE);
}


int main(int argc, char **argv)
{
  int bits;
  BIGNUM
    *n = BN_new(),
    *e = BN_new(),
    *d = BN_new(),
    *phi = BN_new(),
    *one = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  if (argc < 2)  usage();

  bits = atoi(argv[1]);
  if (bits < 16) usage();

  printf("[+] Generating RSA%d key...\n", bits);
  rsa_genkey(bits, n, phi, e, d);
  printf("[+] New RSA%d key found:\n", bits);
  printf("   N: ");  BN_print_fp(stdout, n); printf("\n");
  printf("   e: ");  BN_print_fp(stdout, e); printf("\n");
  printf("   d: ");  BN_print_fp(stdout, d); printf("\n");
  printf(" phi: ");  BN_print_fp(stdout, phi); printf("\n");


  printf("\n[+] Verifying correctedness...");
  BN_mod_mul(one, e, d, phi, ctx);
  printf(BN_is_one(one)?"[ok]\n":"[fail]\n");
  BN_CTX_free(ctx);
  BN_free(one);
  BN_free(n);
  BN_free(e);
  BN_free(d);
  BN_free(phi);


  return 0;
}
