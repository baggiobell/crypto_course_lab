#ifndef _RSA_H_
#define _RSA_H_

#include <openssl/bn.h>


void rsa_encrypt(BIGNUM* m, const BIGNUM* e, const BIGNUM* n);

#define rsa_decrypt(m, e, n) rsa_encrypt(m, e, n)

void rsa_genkey(int bits,
                BIGNUM* n, BIGNUM* phi, BIGNUM* e, BIGNUM* d);

#endif
