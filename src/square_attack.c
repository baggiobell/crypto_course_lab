#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bunny24.h"

#define SIXBITS_MAX 0x40

void oracle(char *dest, char *message)
{
  reduced_bunny24_encrypt(dest, "vik", message);
}

void square_attack(char *bk)
{
  int i, j;
  char m[3];
  char test_m[3];
  int8 c[4];
  int8 signed_c[64][4];
  char ciphertext[3];
  int8 test_k;
  int8 k[4];
  int8 signedk[4];
  int8 signedk_pool[4][SIXBITS_MAX];
  int8 keys_found[4];
  int8 sum;

  memset(signedk_pool, 1, 4 * SIXBITS_MAX * sizeof(int8));
  memset(keys_found, SIXBITS_MAX, 4 * sizeof(int8));
  while (memcmp(keys_found, "\x1\x1\x1\x1", 4)) {
    m[1] = rand(); m[2] = rand();
    for (i = 0; i != SIXBITS_MAX; i++) {
      m[0] = i;
      /* ask the oracle what is the ciphertext for the message */
      oracle(ciphertext, m);
      /* compute and cache č = λ⁻¹(c) */
      bytes_to_block(c, ciphertext);
      inverse_mixing_layer(signed_c[i], c);
    }

    for (i=0; i!=4; i++) {
      for (test_k = 0; test_k != SIXBITS_MAX; test_k++) {
        if (!signedk_pool[i][test_k]) continue;
        sum = 0;
        for (j=0; j!= SIXBITS_MAX; j++) sum ^= insbox(i, signed_c[j][i] ^ test_k);
        if (sum) {
          signedk_pool[i][test_k] = 0;
          keys_found[i]--;
        }
      }
    }
    for (i=0; i!=4; i++)
      for (test_k = 0; test_k != SIXBITS_MAX; test_k++)
        if (signedk_pool[i][test_k]) { signedk[i] = test_k; break; }

    mixing_layer(k, signedk);
    block_to_bytes(bk, k);
    reduced_bunny24_decrypt(test_m, bk, ciphertext);
    if (!memcmp(test_m, m, 3)) break;
  }
}


int main(int argc, char** argv)
{
  char bk[4];

  square_attack(bk);
  printf("%c%c%c\n", bk[0], bk[1], bk[2]);
  return 0;
}
