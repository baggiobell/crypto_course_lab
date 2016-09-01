#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bunny24.h"
#include "field.h"

int test_sbox(void)
{
  int8 v[4] = {0x1, 0x1, 0x1, 0x1};
  int8 w[4] = {0x0};

  sbox(w, v);
  assert(w[0] == btoi("000001"));
  assert(w[1] == btoi("000001"));
  assert(w[2] == btoi("000001"));
  assert(w[3] == btoi("000101"));

  return 1;
}

int test_conversions(void)
{
  char bytes[3] = {0};
  int8 block[4] = {0};

  memcpy(bytes, "\xa9\xa8\xa9", 3);
  bytes_to_block(block, bytes);
  block_to_bytes(bytes, block);
  assert(!memcmp(bytes, "\xa9\xa8\xa9", 3));


  memcpy(bytes, "\xf4\xd4\xd0", 3);
  bytes_to_block(block, bytes);
  assert(!(block[0] >> 6 |
           block[1] >> 6 |
           block[2] >> 6 |
           block[3] >> 6));
  return 1;
}



/*
 * In case of fire:
 *
 *  def parse_shit(s):
 *     s = s.strip('()').split('  ')
 *     return map(hex, [int(x.replace(' ', ''), 2) for x in s])
 */
int test_mixing_layer(void)
{
  int8 block[4];
  int8 mixed[4];
  size_t i;

  static const int8 test[][4] = {
    {0x33, 0x24, 0x5, 0x20},
    {0x12, 0x38, 0x3c, 0x18},
    {0x24, 0x25, 0x1d, 0x35}
  };
  static const int8 expected[][4] = {
    {0x1b, 0x8,  0x2c, 0x37},
    {0x3c, 0x35, 0xe,  0x31},
    {0xd,  0x23, 0x3,  0x6}
  };

  for (i=0; i!=3; i++) {
    memcpy(block, test[i], 4);
    assert(!memcmp(mixing_layer(mixed, block),
                   expected[i], 4));
  }

  return 1;
}

int test_key_schedule(void)
{
  /*
    >>> a
   ('10010001', '10111010', '01100000')
   >>> print map(hex, [int(x, 2) for x in a])
   ['0x91', '0xba', '0x60']
  */
  size_t i;
  size_t j;

  char key[] =  {0x91, 0xba, 0x60};
  int8* round_keys[16];

  /*
     >>> a
     ['110011100111101010001010',
     '101000100011001011100001',
     '000001001111000001001010',
     '100001000011100110100000',
     '101111101011000101101011',
     '100000110111001001001011',
     '000110010111000000100010',
     '000011111100010111101000',
     '001001001100100000100001',
     '111101001010110111100001',
     '001110001111001001101110',
     '101110101110011011111110',
     '011001001111000000101110',
     '010010111110001111100111',
     '100111010000100001111100',
     '101100000111010101101010']
     >>> print '\n'.join([
             '{' + ', '.join([hex(int(x, 2)) for x in key]) + '}' + ','
             for key in a])
  */

  int8 expected_round_keys[16][4] = {
    {0x33, 0x27, 0x2a, 0xa},
    {0x28, 0x23, 0xb, 0x21},
    {0x1, 0xf, 0x1, 0xa},
    {0x21, 0x3, 0x26, 0x20},
    {0x2f, 0x2b, 0x5, 0x2b},
    {0x20, 0x37, 0x9, 0xb},
    {0x6, 0x17, 0x0, 0x22},
    {0x3, 0x3c, 0x17, 0x28},
    {0x9, 0xc, 0x20, 0x21},
    {0x3d, 0xa, 0x37, 0x21},
    {0xe, 0xf, 0x9, 0x2e},
    {0x2e, 0x2e, 0x1b, 0x3e},
    {0x19, 0xf, 0x0, 0x2e},
    {0x12, 0x3e, 0xf, 0x27},
    {0x27, 0x10, 0x21, 0x3c},
    {0x2c, 0x7, 0x15, 0x2a}
  };

  for (i=0; i!=16; i++)
    round_keys[i] = calloc(4, sizeof(int8));

  key_schedule(round_keys, key);

  for (i=0; i!=16; i++)
    for (j=0; j!=4; j++)
      assert(round_keys[i][j] == expected_round_keys[i][j]);

  for (i=0; i!=16; i++)
    free(round_keys[i]);
  return 1;
}


int test_encrypt(void)
{
  char m[3];
  char c[3];
  char k[3];

  memcpy(m, "\x27\x58\x3c", 3 * sizeof(char));
  memcpy(k, "\xf4\xd4\xd0", 3 * sizeof(char));
  bunny24_encrypt(c, k, m);
  assert(!memcmp(c, "\xF9\x04\x66", 3 * sizeof(char)));

  memcpy(m, "\x72\xDA\xDC", 3 * sizeof(char));
  memcpy(k, "\x8A\x33\x9E", 3 * sizeof(char));
  bunny24_encrypt(c, k, m);
  assert(!memcmp(c, "\xBF\x0C\x2B", 3 * sizeof(char)));

  memcpy(m, "\x08\x17\x36", 3 * sizeof(char));
  memcpy(k, "\x8C\x5B\x5C", 3 * sizeof(char));
  bunny24_encrypt(c, k, m);
  assert(!memcmp(c, "\x5E\x22\x97", 3 * sizeof(char)));

  memcpy(m, "\x35\x98\xCE", 3 * sizeof(char));
  memcpy(k, "\x13\x45\x65", 3 * sizeof(char));
  bunny24_encrypt(c, k, m);
  assert(!memcmp(c, "\xBE\x5B\xB9", 3 * sizeof(char)));

  memcpy(m, "\xF5\xB1\x17", 3 * sizeof(char));
  memcpy(k, "\x91\xBA\x60", 3 * sizeof(char));
  bunny24_encrypt(c, k, m);
  assert(!memcmp(c, "\xC9\x28\xF3", 3 * sizeof(char)));

  return 1;
}


int test_cbc(void)
{
  char m[256];
  char k[256];
  char iv[256];
  char c[256];

  /* testing CBC: */
  /** test that iv = 0 makes cbc == bunny */
  memcpy(m, "\x55\x97\xcf", 3 * sizeof(char));
  memcpy(k, "\x73\x29\x04", 3 * sizeof(char));
  bunny24_encrypt(c, k, m);
  assert(!memcmp(c, "\xC9\x28\xF3", 3 * sizeof(char)));

  memcpy(m, "\x12\x34\x56", 3 * sizeof(char));
  memcpy(iv, "\x47\x93\x99", 3 * sizeof(char));
  memcpy(k, "\x73\x29\x04", 3 * sizeof(char));
  bunny24_cbc_encrypt(c, k, iv, m, 3);
  assert(!memcmp(c, "\x00\x70\xF4", 3 * sizeof(char)));

  return 1;
}

int test_decryption(void)
{
  char m[3];
  char c[3];
  char k[3];

  int8 n[4] = {1, 2, 3, 4};
  int8 kk[4] = {1, 0, 1, 0};
  int8 d[4];

  /* test inverse sbox */
  sbox(d, n);
  inverse_sbox(n, d);
  assert(n[0] == 1 &&
         n[1] == 2 &&
         n[2] == 3 &&
         n[3] == 4);

  /* test inverse mixing matrix */
  mixing_layer(d, n);
  inverse_mixing_layer(n, d);
  assert(n[0] == 1 &&
         n[1] == 2 &&
         n[2] == 3 &&
         n[3] == 4);

  /* test inverse round function */
  round_function(d, n, kk);
  inverse_round_function(n, d, kk);
  assert(n[0] == 1 &&
         n[1] == 2 &&
         n[2] == 3 &&
         n[3] == 4);

  /* test global decryption */
  memcpy(m, "\x10\x20\x10", 3 * sizeof(char));
  memcpy(k, "\x1\x2\x3", 3 * sizeof(char));
  bunny24_encrypt(c, k, m);
  bunny24_decrypt(m, k, c);

  assert(!memcmp(m, "\x10\x20\x10", 3 * sizeof(char)));
  return 1;
}

int test_bunny24_cbc_encrypt(void)
{
  char m[10];
  char k[3];
  char iv[3];
  char c[10];
  char cbcc[10];

  /* iv = 000 shall be the same as bunny24_encrypt() */
  memcpy(m, "\x12\x34\x56", 3 * sizeof(char));
  memcpy(iv, "\0\0\0", 3 * sizeof(char));
  memcpy(k, "\x73\x29\x04", 3 * sizeof(char));
  bunny24_cbc_encrypt(cbcc, iv, k, m, 3);
  bunny24_encrypt(c, k, m);
  assert(!memcmp(cbcc, c, 3));

  /* encryption with just 3 bytes */
  memcpy(iv, "\x47\x93\x99", 3 * sizeof(char));
  bunny24_cbc_encrypt(cbcc, iv, k, m, 3);
  assert(!memcmp(cbcc, "\x00\x70\xF4", 3));

  /* encryption with a multiple of 3 chars. */
  memcpy(m, "\x12\x34\x56\xaa\xaa\xaa", 6 * sizeof(char));
  memcpy(iv, "\x42\x55\x1B", 3 * sizeof(char));
  memcpy(k, "\x77\xC9\x89", 3 * sizeof(char));
  bunny24_cbc_encrypt(cbcc, iv, k, m, 6);
  assert(!memcmp(cbcc, "\xC7\x97\xC4\x4F\x2F\xDB", 6));

  /* encryption with padding */
  memcpy(m, "\x12\x34\x56\xA0", 4 * sizeof(char));
  memcpy(iv, "\x7C\x89\xA6", 3 * sizeof(char));
  memcpy(k, "\xAC\x6B\x46", 3 * sizeof(char));
  bunny24_cbc_encrypt(cbcc, iv, k, m, 4);
  assert(!memcmp(cbcc, "\xBC\xEC\x1C\xD4\x6D\xE1", 6));
  return 1;
}


int test_bunny24_cbc_decrypt(void)
{
  char m[20];
  char k[3];
  char iv[3];
  char c[20];


  memcpy(m, "\x12\x34\x56", 3 * sizeof(char));
  memcpy(k, "\x73\x29\x04", 3 * sizeof(char));
  memcpy(iv, "\x47\x93\x99", 3 * sizeof(char));
  bunny24_cbc_encrypt(c, iv, k, m, 3);
  bunny24_cbc_decrypt(m, iv, k, c, 3);
  assert(!memcmp(m, "\x12\x34\x56", 3));

  memcpy(m, "\x12\x34\x56\xAA\xAA\xAA\xAA\xA0", 8 * sizeof(char));
  memcpy(k, "\xAB\xD6\xFE", 3 * sizeof(char));
  memcpy(iv, "\x95\xDD\xB3", 3 * sizeof(char));
  bunny24_cbc_encrypt(c, iv, k, m, 8);
  assert(!memcmp(c, "\xC0\xD4\x3E\x7B\x79\x62\xE8\x73\x47", 9));
  bunny24_cbc_decrypt(m, iv, k, c, 9);
  assert(!memcmp(m, "\x12\x34\x56\xAA\xAA\xAA\xAA\xA0", 8));

  return 1;
}

int test_bruteforce(void)
{
  char m[3] = {'d', 'i', 'o'};
  char k[3] = {'c', 'a', 'n'};
  char c[3];

  char brute[3];

  srand(0);
  bunny24_encrypt(c, k, m);
  do {
    brute[0] = rand() % 0xff;
    brute[1] = rand() % 0xff;
    brute[2] = rand() % 0xff;

    bunny24_decrypt(m, brute, c);
  } while(memcmp(m, "dio", 3));
  return 1;
}

void test_reduced_bunny24(void)
{
  char m[3];
  char c[3];
  char k[3];

  memcpy(m, "\x27\x58\x3c", 3 * sizeof(char));
  memcpy(k, "\xf4\xd4\xd0", 3 * sizeof(char));
  reduced_bunny24_encrypt(c, k, m);
  reduced_bunny24_decrypt(m, k, c);
  assert(!memcmp(m, "\x27\x58\x3C", 3 * sizeof(char)));
}



int main(int argc, char ** argv)
{
  test_sbox();
  test_conversions();
  test_mixing_layer();
  test_key_schedule();

  test_encrypt();
  test_decryption();

  test_bunny24_cbc_encrypt();
  test_bunny24_cbc_decrypt();

  test_reduced_bunny24();
  return 0;
}
