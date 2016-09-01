#ifndef _BUNNY24_H_
#define _BUNNY24_H_

#include <stdlib.h>
#include "field.h"

int8 insbox(int i, int8 v);

char* cxor(char* dest, const char* a, const char* b);
int8* xor(int8* dest, const int8* v, const int8* key);

int8* sbox(int8 *dest, int8* v);
int8* inverse_sbox(int8* dest, int8* v);


int8* mixing_layer(int8 *dest, int8* v);
int8* inverse_mixing_layer(int8* dest, int8* v);

int8* round_function(int8 *dest, int8* v, int8* key);
int8* inverse_round_function(int8* dest, int8* c, int8* key);

int8** key_schedule(int8** rk, const char* k);

int8* bytes_to_block(int8* dest, const char* bytes);
char* block_to_bytes(char* dest, const int8* block);

char* bunny24_decrypt(char* dest,
                      const char* key,
                      const char* ciphertext);
char* bunny24_encrypt(char* dest,
                      const char* key,
                      const char* message);

char* reduced_bunny24_encrypt(char *dest,
                              const char *key,
                              const char *message);
char* reduced_bunny24_decrypt(char* dest,
                              const char* key,
                              const char* ciphertext);

char* _bunny24_cbc_encrypt(char* (*ecnrypt) (char*, const char*, const char*),
                           char* dest,
                           const char* key,
                           const char* iv,
                           const char* message,
                           size_t len);
char* _bunny24_cbc_decrypt(char* (*decrypt)(char *, const char*, const char*),
                           char* dest,
                           const char* iv,
                           const char* key,
                           const char* cipher,
                           size_t len);

#define bunny24_cbc_encrypt(dest, iv, key, plaintext, len) \
  _bunny24_cbc_encrypt(bunny24_encrypt, dest, iv, key, plaintext, len)
#define reduced_bunny24_cbc_encrypt(dest, key, plaintext, len) \
  _bunny24_cbc_encrypt(reduced_bunny24_encrypt, dest, "\0\0\0\0", key, plaintext, len)

#define bunny24_cbc_decrypt(dest, iv, key, plaintext, len)              \
  _bunny24_cbc_decrypt(bunny24_decrypt, dest, iv, key, plaintext, len)
#define reduced_bunny24_cbc_decrypt(dest, key, plaintext, len) \
  _bunny24_cbc_decrypt(reduced_bunny24_decrypt, dest, "\0\0\0\0", key, plaintext, len)


#endif
