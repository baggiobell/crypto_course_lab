#include <stdio.h>
#include <stdlib.h>
#include <string.h>


const size_t n = 256;


char* ksa(char*, size_t, char*);
void swap(char*, char*);
char* prga(char*, size_t, char*);
char* vernam(char*, char*, char*, size_t);

int main(int argc, char** argv)
{
  char* key;
  char* plaintext;
  size_t textlen, keylen;

  char* s;
  char* ciphertext;

  if (argc < 3) return 1;

  key = argv[1];
  plaintext = argv[2];
  textlen = strlen(plaintext);
  keylen = strlen(key);


  s = malloc(sizeof(char) * n);
  ciphertext = malloc(sizeof(char) * textlen);

  prga(ksa(key, keylen, s), textlen, ciphertext);
  vernam(ciphertext, plaintext, ciphertext, textlen);

  printf(ciphertext);

  return 0;
}


void swap(char* a, char* b)
{
  char tmp = *a;
  *a = *b; *b = tmp;
}


char* ksa(char* key, size_t keylen, char* s)
{
  int i, j;
  // char* s;

  // s = malloc(sizeof(char) * n);
  for (i=0; i!=n; i++) s[i] = i;

  for (i=0;i!=n; i++) {
    j = (j + s[i] + key[i%keylen]) % n;
    swap(&s[i], &s[j]);
  }
  return s;
}

char* prga(char* s, size_t len, char* out)
{
  int i, j;
  int k;
  // char* out;

  // out = malloc(sizeof(char) * len);

  for (i = j = k = 0; k != len; k++) {
    i = (i + 1) % n;
    j = (j + s[i]) % n;

    swap(&s[i], &s[j]);
    out[k] = s[(s[i] + s[j]) % n];
  }
  return out;
}


char* vernam(char* a, char* b, char* dst, size_t len)
{
  size_t i;

  for (i=0; i!=len; i++)
    dst[i] = a[i] ^ b[i];

  return dst;
}
