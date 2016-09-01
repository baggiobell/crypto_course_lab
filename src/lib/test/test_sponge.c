#include <assert.h>
#include <string.h>

#include "sponge.h"

int test_sponge(void)
{
  extern size_t hashlen;
  char hash[20];
  char message[100];
  char expected[20];

  memcpy(message, "\xb3\x00", 2);
  memcpy(expected,
         "\x38\x3c\x4\xc4\xce\x47\x79\x45\xe7\x90\x89\xd\x8e\x72\x77\xfa\x68"
         "\xf1\x5b\xa3", hashlen);
  spongebunny(hash, message, 2);
  assert(!memcmp(hash, expected, hashlen));


  memcpy(message, "\x47\xc\x39\xcf\x9a\xfc\xc0", 7);
  memcpy(expected,
         "\x63\x87\xf1\xbe\xb5\xed\xb0\xd\x6\x48\x7e\x52\x43\x84"
         "\x34\x66\xb5\x60\x84\x64", hashlen);
  spongebunny(hash, message, 7);
  assert(!memcmp(hash, expected, hashlen));
  return 1;
}


int main(void)
{
  test_sponge();

  return 0;
}
