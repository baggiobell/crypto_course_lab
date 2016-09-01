/**
 * \file sponge.c
 * \brief A simple hashing algorithm based on sponge and Bunny24.
 *
 * Sponge is a cryptographic function F mapping a variable-length input with a
 * fixed-length output based on another function f, operating on fixed-length,
 * over b bits. <a href="http://sponge.noekeon.org/">Reference</a>.
 *
 */
#include <string.h>

#include "bunny24.h"

/** Bits on which the f function operates. In the case of spongebunny, 3*8=24. */
const size_t b = 24;
/** Capacity parameter for sponge, in bits. */
const size_t c = 4;
/** Bitrate parameter for sponge, in bits. */
const size_t r = 20;
/** Output length, in bytes. */
const size_t hashlen = 20;

/**
 * \brief Compute the 20-bit xor of a and b.
 *
 * \param offset[in]    Determine wether the first 20 bits, to be taken in 3
 *                      bytes, have to be taken in ranges [3-8][0-8][0-8] or
 *                      [0-8][0-8][0-4]. If true, the first one is considered;
 *                      the second one otherwise.
 */
static void oxor(char* dest, char* a, const char* b, short int offset)
{
  if (!offset) {
    dest[0]  = b[0] ^ a[0];
    dest[1]  = b[1] ^ a[1];
    dest[2]  = b[2] ^ (a[2] & 0xf0);
  } else {
    dest[0]  = b[0] ^ ((a[0] & 0x0f) << 4 | ((a[1] & 0xf0) >> 4));
    dest[1]  = b[1] ^ ((a[1] & 0x0f) << 4 | ((a[2] & 0xf0) >> 4));
    dest[2]  = b[2] ^ ((a[2] & 0x0f) << 4);
  }
}

static void sqeeze(char* dest, const char* from, short int offset)
{
  if (!offset) {
    dest[0]  = from[0];
    dest[1]  = from[1];
    dest[2] |= from[2] & 0xf0;
  } else {
    dest[0] |= (from[0] & 0xf0) >> 4;
    dest[1]  = (from[0] & 0x0f) << 4 | (from[1] & 0xf0) >> 4;
    dest[2]  = (from[1] & 0x0f) << 4 | (from[2] & 0xf0) >> 4;
  }
}


/**
 * \brief Pads a message until it reaches a suitable length for padding.
 *
 * XXX. padding a message with zeroes is a bad assumption, since I could create
 * two binaries padded with NUL bytes, and expect the same hash.
 *
 */
static char* padding(char* message, size_t len)
{
  while ((len*8) % 20)
    message[len++] = '\0';

  return message;
}


/**
 * \brief Sponge Construction
 *
 * Spongebunnty outputs a 160-bit hash of an input message \ref message,
 * internally using bunny24_encrypt as fixed-length f.
 *
 * \param message[in] A variable-length message
 * \param len[in]     Length (in bits) of the message
 * \param dest[out]   Where to store the hashed message.
 */
char* spongebunny(char* dest, char* message, size_t len)
{
  char state[3] = {'\0'};
  const char* key = "\xff\xff\xff";
  size_t i;
  short int offset;

  /* padding the message */
  message = padding(message, len);

  /* absorbing phase */
  for (i=offset=0; i<len; offset = !offset) {
    oxor(state, message+i, state, offset);
    bunny24_encrypt(state, key, state);

    if (!offset) i+= 2;
    else         i+= 3;
  }

  /* sqeezing phase */
  bzero(dest, hashlen * sizeof(char));
  for (i=offset=0; i<hashlen; offset = !offset) {
    sqeeze(dest+i, state, offset);
    bunny24_encrypt(state, key, state);

    if (!offset) i += 2;
    else         i += 3;
  }
  sqeeze(dest+i, state, offset);

  return dest;
}
