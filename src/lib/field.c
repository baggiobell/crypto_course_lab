#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "field.h"


/**
 *  Perform the sum of two polynomial with coefficients over 𝔽₂
 *
 *  \param n the maximum degree of both a and b
 *  \param a,b  binary-encoded digits.
 */
int8 f2sum(int8 n, int8 a, int8 b)
{
  assert(a >> n == 0 && b >> n == 0);
  return a ^ b;
}

/**
 * Perform the product of two polynomials (with coefficients over 𝔽₂)
 * modulo a "special" polynomial, the field polynomial
 *
 * \param p the field polynomial, an irreducible polynomial of degree n over 𝔽₂
 * \param a a polynomial of degree less than n
 * \param b a polynomial of degree lees than n
 *
 */
int8 f2mul(int8 p, int8 n, int8 a, int8 b)
{
  int8 r;

  for (r = 0; b; b >>= 1, a <<= 1) {
    if (a & (1<<n)) a ^= p;
    if (b & 1)
      r ^= a;
  }

  return r;
}


/**
 * \brief Field exponential.
 * Perform the exp() of two polynomials (with coefficients over 𝔽₂)
 * modulo a "special" polynomial, the field polynomial
 *
 * \param p the field polynomial, an irreducible polynomial of degree n over 𝔽₂
 * \param a a polynomial of degree less than n
 * \param b a polynomial of degree lees than n
 *
 */
int8 f2exp(int8 p, int8 n, int8 a, int8 b)
{
  int8 r;
  assert(b != 0);

  for (r=a; b > 1; b--)
    r = f2mul(p, n, r, a);
  return r;
}


/**
 * \brief Polynomial rotation.
 *
 * Rotate a polynomial `p` of degree `n` of `|r|` digits.
 * If `sgn(r) == -1` gets rotated to the left, to the right otherwise.
 *
 * \param p the polynomial to be rotated
 * \param n the degreee of the polynomial
 * \param r the number of digits to be rotated.
 *
 * \return the new, rotated, polynomial.
 *
 */
int8 f2rot(int8 p, int8 n, int r)
{
  if (r < 0)
    return (0xff >> (8-n-r) & p) << -r | p >> (n+r);
  else
    return (0xff >> (8-r) & p) << (n-r) | p >> r;
}


/*
 * +---------------------+
 * | String Manipulation |
 * +---------------------+
 */

/**
 * \brief Polynomial to string.
 *
 * Converts an array of bits to a human-readable string of "(0|1)+"
 *
 * \param n the polynomial to be converted to a string.
 * \return a char painter to the beginning of the allocated string.
 *
 */
char* ptos(int8 n)
{
  size_t i;
  char *s;
  char *e;

  s = e = malloc(sizeof(char) * 8);

  for (i = 1 << 7; i != 0; i >>= 1)
    sprintf(e++, "%d", (n & i) != 0);
  *e = '\0';

  return s;
}


/**
 * Converts human-readable string of (0|1)* into a machine-friendly array of
 * bits.
 *
 * \param s an array of chars describing the binary form
 */
int8 btoi(const char* s)
{
  int8 n;

  for (n = 0; *s; s++) {
    n <<= 1;
    assert(*s == '0' || *s == '1');
    if (*s == '1') n++;
  }
  return n;
}
