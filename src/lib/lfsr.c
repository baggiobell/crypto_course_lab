/**
 * \file lfsr.c
 * \brief Linear Feedback Shift Register library.
 *
 * Implements some basic utilities for dealing with LFSRs, and exports the
 * following ciphers:
 * + \ref maj5()
 * + \ref all5()
 * + \ref a5_1()
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lfsr.h"


/*
 * +-------------------------------+
 * |Generic LFSR utility functions |
 * +-------------------------------+
 */

static char update(const char* p, size_t degree, char* state)
{
  char b;
  size_t i;

  /* calculate the fresh new bit to using thee polynomial vector */
  for (i=b=0; i!=degree; i++)
    if (p[i+1]) b ^= state[i];
  /* rotate the register*/
  memmove(state+1, state, (degree-1) * sizeof(char));
  /* update the first position with the previously computed one */
  state[0] = b;

  return b;
}

static char output(char* state, size_t degree)
{
  return state[degree-1];
}


/**
 * \brief Implementation of a lfsr register.
 *
 * The LFSR will poduce a pseudorandom stream of bytes given the initial state
 * \ref reg and the <em>feedback polynomial</em> \ref p.
 * The output stream will be filled with the \em first register and shift on the
 * right.
 * That is, given a register {x₀, x₁, …, xₙ}, the \ref LFSR() function will
 * update dropping xₙ and return x₀.
 *
 * \param dest array of bytes where to store che ciphertext.
 * \param p polynomial vector for updating the registers.
 * \param len degree of the polynomial.
 * \param reg the register to be used for holding states.
 * \param n desidered length of output
 *
 * \return an encrypted stream of n bytes.
 */
char *LFSR(char* dest,
           const char* p,
           size_t len,
           char* reg,
           size_t n)
{
  size_t i;

  for (i=0; i!=n; i++)
    dest[i] = update(p, len, reg);

  return dest;
}


/**
 * \brief finds the period of a given polynomial.
 *
 * Cycle through each register state Sᵢ until Sᵢ == S₀
 * or either Sᵢ == {0, 0, …,0}.
 *
 * \param p the polynomial to be analyzed
 * \param len the degree of `p`.
 *
 * \return the period, as unsigned int.
 */
unsigned int lfsr_period(char* p, size_t len)
{
  char* start;
  char out;
  char* it;
  unsigned int period;

  /* create starting state: we chose 000..0001 */
  start = (char *) calloc(len, sizeof(char));
  start[len-1] = 1;

  period = 0;
  do {
    LFSR(&out, p, len, start, 1);
    period++;

    it = memchr(start, 1, len);
  } while (it && it  != start + len-1);

  free(start);
  return period;
}



/*
 * +--------------------+
 * |A5/1 LFSR Algorithm |
 * +--------------------+
 */

/**
 * \brief A5/1 Key Loading algorithm.
 *
 *
 * \param key 64-byte key to be used for the cipher.
 * \param frame 22-byte initial vector used for the cipher.
 * \param polynomials array of polynomials to be used per each registers
 * \param degreees degrees per each polynomial
 * \param n number of polynomials to be used
 *          (length of degrees[], polynomials[], and registers[]).
 *
 * \return states to be warmed up.
 */
static char** key_loading(const char* key,
                          const char* frame,
                          const char** polynomials,
                          const size_t*  degrees,
                          const size_t n)
{
  size_t i, j;
  char** registers;

  registers = (char**) malloc(sizeof(char*) * n);
  for (i=0; i!=n; i++)
    registers[i] = calloc(degrees[i], sizeof(char));

  for (i=0; i!=64; i++)
    for (j=0; j!=n; j++) {
      update(polynomials[j], degrees[j], registers[j]);
      registers[j][0] ^= key[i];
    }

  for (i=0; i!=22; i++)
    for (j=0; j!=n; j++) {
      update(polynomials[j], degrees[j], registers[j]);
      registers[j][0] ^= frame[i];
    }

  return registers;
}

static void a5_1_update(const char** polynomials,
                        const size_t* degrees,
                        char** registers)

{
  size_t j;
  char may_update;
  static const size_t clocks[] = {8, 10, 10};

  /* update using the majority function */
  for (j=may_update=0; j!=3; j++)
    if (registers[j][clocks[j]]) may_update++;
  may_update = (may_update > 1);
  for (j=0; j!=3; j++)
    if (registers[j][clocks[j]] == may_update)
      update(polynomials[j], degrees[j], registers[j]);

}

/**
 * \brief The A5/1 stream cipher.
 *
 * \param n     length of the output to be produced.
 * \param key   64-byte key to be used for the cipher.
 * \param dest  destination vector, must be capable of holding \ref n bytes.
 *
 * \return dest
 */
char* a5_1(char* dest, const char* key, const size_t n)
{
  char** states;
  size_t i;
  size_t j;

  static const char* frame = "\0\0\1\0\1\1\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0";
  static const size_t degrees[5] = {19, 22, 23, 11, 13};
  /**
   * Array of polynomials to be used per each registers:
   *   p₀ = x¹⁹ + x¹⁸ + x¹⁷ + x¹⁴ + 1
   *   p₁ = x²² + x²¹ + 1
   *   p₂ = x²³ + x²² + x²¹ + x⁸ + 1
   */
  static const char* polys[3] = {
    "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\0\1\1\1",
    "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1",
    "\1\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\1\1\1",
  };

  states = key_loading(key, frame, polys, degrees, 3);
  for (i=0; i!=100; i++)
    a5_1_update(polys, degrees, states);

  for (i=0; i!=n; i++) {
    /* compute output from all registers */
    for (j = dest[i] = 0; j != 3; j++)
      dest[i] ^= output(states[j], degrees[j]);
    a5_1_update(polys, degrees, states);

  }

  for (i=0; i!=3; i++)
    free(states[i]);
  free(states);

  return dest;
}



/*
 * +---------------------+
 * | MAJ5 LFSR Algorithm |
 * +---------------------+
 */

/*XXX. polynomials and degrees shall be global variables at this point. */
char maj5_update(const char** polynomials,
                 const size_t* degrees,
                 char** registers)
{
  size_t j;
  char may_update;
  static const size_t clocks[] = {8, 10, 10, 4, 6};

  /* update using the majority function */
  for (j=may_update=0; j!=5; j++)
    if (registers[j][clocks[j]]) may_update++;
  may_update = (may_update > 2);
  for (j=0; j!=5; j++)
    if (registers[j][clocks[j]] == may_update)
      update(polynomials[j], degrees[j], registers[j]);

  return may_update;
}


/**
 * \brief MAJ5 cipher.
 *
 * \param key a 64-bit key
 * \param n  length of the output stream cipher
 * \param dest the encrypted byte stream, of length n, not null-terminated.
 *
 * \return dest
 *
 */
char* maj5(char* dest, const char* key, const size_t n)
{
  char** states;
  size_t i;
  size_t j;

  static const char* frame = "\0\0\1\0\1\1\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0";
  static const size_t degrees[5] = {19, 22, 23, 11, 13};
  static const char* polys[5] = {
    /* p = x^19 + x^18 + x^17 + x^14 + 1 */
    "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\0\1\1\1",
    /* p = x^22 + x^21 + 1 */
    "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1",
    /* p = x^23 + x^22 + x^21 + x^8 + 1 */
    "\1\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\1\1\1",
    /*p = x^11 + x^2 + 1 */
    "\1\0\1\0\0\0\0\0\0\0\0\1",
    /* p = x^13 + x^4 + x^3 + x + 1 */
    "\1\1\0\1\1\0\0\0\0\0\0\0\0\1",
  };

  states = key_loading(key, frame, polys, degrees, 5);
  for (i=0; i!=100; i++)
    maj5_update(polys, degrees, states);

  for (i=0; i!=n; i++) {
    /* compute output from all registers */
    for (j = dest[i] = 0; j != 5; j++)
      dest[i] ^= output(states[j], degrees[j]);
    maj5_update(polys, degrees, states);
  }

  for (i=0; i!=5; i++)
    free(states[i]);
  free(states);

  return dest;
}



/*
 * +---------------------+
 * | ALL5 LFSR Algorithm |
 * +---------------------+
 */

static void all5_update(const char** polynomials,
                        const size_t* degrees,
                        char** registers)
{
  size_t i;

  for (i=0; i!=5; i++)
    update(polynomials[i], degrees[i], registers[i]);
}


/**
 * \brief MAJ5 cipher.
 *
 * \param key a 64-bit key
 * \param n  length of the output stream cipher
 * \param dest the encrypted byte stream, of length n, not null-terminated.
 *
 * \return dest
 *
 */
char* all5(char* dest, const char* key, const size_t n)
{
  char outputs[5];
  char** states;
  size_t i;
  size_t j;

  static const char* frame = "\0\0\1\0\1\1\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0";
  static const size_t degrees[5] = {19, 22, 23, 11, 13};
  static const char* polys[5] = {
    /* p = x^19 + x^18 + x^17 + x^14 + 1 */
    "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\0\1\1\1",
    /* p = x^22 + x^21 + 1 */
    "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1",
    /* p = x^23 + x^22 + x^21 + x^8 + 1 */
    "\1\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\1\1\1",
    /* p = x^11 + x^2 + 1 */
    "\1\0\1\0\0\0\0\0\0\0\0\1",
    /* p = x^13 + x^4 + x^3 + x + 1 */
    "\1\1\0\1\1\0\0\0\0\0\0\0\0\1"

  };

  states = key_loading(key, frame, polys, degrees, 5);
  for (i=0; i!=100; i++) all5_update(polys, degrees, states);

  for (i=0; i!=n; i++) {
   /**
    *  The output is computed using a semi-bent, balanced Boolean function
    *  f: (𝔽₂)⁵ → 𝔽₂
    *  (x₁,x₂,x₃,x₄,x₅) → x₁x₄ ⊕ x₂x₃ ⊕ x₂x₅ ⊕ x₃x₄
    */
   for (j=0; j!=5; j++) outputs[j] = output(states[j], degrees[j]);
   dest[i] = outputs[0]*outputs[3] ^ outputs[1]*outputs[2] ^
     outputs[1]*outputs[4] ^ outputs[2]*outputs[3];
   all5_update(polys, degrees, states);

  }

  for (i=0; i!=5; i++)
    free(states[i]);
  free(states);

  return dest;
}
