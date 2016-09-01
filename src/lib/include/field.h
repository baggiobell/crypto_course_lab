#ifndef _INCLUDE_FIELD_H_
#define _INCLUDE_FIELD_H_

#include <stdint.h>
#include <stdlib.h>

/* typedef char unsigned int8; */
typedef uint8_t int8;


int8 f2sum(int8 n, int8 a, int8 b);

int8 f2mul(int8 p, int8 n, int8 a, int8 b);

int8 f2exp(int8 p, int8 n, int8 a, int8 b);

int8 f2rot(int8 p, int8 n, int r);

int8 btoi(const char* s);

char* ptos(int8 n);

#endif
