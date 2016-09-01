#ifndef _LFSR_H_
#define _LFSR_H_
#include <stdlib.h>

char *LFSR(char* dest,
           const char* p,
           size_t len,
           char* reg,
           size_t n);

unsigned int lfsr_period(char*, size_t);

char* maj5(char* dest, const char* key, const size_t n);

char* all5(char* dest, const char* key, const size_t n);

char* a5_1(char* dest, const char* key, const size_t n);

#endif
