#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "field.h"


int test_type(void)
{
  int8 a;

  a = 0xff;
  a++;
  assert(!a);

  a = (0xff << 1) >> 2;
  assert(a == btoi("1111111"));
  return 1;
}

int test_sum(void)
{
  int8 a;
  int8 b;
  int8 c;
  int8 p;

  p = 8;
  a =  4 | 2 | 1;
  b =  0 | 2 | 1;
  c =  4 | 0 | 0;
  assert(f2sum(p, a, b) == c);

  p = 5;
  a = 4 ;
  b = 0 | 2 | 1;
  c = 4 | 2 | 1;
  assert(f2sum(p, a, b) == c);

  return 1;
}

int test_multiplication(void)
{
  int8 a, b, c, p;

  a = btoi("101");
  b = btoi("10");
  p = btoi("1001");
  c = btoi("11");
  assert(f2mul(p, 3, a, b) == c);

  return 1;
}

int test_exponential(void)
{
  int8 a, c, p;

  a = btoi("110");
  p = btoi("100001");
  c = btoi("11011");
  assert(f2exp(p, 5, a, 3) == c);

  a = btoi("10");
  p = btoi("1011011");
  c = btoi("100011");
  assert(f2exp(p, 6, a, 45) == c);


  a = btoi("10");
  p = btoi("1011011");
  c = btoi("10011");
  assert(f2exp(p, 6, a, 16) == c);

   return 1;
}


int test_rotate(void)
{
  int8 a, c;

  a = btoi("01011001");
  c = btoi("10101100");
  assert(f2rot(a, 8, 1) == c);

  a = btoi("01011001");
  c = btoi("10110010");
  assert(f2rot(a, 8, -1) == c);

  return 1;
}


int main(int argc, char ** argv)
{
  test_type();

  test_multiplication();
  test_sum();
  test_rotate();
  test_exponential();

  return 0;
}
