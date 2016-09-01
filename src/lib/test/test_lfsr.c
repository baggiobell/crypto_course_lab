#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "lfsr.h"

void test_period(void)
{
  char* p;
  size_t degree;
  unsigned int period;

  /* test1 : x^3 + x^2 + x + 1 */
  degree = 3;
  p = "\1\1\1\1";
  period = lfsr_period(p, degree);
  printf("period of x^3+x^2+x+1 : %d\n", period);

  /* test2: x^3 + x^2 + 1 */
  degree = 3;
  p = "\1\0\1\1";
  period = lfsr_period(p, degree);
  printf("period of x^3+x^2+1 : %d\n", period);

  /* test3: x^5 + x^3 + 1 */
  degree = 5;
  p = "\1\0\0\1\0\1";
  period = lfsr_period(p, degree);
  printf("period of x^5+x^3+1 : %d\n", period);
}

void test_vector_lfsr(void)
{
  char output[20];
  char* expected;
  size_t degree;
  char* p;
  char reg[11];


  /* test 1
   *
     p = x^3 + x^2 + 1 ;
     LFSR(p,[1,0,1],10) ;
     States:
     [ 1, 0, 1 ],
     [ 1, 1, 0 ],
     [ 1, 1, 1 ],
     [ 0, 1, 1 ],
     [ 0, 0, 1 ],
     [ 1, 0, 0 ],
     [ 0, 1, 0 ],
     [ 1, 0, 1 ],
     [ 1, 1, 0 ],
     [ 1, 1, 1 ],
     [ 0, 1, 1 ]

     LFSR output stream:
     [ 1, 1, 0, 0, 1, 0, 1, 1, 1, 0 ]
  */
  degree = 3;
  p = "\1\0\1\1";
  memcpy(reg, "\1\0\1", degree * sizeof(char));
  LFSR(output, p, degree, reg, 10);
  expected = "\1\1\0\0\1\0\1\1\1\0";
  assert(!memcmp(output, expected, 10));


  /* test 2
   *

   p = x^3 + x^2 + 1 ;

   LFSR(p,[GF(2)!1,1,0],10) ;
   States:
   [ 1, 1, 0 ],
   [ 1, 1, 1 ],
   [ 0, 1, 1 ],
   [ 0, 0, 1 ],
   [ 1, 0, 0 ],
   [ 0, 1, 0 ],
   [ 1, 0, 1 ],
   [ 1, 1, 0 ],
   [ 1, 1, 1 ],
   [ 0, 1, 1 ],
   [ 0, 0, 1 ]

   LFSR output stream:
   [ 1, 0, 0, 1, 0, 1, 1, 1, 0, 0 ]
  */
  degree = 3;
  p = "\1\0\1\1";
  memcpy(reg, "\1\1\0", degree * sizeof(char));
  LFSR(output, p, degree, reg, 10);
  expected = "\1\0\0\1\0\1\1\1\0\0";
  assert(!memcmp(expected, output, 10));

  /* test 3
   *
   p = x^11 + x^2 + 1 ;

   LFSR(p,[1,0,1,1,1,1,0,0,0,1,1],20) ;

   States:
   [ 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1 ],
   [ 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1 ],
   [ 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0 ],
   [ 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0 ],
   [ 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0 ],
   [ 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1 ],
   [ 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1 ],
   [ 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1 ],
   [ 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1 ],
   [ 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0 ],
   [ 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1 ],
   [ 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1 ],
   [ 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0 ],
   [ 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1 ],
   [ 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0 ],
   [ 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1 ],
   [ 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1 ],
   [ 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0 ],
   [ 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0 ],
   [ 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1 ],
   [ 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0 ]


   LFSR output stream:
   [ 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0 ]
  */
  degree = 11;
  p = "\1\0\1\0\0\0\0\0\0\0\0\1";
  memcpy(reg, "\1\0\1\1\1\1\0\0\0\1\1", degree * sizeof(char));
  LFSR(output, p, degree, reg, 20);
  expected = "\1\0\1\0\1\1\0\0\1\0\0\1\0\0\0\1\1\1\1\0";
  assert(!strncmp(expected, output, 20));

}


void test_vector_maj5(void)
{
  char dst[228];
  char* key =
    "\0\1\0\0\1\0\0\0\1\1\0\0\0\1\0\0\1\0\1\0\0\0\1\0\1"
    "\1\1\0\0\1\1\0\1\0\0\1\0\0\0\1\1\1\0\1\0\1\0\1\1"
    "\0\1\1\0\0\1\1\1\1\1\1\0\1\1\1";

  maj5(dst, key, 228);
  maj5(dst, key, 228);

  /*
    r1:[0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0]
    r2:[1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
        0, 1, 0]
    r3:[1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0,
        0, 0, 1, 1]
    r4:[1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0]
    r5:[1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1]
    Output Stream:
    [ 0 ]
  */
  assert(!dst[0]);
  assert(!memcmp(dst, "\0\0\1\0", 4));

  assert(!memcmp(dst,
                 "\0\0\1\0\1\1\1\0\0\1\0\0\1\1\1\0\1\1\0\1\0\0\1\0\0\1\0"
                 "\1\1\1\0\0\1\0\1\1\1\0\1\1\0\0\1\0\1\1\0\1\1\1\0\1\1\1"
                 "\1\1\0\1\0\1\0\1\0\1\1\0\1\1\1\0\0\0\0\0\1\0\0\1\1\1\0"
                 "\1\1\1\0\0\1\0\1\0\0\0\0\1\1\0\1\0\1\0\0\1\1\1\1\1\0\1"
                 "\0\0\0\0\0\1\1\1\1\1\1\0\1\0\1\1\0\0\0\1\0\1\1\0\0\0\0"
                 "\0\1\1\0\0\0\0\1\0\0\1\0\1\0\0\1\0\1\0\1\1\0\1\1\0\1\0"
                 "\1\1\1\0\0\1\0\0\1\1\0\1\1\0\1\1\0\1\1\1\1\0\1\0\1\0\1"
                 "\1\1\0\1\1\0\0\1\0\0\1\0\1\0\1\1\1\0\0\0\0\1\1\1\1\0\0"
                 "\0\0\1\0\1\1\0\0\1\1\0\0", 228));

}

void test_vector_all5(void)
{
  char *key = "\0\1\0\0\1\0\0\0\1\1\0\0\0\1\0\0\1\0\1\0\0\0\1\0\1\1\1"
    "\0\0\1\1\0\1\0\0\1\0\0\0\1\1\1\0\1\0\1\0\1\1\0\1\1\0\0"
    "\1\1\1\1\1\1\0\1\1\1";
  char dst[228];

  all5(dst, key, 228);
  assert(!memcmp(dst,
                 "\1\0\0\0\1\1\1\0\0\1\0\0\1\1\0\1\0\1\0\1\1\0\1\0\1\0\0\0\1\0"
                 "\0\0\0\1\0\0\0\0\0\0\1\1\0\1\0\0\0\1\0\1\0\0\0\1\0\1\0\1\0\0"
                 "\0\0\0\1\0\0\0\0\0\1\0\1\0\1\1\0\1\0\0\1\1\0\0\0\1\0\0\1\0\1"
                 "\0\0\0\1\0\1\0\0\0\0\0\1\0\1\1\0\0\0\0\0\1\0\0\0\0\1\1\1\0\0"
                 "\1\0\0\1\1\1\0\0\1\1\1\1\0\0\1\0\0\0\0\0\0\0\1\0\0\0\0\0\1\0"
                 "\1\1\0\1\1\1\1\0\0\1\0\0\0\0\0\1\1\0\1\1\0\1\0\0\0\1\0\0\0\0"
                 "\0\1\0\0\1\1\1\0\0\1\0\1\1\0\0\0\0\1\1\1\1\1\1\1\1\0\0\1\1\0"
                 "\0\1\0\0\0\0\0\0\1\1\0\0\0\0\0\1\1\0",228));
}

void test_vector_a51(void)
{
  char* key = "\0\1\0\0\1\0\0\0\1\1\0\0\0\1\0\0\1\0\1\0\0\0\1\0\1\1\1\0\0"
    "\1\1\0\1\0\0\1\0\0\0\1\1\1\0\1\0\1\0\1\1\0\1\1\0\0\1\1\1\1\1\1\0\1\1\1";
  char dst[228];

  a5_1(dst, key, 228);
  assert(!memcmp(dst,
                 "\1\0\1\0\1\0\0\1\1\0\1\0\0\1\1\1\0\1\0\1\0\1\0\1\0\0\1\0\1\1"
                 "\0\0\0\0\0\1\0\1\1\1\1\1\1\1\0\1\0\0\0\0\0\0\1\0\1\0\1\0\0\0"
                 "\1\1\0\1\0\1\0\1\1\0\1\1\0\1\1\1\0\0\0\0\1\1\0\0\0\0\1\0\1\0"
                 "\1\0\1\1\0\1\0\0\1\1\1\0\0\1\0\1\0\0\0\1\1\0\0\0\0\0\0\1\0\0"
                 "\1\0\0\1\1\1\1\1\1\0\1\0\0\1\1\0\1\0\1\1\0\1\0\0\0\1\1\0\1\0"
                 "\1\1\1\0\1\0\1\0\1\1\1\1\1\1\0\1\1\0\1\1\0\0\1\0\1\0\0\1\0\0"
                 "\1\1\0\1\1\0\1\0\0\1\1\0\0\1\0\1\1\1\1\1\0\0\1\0\0\0\0\0\1\1"
                 "\0\1\1\0\1\1\1\1\1\0\0\0\1\1\0\1\0\1", 228));
}

int main(int argc, char** argv)
{
  test_period();
  test_vector_lfsr();
  test_vector_maj5();
  test_vector_all5();
  test_vector_a51();
  return 0;
 }