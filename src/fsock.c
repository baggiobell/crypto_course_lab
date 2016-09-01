#include "fsock.h"
#include "lfsr.h"
#include "bunny24.h"

#include <openssl/bn.h>

#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

typedef uint16_t twobytes;


void print_buff(char *sbuff, size_t buff_size) {
  char unsigned *buff = (unsigned char *) sbuff;
  int i = 0, j;

  for (i=0; i < buff_size; i+= j) {
    for (j=0; ((j + i) < buff_size) && (j < 16); j++)
      fprintf(stderr,"%02X ",buff[i+j]);

    for (;j < 16; j++) fprintf(stderr,"-- ");

    fprintf(stderr," *** ");
    for (j=0; ((j + i) < buff_size) && (j < 16); j++)
      fprintf(stderr, "%c",
              isprint(buff[i+j]) ? buff[i+j] : '.');

    for (;j < 16; j++)
      fputc('.',stderr);
    fputc('\n',stderr);
  }
}

void screate(const char* path)
{
  if (unlink(path) < 0 && errno != ENOENT)
    sabort();
  if (mkfifo(path, 0600) < 0)
    sabort();
}

int sopen(const char* path, int mode)
 {
   int fd;

   if ((fd = open(path, O_RDWR)) < 0)
     sabort();

  return fd;
}

void sclose(const int fd)
{
  close(fd);
  //if (close(fd) < 0) sabort();
}

void swrite(char *buf, int size, int fd)
{
  twobytes msg_size;
  msg_size = size;

  if (write(fd, (const void *) &msg_size, sizeof(twobytes)) != 2)
    sabort();
  if (write(fd, (const void *) buf, (msg_size * sizeof(char))) != msg_size)
    sabort();

  fprintf(stderr, "Writing message: \n");
  print_buff(buf, size);

}


int sread(char *dest, int fd)
{
  twobytes msg_size;

  if (read(fd, (void *) &msg_size, sizeof(twobytes)) != 2)
    sabort();
  if (read(fd, (void *) dest, msg_size) != msg_size)
    sabort();

  fprintf(stderr, "Reading message: \n");
  print_buff(dest, msg_size);
  return msg_size;
}

int sread_bn(BIGNUM** a, int fd)
{
  static char sa[MSG_SIZE_MAX];
  int size;

  if (!(size = sread(sa, fd))) sabort();
  return BN_hex2bn(a, sa);

}

void swrite_bn(BIGNUM *a, int fd)
{
  char *s;
  s = BN_bn2hex(a);
  swrite(s, strlen(s)+1, fd);
  OPENSSL_free(s);
}

int sread_string(const char *s, size_t slen, int fd)
{
  twobytes msg_size;
  static char buf[MSG_SIZE_MAX];

  if (read(fd, (void *) &msg_size, sizeof(twobytes)) != 2)
    sabort();
  if (msg_size != slen)
    return 0;

  if (read(fd, (void *) buf, msg_size) < 0)
    sabort();
  return !memcmp(buf, s, slen);
}


void read_bn_pair(const char *path,
                  BIGNUM** a,
                  BIGNUM** b)
{
  static char fst[129] = {0};
  static char snd[129] = {0};
  FILE *f;

  if (!(f = fopen(path, "r"))) sabort();
  if (fscanf(f, "%128[^,],%128[^,]", fst, snd) != 2)
    sabort();
  BN_hex2bn(a, fst);
  BN_hex2bn(b, snd);
}

void ciphersuite_encode(char suite_id,
                        int *symm_cipher,
                        int *hash,
                        int* asymm_cipher) {
  switch (suite_id) {
  case 'A':
    *symm_cipher = 1;
    *hash = 4;
    *asymm_cipher = 5;
    break;
  case 'B':
    *symm_cipher = 1;
    *hash = 4;
    *asymm_cipher = 6;
    break;
  case 'C':
    *symm_cipher = 2;
    *hash = 4;
    *asymm_cipher = 5;
    break;
  case 'D':
    *symm_cipher = 2;
    *hash = 4;
    *asymm_cipher = 6;
    break;
  case 'E':
    *symm_cipher = 3;
    *hash = 4;
    *asymm_cipher = 5;
    break;
  case 'F':
    *symm_cipher = 3;
    *hash = 4;
    *asymm_cipher = 6;
    break;
  default:
    sabort();
  }
}

static void scipher(char *dest,
                    int cipher_id,
                    char *s,
                    size_t len,
                    char *key) {
  char skey[64];
  int i, j;
  int8 c;
  char *buf;

  buf = calloc(sizeof(char), len * 8);
  if (!buf) sabort();

  /*
   *  uniformity: using the same actual keylength of the stream cipher. This way
   *  it is guaranteed a fixed overhead in data transfer.
   */
  for (i=0; i!=8*3; i++) {
    c = ((unsigned char) key[i/8]) & (0x01 << (i%8));
    skey[i] = (c == 0) ? '\0':'\1';
  }
  bzero(skey + 8*3, 64-8*3);

  if (cipher_id == 2)
    all5(buf, skey, len*8);
  else
    maj5(buf, skey, len*8);

  for (i=0; i<len; i++) {
    for (c=0, j=i*8; j!= (i+1)*8; j++)
      c = c<<1 | buf[j];
    dest[i] = s[i] ^ c;
  }
  free(buf);

}

static const char *iv = "abcd";

void sdecrypt(char *dest,
              int cipher_id,
              char *s,
              size_t len,
              char *key) {
  if (cipher_id == 1)
    bunny24_cbc_decrypt(dest, key, iv, s, len);
  else
    scipher(dest, cipher_id, s, len, key);
}


void sencrypt(char *dest,
             int cipher_id,
             char *s,
             size_t len,
             char *key) {
  if (cipher_id == 1)
    bunny24_cbc_encrypt(dest, key, iv, s, len);
  else
    scipher(dest, cipher_id, s, len, key);
}
