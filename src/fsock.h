#ifndef _FSOCK_H_
#define _FSOCK_H_

#include <openssl/bn.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <error.h>

#define dbgprint(s, n) \
  { printf(s); BN_print_fp(stdout, n); printf("\n");}

#define sabort() \
  error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__, "%d", errno)

#define CONNECTION_STRING \
  "Hello!"
#define CLOSE_CONNECTION_STRING \
  "Bye"
#define DECRYPTED_STRING \
  "MESSAGE RECEIVED AND DECRYPTED!"
#define CORRUPTED_STRING  \
  "CORRUPTED MESSAGE RECEIVED!"
#define OK_STRING \
  "OK"
#define MSG_SIZE_MAX \
  2048
#define RND_TOKEN_SIZE \
  16
#define ENCRYPTED_MSG_SIZE_MAX \
  128
#define HASH_SIZE \
  20
#define KEY_SIZE \
  4


void screate(const char *path);

int sopen(const char *path, int mode);

void sclose(const int fd);

void swrite(char *buf, int size, int fd);

void swrite_bn(BIGNUM *a, int fd);

int sread(char *dest, int fd);

int sread_bn(BIGNUM** a, int fd);

int sread_string(const char *s, size_t slen, int fd);


void read_bn_pair(const char *path,
                  BIGNUM** a,
                  BIGNUM** b);

void ciphersuite_encode(char suite_id,
                        int *symm_cipher,
                        int *hash,
                        int* asymm_cipher);

void sdecrypt(char *dest, int cipher_id, char *s, size_t len, char *key);
void sencrypt(char *dest, int cipher_id, char *s, size_t len, char *key);

#define sread_HELLO(fd) \
  sread_string(CONNECTION_STRING, strlen(CONNECTION_STRING), fd)
#define swrite_HELLO(fd) \
  swrite(CONNECTION_STRING, strlen(CONNECTION_STRING), fd)

#define sread_DECRYPTED_STRING(fd) \
  sread_string(DECRYPTED_STRING, strlen(DECRYPTED_STRING), fd)
#define swrite_DECRYPTED_STRING(fd) \
  swrite(DECRYPTED_STRING, strlen(DECRYPTED_STRING), fd)

#define swrite_CORRUPTED_STRING(fd) \
  swrite(CORRUPTED_STRING, strlen(CORRUPTED_STRING), fd)

#define swrite_OK(fd) \
  swrite(OK_STRING, strlen(OK_STRING), fd)
#define sread_OK(fd) \
  sread_string(OK_STRING, strlen(OK_STRING), fd)

#define sread_BYE(fd) \
  sread_string(CLOSE_CONNECTION_STRING, strlen(CLOSE_CONNECTION_STRING), fd)
#define swrite_BYE(fd) \
  swrite(CLOSE_CONNECTION_STRING, strlen(CLOSE_CONNECTION_STRING), fd)

#endif
