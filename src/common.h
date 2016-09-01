#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/bn.h>

#define MSG_SIZE_MAX		2048
#define CONNECTION_STRING	"Hello!"
#define CLOSE_CONNECTION_STRING	"Bye"
#define OK_STRING		"OK"

void print_buff(u_int8_t *, size_t);
int open_channel(const char *);
void close_channel(int);
ssize_t read_msg(int, u_int8_t **);
ssize_t write_msg(int, const u_int8_t *, u_int16_t);

int read_string(int, const char *);
int write_OK(int);
int write_BYE(int);

#endif
