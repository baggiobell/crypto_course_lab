#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>

#include "fsock.h"
#include "rng.h"
#include "rsa.h"
#include "sponge.h"

#define SRV_PUBKEY_FILE  \
  "client_folder/server_rsa64_public_key.txt"
#define CLI_PRIVKEY64_FILE \
  "client_folder/client_rsa64_private_key.txt"
#define CLI_PRIVKEY512_FILE \
  "client_folder/client_rsa512_private_key.txt"
#define CIPHERSUITE_FILE \
    "client_folder/client_cipher_suite.txt"
#define MESSAGE_FILE \
    "client_folder/client_message.txt"

static int get_message(char *dest)
{
  FILE *f;
  int i;

  if (!(f = fopen(MESSAGE_FILE, "r"))) sabort();
  fgets(dest, ENCRYPTED_MSG_SIZE_MAX, f);

  if (fclose(f) < 0) sabort();
  i = strlen(dest);
  while (i%3)
    dest[i++] = '\0';
  return i;
}

int main(int argc, char **argv)
{
  /* command-line args */
  char
    *rpath = "./sc.fifo",
    *wpath = "./cs.fifo",
    *client_name = "Pippo";
  BIGNUM
    *srv_rsa_e = NULL,
    *srv_rsa_n = NULL,
    *cli_rsa_d = NULL,
    *cli_rsa_n = NULL,
    *r = NULL,
    *r1 = NULL,
    *c,
    *k = NULL;
  /* file descriptors */
  int rfd, wfd;
  /* cipehrsuites */
  FILE *fcipher;
  char ciphersuite;
  int symm_cipher, hash, asymm_cipher;
  /* messaging */
  char hashbuf[40];
  size_t message_size;
  char
    message[ENCRYPTED_MSG_SIZE_MAX],
    cipher[ENCRYPTED_MSG_SIZE_MAX],
    key[KEY_SIZE+10];

  rfd = sopen(rpath, O_RDONLY);
  wfd = sopen(wpath, O_WRONLY);

  /* GET public rsa key of S, (s_puk,n) */
  read_bn_pair(SRV_PUBKEY_FILE, &srv_rsa_n, &srv_rsa_e);
  /* GET private rsa key of C, (s_prk,n) */
  read_bn_pair(CLI_PRIVKEY64_FILE, &cli_rsa_n, &cli_rsa_d);
  /* GET my cipher suite from file */
  fcipher = fopen(CIPHERSUITE_FILE, "r");
  ciphersuite = fgetc(fcipher);
  ciphersuite_encode(ciphersuite,
                     &symm_cipher,
                     &hash,
                     &asymm_cipher);
  fclose(fcipher);


  /* connecting! */
  swrite_HELLO(wfd);
  sread_OK(rfd);

  /** SERVER AUTHENTICATION **/
  /* CREATE a random number r */
  bn_rng(&r, RND_TOKEN_SIZE);
  /* ENCRYPT r using (s_puk,n) -> c = r^s_puk mod n */
  c = BN_dup(r);
  rsa_encrypt(c, srv_rsa_e, srv_rsa_n);

  /* WRITE c to S */
  swrite_bn(c, wfd);
  /* READ r' from C */
  sread_bn(&r1, rfd);

  /* CHECK if r = r' */
  if (BN_cmp(r, r1) != 0) {
    fprintf(stderr, "Error: r and r' mismatch!\n");
    goto bye;
  }

  /** CLIENT AUTHENTICATION **/
  /* SEND client_name to S */
  swrite(client_name, strlen(client_name), wfd);
  sread_bn(&c, rfd);
  /* READ c from S */
  rsa_decrypt(c, cli_rsa_d, cli_rsa_n);
  swrite_bn(c, wfd);

  /** CIPHERSUITE NEGOTIATION **/
  /* SEND my cipher suite to server */
  swrite(&ciphersuite, 1, wfd);
  /* GET private key file (if any) */
  if (asymm_cipher == 6)
    read_bn_pair(CLI_PRIVKEY512_FILE, &cli_rsa_n, &cli_rsa_d);
  /* compute k from h and my private key */
  sread_bn(&k, rfd);
  rsa_decrypt(k, cli_rsa_d, cli_rsa_n);
  BN_bn2bin(k, (unsigned char *) key);
  /* GET message from file */
  message_size = get_message(message);
  /* hash the message */
  spongebunny(hashbuf, message, message_size);
  swrite(hashbuf, HASH_SIZE, wfd);
  /* encrypt the message */
  sencrypt(cipher, symm_cipher,
           message, message_size, key);
  swrite(cipher, message_size, wfd);
  /* Disconnection */
  sread_DECRYPTED_STRING(rfd);

 bye:
  swrite_BYE(wfd);

  BN_free(srv_rsa_n);
  BN_free(srv_rsa_e);
  BN_free(r);
  BN_free(c);
  BN_free(r1);

  sclose(rfd);
  sclose(wfd);
  return 0;
}
