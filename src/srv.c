#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>

#include "fsock.h"
#include "rsa.h"
#include "rng.h"
#include "sponge.h"

#define SRV_PRIVKEY_FILE  \
  "server_folder/server_rsa64_private_key.txt"
#define CLIENT_NAMES_FILE_RSA64 \
  "server_folder/clients_rsa64_public_keys.txt"
#define CLIENT_NAMES_FILE_RSA512 \
  "server_folder/clients_rsa512_public_keys.txt"
#define CIPHERSUITE_FILE \
  "server_folder/server_cipher_suite_list.txt"
#define MESSAGE_STORE_FILE \
  "server_folder/received_messages.txt"

static int get_client(const char *names_file,
                      const char *name,
                      BIGNUM **e, BIGNUM** n)
{
  int ret;

  FILE *f;
  static char sname[129], se[129], sn[129];

  if (!(f = fopen(names_file, "r"))) sabort();
  while (!feof(f)) {
    fscanf(f, "%128s %128s %128s", sname, sn, se);
    if ((ret = !strcmp(name, sname))) break;
  }
  if (ret) {
    BN_hex2bn(e, se);
    BN_hex2bn(n, sn);
  }
  return ret;
}

static int get_cipher(const char cipher)
{
  char c;
  FILE *f;

  if (!(f = fopen(CIPHERSUITE_FILE, "r"))) sabort();
  while (!feof(f)) {
    c = fgetc(f);
    if (c == cipher) return 1;
  }
  return 0;
}


int main(int argc, char **argv)
{
  char
    *rpath = "cs.fifo",
    *wpath = "sc.fifo";
  /* internal */
  int rfd, wfd;
  char
    cliname[MSG_SIZE_MAX],
    buf[MSG_SIZE_MAX],
    message[MSG_SIZE_MAX],
    key[KEY_SIZE+10];
  size_t cliname_size, buf_size;
  char computed_hash[40], got_hash[40];
  BIGNUM
    *srv_rsa_d = NULL,
    *srv_rsa_n = NULL,
    *cli_rsa_e = NULL,
    *cli_rsa_n = NULL,
    *c = NULL,
    *r = NULL,
    *r1 = NULL,
    *k = NULL,
    *h;
  /* ciphersuite */
  char ciphersuite;
  int symm_cipher, hash, asymm_cipher;
  /* final file */
  FILE *message_store;

  /* open input and output file descriptors */
  screate(rpath);
  rfd = sopen(rpath, O_RDONLY);
  screate(wpath);
  wfd = sopen(wpath, O_WRONLY);
  /*
   *  GET private rsa key of S, (s_prk,n) from
   *  "server_folder/server_rsa_private_key.txt"
   */
  read_bn_pair(SRV_PRIVKEY_FILE, &srv_rsa_n, &srv_rsa_d);


  while (1) {
    sread_HELLO(rfd);
    swrite_OK(wfd);

    /** SERVER AUTHENTICATION **/
    /* READ c from C */
    sread_bn(&c, rfd);
    /* DECRYPT c using (s_prk,n) -> r' = c^s_prk mod n */
    rsa_decrypt(c, srv_rsa_d, srv_rsa_n);
    /* SEND r' to C */
    swrite_bn(c, wfd);

    /** CLIENT AUTHENTICATION **/
    cliname_size = sread(cliname, rfd);
    cliname[cliname_size] = '\0';
    if (!strcmp(cliname, CLOSE_CONNECTION_STRING))
      continue;

    fprintf(stderr, "Client '%s' connected!\n", cliname);
    if (!get_client(CLIENT_NAMES_FILE_RSA64, cliname, &cli_rsa_e, &cli_rsa_n)) {
      fprintf(stderr, "Unrecognized client '%s'\n",
              cliname);
      goto bye;
    }
    /* CREATE a pseudo-random message r */
    bn_rng(&r, RND_TOKEN_SIZE);
    /* ENCRYPT r using c_puk[i] -> r' = r^c_puk[i] mod n[i] */
    BN_copy(c, r);
    rsa_encrypt(c, cli_rsa_e, cli_rsa_n);
    /* WRITE c to C */
    swrite_bn(c, wfd);
    /* READ r' from C */
    sread_bn(&r1, rfd);
    /* CHECK that r = r' */
    if (BN_cmp(r, r1) != 0) goto bye;

    /** CIPEHRSUITE NEGOTIATION **/
    /* READ list from C */
    sread(&ciphersuite, rfd);
    if (!get_cipher(ciphersuite)) {
      fprintf(stderr, "Invalid cipher '%c'!\n", ciphersuite);
      goto bye;
    }
    ciphersuite_encode(ciphersuite,
                       &symm_cipher,
                       &hash,
                       &asymm_cipher);
    if (asymm_cipher == 6 &&
        !get_client(CLIENT_NAMES_FILE_RSA512, cliname, &cli_rsa_e, &cli_rsa_n)) sabort();

    /* CREATE a pseudo-random key */
    bn_rng(&k, RND_TOKEN_SIZE);
    BN_bn2bin(k, (unsigned char *) key);
    /* ENCRYPT key */
    h = BN_dup(k);
    rsa_encrypt(h, cli_rsa_e, cli_rsa_n);
    /* WRITE h to C */
    swrite_bn(h, wfd);
    /* Encrypt communication */
    /* READ hash */
    if (sread(got_hash, rfd) != HASH_SIZE) sabort();
    /* READ message */
    buf_size = sread(buf, rfd);
    sdecrypt(message, symm_cipher, buf,
             buf_size, key);
    spongebunny(computed_hash, message, buf_size);
    /* CHECK hash */
    if (memcmp(computed_hash, got_hash, HASH_SIZE)) {
      swrite_CORRUPTED_STRING(wfd);
      goto bye;
    }
    swrite_DECRYPTED_STRING(wfd);

    /* open message_store and write the message. */
    if (!(message_store = fopen(MESSAGE_STORE_FILE, "a")))
      sabort();
    fprintf(message_store, "%s\n", message);
    printf("Message: %s\n", message);
    if (fclose(message_store) < 0) sabort();
  bye:
    sread_BYE(rfd);
  }

  BN_free(srv_rsa_d);
  BN_free(srv_rsa_n);
  BN_free(c);
  BN_free(cli_rsa_e);
  BN_free(cli_rsa_n);
  BN_free(r);
  BN_free(r1);
  BN_free(k);
  BN_free(h);

  sclose(rfd);
  sclose(wfd);
  return 0;
}
