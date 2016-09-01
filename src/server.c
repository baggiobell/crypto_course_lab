#include "common.h"

int open_fifo(const char * pathname)
{
  /* Recreate the FIFO in pathname */
  unlink(pathname);
  if (mkfifo(pathname,0600) < 0) {
    perror("mkfifo()");
    exit(1);
  }

  /* Open the channel */
  return open_channel(pathname);
}

int wait_connection(int channel_fd)
{
  ssize_t msg_size;
  u_int8_t * buff;

  /* Wait a connection from the client */
  if (((msg_size = read_msg(channel_fd, &buff)) < 0) ||
      (msg_size != strlen(CONNECTION_STRING) ||
       strncasecmp((const char *)CONNECTION_STRING, (const char *)buff,msg_size)))
    /* Protocol error */
    return -1;
  else
    return 0;
}

int main(int argc, char ** argv)
{
  int sc_fifo_fd, cs_fifo_fd;
  u_int8_t * buff;

  /* Mandatory arguments */
  if (argc < 4 ||
      !argv[1] || !argv[2] || !argv[3]) {
    fprintf(stderr,"server [server->client fifo] [client->server fifo] [password file]\n");
    exit(1);
  }

  /* Main loop */
 main_loop:
//	do {
  /* Open the server->client fifo */
  fprintf(stderr, "Opening server->client fifo...\n");
  sc_fifo_fd = open_fifo(argv[1]);

  /* Open the client->server fifo */
  fprintf(stderr, "Opening client->server fifo...\n");
  cs_fifo_fd = open_fifo(argv[2]);

  /* Wait for a connection */
  fprintf(stderr, "Waiting connection...\n");
  if (wait_connection(cs_fifo_fd) < 0) {
    fprintf(stderr, "Communication error...\n");
    goto next1;
  }

  /* Write OK */
  write_OK(sc_fifo_fd);

  /* Server authentication */
  read_msg(cs_fifo_fd, &buff);
  fprintf(stderr, "%c\n", buff[2]);

  // GET private rsa key of S, (s_prk,n) from "server_folder/server_rsa_private_key.txt"
  /* ... */
  // READ c from S
  /* ... */
  // DECRYPT c using (s_prk,n) -> r' = c^s_prk mod n
  /* ... */
  // SEND r' to C
  /* ... */

  /* Client authentication */
  // READ client name nm of C
  /* ... */
  // GET the public rsa keys of the possible clients associated to each name, (names[],c_puk[],n[]) from "client_folder/clients_rsa_public_keys.txt"
  /* ... */
  // EXTRACT from (names[],c_puk[],n[]) the pair (c_puk[i],n[i]) where names[i] = nm
  /* ... */
  // CREATE a pseudo-random message r
  /* ... */
  // ENCRYPT r using s_puk[i] -> c = r^s_puk[i] mod n[i]
  /* ... */
  // WRITE c to C
  /* ... */

  /* Negotiation of the cipher suite */
  /* ... */

  /* Negotiation of the private key */
  /* ... */

  /* Encrypt communication */
  /* ... */

  /* Disconnection */
  /* ... */

 next1: // to be used when server writes the BYE string
  /* Close current connection */
  fprintf(stderr,"Closing connection...\n");
  write_BYE(sc_fifo_fd);
  close_channel(sc_fifo_fd);
  close_channel(cs_fifo_fd);
  //    exit(0) ;
  goto main_loop;

 next2: // to be used when client writes the BYE string
	/* Close connection with the server */
  fprintf(stderr,"Closing connection...\n");

  /* Expect BYE */
  if (read_string(cs_fifo_fd,CLOSE_CONNECTION_STRING) < 0) {
    fprintf(stderr,"Communication error\n");
    goto next2;
  }

  close_channel(sc_fifo_fd);
  close_channel(cs_fifo_fd);

  goto  main_loop ;

  //	} while(1);

  //	close_channel(sc_fifo_fd);
  //	close_channel(cs_fifo_fd);

  exit(0);
}

