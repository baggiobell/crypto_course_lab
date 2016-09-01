#include "common.h"

void print_buff(u_int8_t * buff, size_t buff_size)
{
  int i = 0, j;

  while (i < buff_size) {
    j = 0;
    while (((j + i) < buff_size) && (j < 16)) {
      fprintf(stderr,"%02X ",buff[i+j]);
      j++;
    }

    while (j < 16) {
      fprintf(stderr,"-- ");
      j++;
    }
    fprintf(stderr," *** ");

    j = 0;
    while (((j + i) < buff_size) && (j < 16)) {
      fprintf(stderr, "%c", isprint(buff[i+j]) ? buff[i+j] : '.');
      j++;
    }

    while (j < 16) {
      fputc('.', stderr);
      j++;
    }

    i += j;
    fputc('\n', stderr);
  }
}

int write_OK(int channel_fd)
{
  return write_msg(channel_fd,
                   (const u_int8_t *) OK_STRING,
                   strlen(OK_STRING));
}

int write_BYE(int channel_fd)
{
  return write_msg(channel_fd,
                    (const u_int8_t *) CLOSE_CONNECTION_STRING,
                    strlen(CLOSE_CONNECTION_STRING));
}

int open_channel(const char * pathname)
{
  int fd;

  /* Open the FIFO in pathname */
  if ((fd = open(pathname,O_RDWR)) < 0) {
    perror("open()");
    exit(1);
  }

  return fd;
}

void close_channel(int channel_fd)
{
  /* Close the file descriptor */
  close(channel_fd);
}

ssize_t read_msg(int channel_fd, u_int8_t ** msg)
{
  ssize_t read_len;
  u_int16_t msg_size;
  static u_int8_t msg_buff[MSG_SIZE_MAX];

  /* The first 16 bits represents the message size */
  if (read(channel_fd, (void *)&msg_size, sizeof(msg_size)) < 0 ) {
    perror("read()");
    exit(1);
  }

  fprintf(stderr,"Reading size:\n");
  print_buff((u_int8_t *)(&msg_size),sizeof(msg_size));

  /* Verify that the size of the message is no more than MSG_SIZE_MAX bytes */
  if (msg_size >= MSG_SIZE_MAX) {
    fprintf(stderr,"Message too large\n");
    return -1;
  }

  /* Read msg_size bytes from the channel */
  if ((read_len = read(channel_fd, (void *)msg_buff, msg_size)) < 0 ) {
    perror("read()");
    exit(1);
  }

  /* Assign the buffer to msg */
  *msg = msg_buff;

  fprintf(stderr,"Reading message:\n");
  print_buff((u_int8_t *)(*msg), msg_size);

  return read_len;
}

ssize_t write_msg(int channel_fd, const u_int8_t * msg, u_int16_t msg_size)
{
  /* Send the size */
  if (write(channel_fd, (const void *)&msg_size, sizeof(msg_size)) < 0) {
    perror("write()");
    exit(1);
  }

  fprintf(stderr, "Writing size:\n");
  print_buff((u_int8_t *)&msg_size, sizeof(msg_size));

  /* Send the message */
  if (write(channel_fd, (const void *)msg, msg_size) < 0) {
    perror("write()");
    exit(1);
  }

  fprintf(stderr, "Writing message:\n");
  print_buff((u_int8_t *)msg, msg_size);

  return msg_size;
}

int read_string(int channel_fd, const char * str)
{
  size_t read_len;
  u_int8_t * msg;

  read_len = read_msg(channel_fd, &msg);
  if (read_len != strlen(str) ||
      memcmp(msg,str,strlen(str)))
    return -1;
  else
    return 0;
}

