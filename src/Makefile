SERVER_OBJS=srv.o fsock.o
CLIENT_OBJS=cli.o fsock.o
LIB_OBJS=lib/field.o lib/bunny24.o lib/lfsr.o lib/rng.o lib/sponge.o lib/rsa.o
#CC=clang
CFLAGS=-Wall -Iinclude/ -Ilib/include/ -g
LDFLAGS=-lssl -lcrypto

all: server client sqrattack keys

client: $(CLIENT_OBJS) $(LIB_OBJS)
	$(CC) $(CLIENT_OBJS) $(LIB_OBJS) $(CFLAGS) $(LDFLAGS) -o $@

server: $(SERVER_OBJS) $(LIB_OBJS)
	$(CC) $(SERVER_OBJS) $(LIB_OBJS) $(CFLAGS) $(LDFLAGS) -o $@

sqrattack: $(LIB_OBJS) square_attack.o
	$(CC) square_attack.o  $(LIB_OBJS) $(CFLAGS) $(LDFLAGS) -o $@

keys: $(LIB_OBJS) keys.o
	$(CC) keys.o $(LIB_OBJS) $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f $(CLIENT_OBJS) $(SERVER_OBJS) server client
	rm -f keys.o keys
	rm -f square_attack.o sqrattack
	rm -f cs.fifo sc.fifo
	rm -f server_folder/received_messages.txt
