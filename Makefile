CC=clang
OPENSSL=/opt/homebrew/Cellar/openssl@3/3.1.3
INCLUDE=$(OPENSSL)/include/
CFLAGS=-c -I$(INCLUDE) 

all: server client

server: server.c
	$(CC) server.c -I$(INCLUDE) -L$(OPENSSL) -o server $(OPENSSL)/lib/libcrypto.a -ldl -lpthread

client: client.c
	$(CC) client.c -I$(INCLUDE) -L$(OPENSSL) -o client $(OPENSSL)/lib/libcrypto.a -ldl -lpthread

clean:
	rm -rf server