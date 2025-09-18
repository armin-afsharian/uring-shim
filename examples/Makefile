CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -pthread -I..
LDFLAGS = -L../build -Wl,-rpath=/usr/lib -luring_shim -luring -levent -levent_pthreads


SERVER_SRC = server-eventfd.c
SERVER_LIBEVENT_SRC = server-multithread-libevent.c
CLIENT_SRC = client.c


SERVER_TARGET = server-eventfd.out
SERVER_LIBEVENT_TARGET = server-multithread-libevent.out
CLIENT_TARGET = client.out


all: $(SERVER_TARGET) $(CLIENT_TARGET) $(SERVER_LIBEVENT_TARGET)


$(SERVER_TARGET): $(SERVER_SRC) $(SERVER_HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $ $(LDFLAGS)

$(SERVER_LIBEVENT_TARGET): $(SERVER_LIBEVENT_SRC) $(SERVER_HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $ $(LDFLAGS)

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) $(SERVER_LIBEVENT_TARGET)

.PHONY: all clean
