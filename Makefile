CC = gcc
CFLAGS = -Wall -fPIC -O2
LDFLAGS = -shared
TARGET = build/liburing_shim.so 
SRCS = uring_shim.c
OBJS = $(SRCS:.c=.o)
HDR = uring_shim.h

all: $(TARGET)

$(TARGET): $(OBJS) | build
	$(CC) $(LDFLAGS) -o $@ $^

build:
	mkdir -p build

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -d /usr/local/lib
	install -m 755 $(TARGET) /usr/local/lib/
	install -m 644 $(HDR) /usr/local/include/
	ldconfig

.PHONY: all clean install