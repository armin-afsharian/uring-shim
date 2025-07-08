# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -pthread -I..
LDFLAGS = -L../build -Wl,-rpath=/usr/lib -luring_shim -luring -levent -levent_pthreads

# Source files
SERVER_SRC = server.c
SERVER_LIBEVENT_SRC = server_multithread_libevent.c
CLIENT_SRC = client.c

# Target executables
SERVER_TARGET = server.out
SERVER_LIBEVENT_TARGET = server_libevent.out
CLIENT_TARGET = client.out

# Default target - build both client and server
all: $(SERVER_TARGET) $(CLIENT_TARGET) $(SERVER_LIBEVENT_TARGET)

# Build server with io_uring dependency
$(SERVER_TARGET): $(SERVER_SRC) $(SERVER_HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $ $(LDFLAGS)

$(SERVER_LIBEVENT_TARGET): $(SERVER_LIBEVENT_SRC) $(SERVER_HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $ $(LDFLAGS)

# Build client (no io_uring dependency)
$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $<

# Run server in background, then run client
run: all
	@echo "Starting server..."
	./$(SERVER_TARGET) &
	@sleep 2
	@echo "Starting client..."
	./$(CLIENT_TARGET)

# Test with multiple clients
test-multiple: all
	@echo "Starting server..."
	./$(SERVER_TARGET) &
	@sleep 2
	@echo "Starting multiple clients..."
	gnome-terminal -- ./$(CLIENT_TARGET) &
	gnome-terminal -- ./$(CLIENT_TARGET) &
	gnome-terminal -- ./$(CLIENT_TARGET) &

# Debug server with gdb
debug-server: $(SERVER_TARGET)
	gdb ./$(SERVER_TARGET)

# Debug client with gdb
debug-client: $(CLIENT_TARGET)
	gdb ./$(CLIENT_TARGET)

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install liburing-dev build-essential

# Clean build artifacts
clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) $(SERVER_LIBEVENT_TARGET)

# Check for memory leaks with valgrind
check-server: $(SERVER_TARGET)
	valgrind --leak-check=full ./$(SERVER_TARGET)

check-client: $(CLIENT_TARGET)
	valgrind --leak-check=full ./$(CLIENT_TARGET)

# Force rebuild
rebuild: clean all

# Show help
help:
	@echo "Available targets:"
	@echo "  all           - Build both client and server"
	# @echo "  server        - Build server only"
	# @echo "  client        - Build client only"
	@echo "  run           - Build and run server, then client"
	@echo "  test-multiple - Run server with multiple client instances"
	@echo "  debug-server  - Run server in gdb"
	@echo "  debug-client  - Run client in gdb"
	@echo "  install-deps  - Install required dependencies"
	@echo "  clean         - Remove build artifacts"
	@echo "  check-server  - Run server with valgrind"
	@echo "  check-client  - Run client with valgrind"
	@echo "  rebuild       - Clean and build"
	@echo "  help          - Show this help"

# Declare phony targets
.PHONY: all run test-multiple debug-server debug-client install-deps clean check-server check-client rebuild help
