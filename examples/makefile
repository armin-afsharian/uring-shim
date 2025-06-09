# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -pthread -I io_uring.h
LDFLAGS = -luring -levent -levent_pthreads

CUSTOM_INCLUDE_DIR = ./include

# Include and library flags for custom library[1]
INCLUDES = -I$(CUSTOM_INCLUDE_DIR)

# Source files
SERVER_SRC = server.c
SERVER_LIBEVENT_SRC = server_multithread_libevent.c
CLIENT_SRC = client.c

# Target executables
SERVER_TARGET = server
SERVER_LIBEVENT_TARGET = server_libevent
CLIENT_TARGET = client

# Default target - build both client and server[3][4]
all: $(SERVER_TARGET) $(CLIENT_TARGET) $(SERVER_LIBEVENT_TARGET)

# Build server with io_uring dependency[3][4]
$(SERVER_TARGET): $(SERVER_SRC) $(SERVER_HEADERS) $(CUSTOM_INCLUDE_DIR)/io_uring.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SERVER_TARGET) $(SERVER_SRC) $(LDFLAGS)

$(SERVER_LIBEVENT_TARGET): $(SERVER_LIBEVENT_SRC) $(SERVER_HEADERS) $(CUSTOM_INCLUDE_DIR)/io_uring.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $(SERVER_LIBEVENT_TARGET) $(SERVER_LIBEVENT_SRC) $(LDFLAGS)

# Build client (no io_uring dependency)[3][4]
$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) $(CLIENT_SRC)

# Run server in background, then run client[3]
run: all
	@echo "Starting server..."
	./$(SERVER_TARGET) &
	@sleep 2
	@echo "Starting client..."
	./$(CLIENT_TARGET)

# Test with multiple clients[1]
test-multiple: all
	@echo "Starting server..."
	./$(SERVER_TARGET) &
	@sleep 2
	@echo "Starting multiple clients..."
	gnome-terminal -- ./$(CLIENT_TARGET) &
	gnome-terminal -- ./$(CLIENT_TARGET) &
	gnome-terminal -- ./$(CLIENT_TARGET) &

# Debug server with gdb[3]
debug-server: $(SERVER_TARGET)
	gdb ./$(SERVER_TARGET)

# Debug client with gdb[3]
debug-client: $(CLIENT_TARGET)
	gdb ./$(CLIENT_TARGET)

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install liburing-dev build-essential

# Clean build artifacts[3][4]
clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)

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
	@echo "  server        - Build server only"
	@echo "  client        - Build client only"
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

# Declare phony targets[4]
.PHONY: all run test-multiple debug-server debug-client install-deps clean check-server check-client rebuild help
