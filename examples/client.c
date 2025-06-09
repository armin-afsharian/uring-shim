#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define BUFFER_SIZE 1024
#define MAX_EVENTS 10

int client_fd, epoll_fd;

void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int connect_to_server(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) error_exit("socket");
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
        error_exit("inet_pton");
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        error_exit("connect");
    
    return fd;
}

void setup_epoll() {
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) error_exit("epoll_create1");
    
    // Add stdin to epoll for user input[2]
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = STDIN_FILENO
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0)
        error_exit("epoll_ctl stdin");
    
    // Add client socket to epoll for server responses[2]
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0)
        error_exit("epoll_ctl client_fd");
}

void handle_user_input() {
    char buffer[BUFFER_SIZE];
    if (fgets(buffer, sizeof(buffer), stdin)) {
        
        for (int i = 0; i < 100000; i++) {
            // Send message to server using regular socket operations
            char message[BUFFER_SIZE];
            snprintf(message, sizeof(message), "test%d", i);
            printf("Sending message from keyboard: %s\n", message);
            ssize_t sent = send(client_fd, message, strlen(message), 0);
            usleep(100000); // Sleep for 1us
            if (sent < 0) {
                perror("send");
                return;
            }
            printf("Message sent successfully\n");
        }
    }
}

void handle_server_response() {
    char buffer[BUFFER_SIZE];
    
    // Receive response from server using regular socket operations
    printf("Waiting for server response...\n");
    ssize_t received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (received < 0) {
        perror("recv");
        return;
    } else if (received == 0) {
        printf("Server closed connection\n");
        exit(0);
    }
    
    buffer[received] = '\0';
    printf("Server response: %s", buffer);
}

void print_usage(const char *program) {
    fprintf(stderr, "Usage: %s <server_address> <port>\n", program);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
    }

    const char *server_addr = argv[1];
    int port = atoi(argv[2]);
    
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Error: Port must be between 1 and 65535\n");
        print_usage(argv[0]);
    }

    client_fd = connect_to_server(server_addr, port);
    setup_epoll();
    
    printf("Connected to server %s:%d. Type messages (Ctrl+C to exit):\n", 
           server_addr, port);
    
    struct epoll_event events[MAX_EVENTS];
    
    // Main event loop using epoll[2]
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) error_exit("epoll_wait");

        printf("epoll_wait returned %d\n", nfds);
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == STDIN_FILENO) {
                printf("User input detected\n");
                handle_user_input();
            } else if (events[i].data.fd == client_fd) {
                printf("Server response detected\n");
                handle_server_response();
            }
        }
    }
    
    close(client_fd);
    close(epoll_fd);
    return 0;
}
