#define _POSIX_C_SOURCE 200809L

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <uring_shim.h>

#define MAX_EVENTS 64
#define BUFFER_SIZE 1024
#define BACKLOG 128
#define BUF_SIZE 4096
#define BUF_COUNT 256

struct connection {
    int fd;
    char buffer[BUFFER_SIZE];
    enum { READ, WRITE1 } state;
};

typedef struct conn_data {
    int fd;
} conn_data_t;


int server_fd, epoll_fd, event_fd;
char *buffers; /* buffers for the buffer ring */
struct io_uring_buf_ring *buf_ring;
uring_shim_t shim;
char* buffer;


void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}


int setup_server_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) error_exit("socket");
    
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        error_exit("setsockopt");
    
    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        error_exit("fcntl");
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        error_exit("bind");
    
    if (listen(fd, BACKLOG) < 0)
        error_exit("listen");
    
    return fd;
}

void setup() {

    event_fd = uring_shim_init(&shim, 256);
    
    // Create epoll instance
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) error_exit("epoll_create1");
    
    // Add server socket to epoll
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = server_fd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0)
        error_exit("epoll_ctl server");
    
    // Add eventfd to epoll for io_uring completion notifications[3][7]
    ev.events = EPOLLIN;
    ev.data.fd = event_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &ev) < 0)
        error_exit("epoll_ctl eventfd");
}



void req_handler(void *user_data) {
    conn_data_t *conn_data = (conn_data_t*)user_data;
    
    // printf("Request completed with result: %d\n", conn_data->fd);

    int ret = uring_shim_read(&shim, conn_data->fd, &buffer, BUF_SIZE);
    if (ret <= 0) {
        fprintf(stderr, "Error reading from fd %d: %s\n", conn_data->fd, strerror(-ret));
        close(conn_data->fd);
        free(conn_data);
        return;
    }
    buffer[ret] = '\0'; // Null-terminate the string
    printf("Read %d bytes from fd %d: %s\n", ret, conn_data->fd, buffer);
}

void handle_new_connection() {
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            perror("accept");
            continue;
        }
        
        // Set client socket non-blocking
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            perror("fcntl client");
            close(client_fd);
            continue;
        }
        
        printf("New client connected\n");


        conn_data_t *conn_data = malloc(sizeof(conn_data_t));
        conn_data->fd = client_fd;
        uring_shim_event_add(&shim, client_fd, RECV_MULTIISHOT, req_handler, (void *)conn_data);
    }
}

int main() {
    server_fd = setup_server_socket(8080);
    buffer = malloc(BUF_SIZE);
    setup();
    
    printf("Server listening on port 8080\n");
    
    struct epoll_event events[MAX_EVENTS];

    if (uring_shim_setup(&shim, 1, 16, 4096) < 0) {
        fprintf(stderr, "Error setting up uring_shim\n");
        return -1;
    }
    
    // Main event loop using epoll[3][7]
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                // Signal interrupted epoll_wait, just continue[3]
                continue;
            } else {
                // Real error occurred
                error_exit("epoll_wait");
            }
        }
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                handle_new_connection();
            } else if (events[i].data.fd == event_fd) {
                // io_uring completion notification[1][3][7]
                uring_shim_handler(&shim);
            }
        }
    }
    
    close(server_fd);
    close(epoll_fd);
    close(event_fd);
    free(buffer);
    io_uring_queue_exit(&shim.ring);
    return 0;
}
