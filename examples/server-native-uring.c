#define _GNU_SOURCE

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
#define QUEUE_DEPTH 256

void handle_new_connection(void *user_data, int client_fd);

struct connection {
    int fd;
    char buffer[BUFFER_SIZE];
    enum { READ, WRITE1 } state;
};

typedef struct conn_data {
    int fd;
    char buffer[BUF_SIZE];
} conn_data_t;

int server_fd, epoll_fd, event_fd;
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
    uring_shim_params_t params = {
        .queue_depth = QUEUE_DEPTH,
        .use_eventfd = 0,
        .single_issuer = 1,
        .bgid = 1,
        .buf_count = BUF_COUNT,
        .buf_size = BUF_SIZE
    };
    event_fd = uring_shim_init(&shim, &params);
    if (event_fd < 0) {
        error_exit("uring_shim_init");
    }
    conn_data_t *conn_data = malloc(sizeof(conn_data_t));
    if (!conn_data) {
        perror("malloc conn_data");
        close(server_fd);
    }
    conn_data->fd = server_fd;
    uring_shim_event_add(&shim, server_fd, ACCEPT, handle_new_connection, (void *)conn_data, NULL, 0);
}

void req_handler(void *user_data, int fd __attribute_maybe_unused__) {
    conn_data_t *conn_data = (conn_data_t*)user_data;

    ssize_t ret = uring_shim_read_copy(&shim, conn_data->fd, conn_data->buffer, BUF_SIZE);
    if (ret <= 0) {
        if (ret < 0 && errno != EAGAIN) {
            fprintf(stderr, "Error reading from fd %d: %s\n", conn_data->fd, strerror(errno));
        } else if (ret == 0) {
            printf("Client on fd %d disconnected.\n", conn_data->fd);
        }
        close(conn_data->fd);
        free(conn_data);
        return;
    }
    
    printf("Read %zd bytes from fd %d\n", ret, conn_data->fd);

    ssize_t sent_bytes = send(conn_data->fd, conn_data->buffer, ret, 0);
    if (sent_bytes < 0) {
        perror("send");
    } else {
        printf("Echoed %zd bytes to fd %d\n", sent_bytes, conn_data->fd);
    }
}

void handle_new_connection(void *user_data __attribute_maybe_unused__, int client_fd) {
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            perror("fcntl client");
            close(client_fd);
        }
        
        printf("New client connected on fd %d\n", client_fd);

        conn_data_t *conn_data = malloc(sizeof(conn_data_t));
        if (!conn_data) {
            perror("malloc conn_data");
            close(client_fd);
        }
        conn_data->fd = client_fd;
        uring_shim_event_add(&shim, client_fd, RECV_MULTIISHOT, req_handler, (void *)conn_data, NULL, 0);
}


int main() {
    server_fd = setup_server_socket(8080);
    setup();
    printf("Server listening on port 8080\n");
 
    while (1) {
        int ret = uring_poll(&shim, 0);
        if (ret < 0) {
            error_exit("uring_poll");
        }
    }
    
    close(server_fd);
    close(epoll_fd);
    uring_shim_cleanup(&shim);
    return 0;
}
