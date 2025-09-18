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
        .use_eventfd = 1,
        .single_issuer = 1,
        .bgid = 1,
        .buf_count = BUF_COUNT,
        .buf_size = BUF_SIZE
    };
    event_fd = uring_shim_init(&shim, &params);
    if (event_fd < 0) {
        error_exit("uring_shim_init");
    }
    
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) error_exit("epoll_create1");
    
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = server_fd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0)
        error_exit("epoll_ctl server");
    
    ev.events = EPOLLIN;
    ev.data.fd = event_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &ev) < 0)
        error_exit("epoll_ctl eventfd");
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
        
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            perror("fcntl client");
            close(client_fd);
            continue;
        }
        
        printf("New client connected on fd %d\n", client_fd);

        conn_data_t *conn_data = malloc(sizeof(conn_data_t));
        if (!conn_data) {
            perror("malloc conn_data");
            close(client_fd);
            continue;
        }
        conn_data->fd = client_fd;
        uring_shim_event_add(&shim, client_fd, RECV_MULTIISHOT, req_handler, (void *)conn_data, NULL, 0);
    }
}

int main() {
    server_fd = setup_server_socket(8080);
    setup();
    printf("Server listening on port 8080\n");
    struct epoll_event events[MAX_EVENTS];
 
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                error_exit("epoll_wait");
            }
        }
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                handle_new_connection();
            } else if (events[i].data.fd == event_fd) {
                uring_shim_handler(&shim);
            }
        }
    }
    
    close(server_fd);
    close(epoll_fd);
    uring_shim_cleanup(&shim);
    return 0;
}
