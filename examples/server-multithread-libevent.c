#define _GNU_SOURCE

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <uring_shim.h>

#define MAX_THREADS 4
#define BACKLOG 128
#define BUF_SIZE 4096
#define BUF_COUNT 2048


typedef struct thread_context {
    struct event_base *base;
    uring_shim_t shim;
    int thread_id;
} thread_context_t;

typedef struct conn_data {
    int fd;
    int thread_id;
    char buffer[BUF_SIZE];
} conn_data_t;


static thread_context_t thread_contexts[MAX_THREADS];
static int next_thread = -1;
static int server_fd;


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

void req_handler(void *user_data, int fd __attribute_maybe_unused__) {
    conn_data_t *conn_data = (conn_data_t*)user_data;
    thread_context_t *ctx = &thread_contexts[conn_data->thread_id];
    
    ssize_t ret = uring_shim_read_copy(&ctx->shim, conn_data->fd, conn_data->buffer, BUF_SIZE);
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
    
    printf("Thread %d: Read %zd bytes from fd %d\n", conn_data->thread_id, ret, conn_data->fd);

    ssize_t sent_bytes = send(conn_data->fd, conn_data->buffer, ret, 0);
    if (sent_bytes < 0) {
        perror("send");
    } else {
        printf("Thread %d: Echoed %zd bytes to fd %d\n", conn_data->thread_id, sent_bytes, conn_data->fd);
    }
}

void handle_uring_event(evutil_socket_t fd __attribute_maybe_unused__, short events __attribute_maybe_unused__, void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    uring_shim_handler(&ctx->shim);
}

void handle_new_connection(evutil_socket_t fd, short events __attribute_maybe_unused__, void *arg __attribute_maybe_unused__) {
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_fd = accept(fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            perror("accept");
        return;
    }
    
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl client");
        close(client_fd);
        return;
    }
    
    printf("Thread main thread: New client connected\n");

    int thread_id = (++next_thread) % MAX_THREADS;
    conn_data_t *conn_data = malloc(sizeof(conn_data_t));
    if (!conn_data) {
        perror("malloc conn_data");
        close(client_fd);
        return;
    }
    conn_data->fd = client_fd;
    conn_data->thread_id = thread_id;
    
    uring_shim_event_add(&thread_contexts[thread_id].shim, client_fd, RECV_MULTIISHOT, 
                         req_handler, (void *)conn_data, NULL, 0);
    printf("Assigned client fd %d to thread %d\n", client_fd, thread_id);
}

void *worker_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    
    ctx->base = event_base_new();
    if (!ctx->base) {
        fprintf(stderr, "Thread %d: Could not create event base\n", ctx->thread_id);
        return NULL;
    }
    
    uring_shim_params_t params = {
        .queue_depth = 256,
        .use_eventfd = 1,
        .bgid = ctx->thread_id,
        .single_issuer = 0,
        .buf_count = BUF_COUNT,
        .buf_size = BUF_SIZE
    };
    int event_fd = uring_shim_init(&ctx->shim, &params);
    if (event_fd < 0) {
        fprintf(stderr, "Thread %d: Could not initialize io_uring\n", ctx->thread_id);
        return NULL;
    }
    
    struct event *uring_event = event_new(ctx->base, event_fd, 
                                        EV_READ | EV_PERSIST,
                                        handle_uring_event, ctx);
    event_add(uring_event, NULL);
    
    printf("Thread %d started\n", ctx->thread_id);
    event_base_dispatch(ctx->base);
    
    return NULL;
}

int main() {
    
    evthread_use_pthreads();
    
    server_fd = setup_server_socket(8080);
    printf("Server listening on port 8080\n");
    
    pthread_t threads[MAX_THREADS];
    

    for (int i = 0; i < MAX_THREADS; i++) {
        thread_contexts[i].thread_id = i;
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_contexts[i]) != 0) {
            error_exit("pthread_create");
        }
    }

    struct event_base *base;
    base = event_base_new();

    struct event *accept_event = event_new(base, server_fd, 
                                             EV_READ | EV_PERSIST,
                                             handle_new_connection, NULL);
    event_add(accept_event, NULL);
    event_base_dispatch(base);

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    event_free(accept_event);
    event_base_free(base);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_contexts[i].base) {
            event_base_free(thread_contexts[i].base);
        }
        uring_shim_cleanup(&thread_contexts[i].shim);
    }
    close(server_fd);
    return 0;
}