#define _POSIX_C_SOURCE 200809L

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <liburing.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "io_uring.h"

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

void req_handler(void *user_data) {
    conn_data_t *conn_data = (conn_data_t*)user_data;
    
    printf("Request completed with result: %d\n", conn_data->fd);

    char buffer[BUF_SIZE];
    int ret = uring_shim_read(&thread_contexts[conn_data->thread_id].shim, 
                             conn_data->fd, buffer, BUF_SIZE);
    if (ret <= 0) {
        fprintf(stderr, "Error reading from fd %d: %s\n", conn_data->fd, strerror(-ret));
        close(conn_data->fd);
        free(conn_data);
        return;
    }
    // printf("Thread %d: Read %d bytes from fd %d: %s\n", 
    //        conn_data->thread_id, ret, conn_data->fd, buffer);
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
    
    // Set client socket non-blocking
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl client");
        close(client_fd);
        return;
    }
    
    printf("Thread main thread: New client connected\n");

    int thread_id = (++next_thread) % MAX_THREADS;
    conn_data_t *conn_data = malloc(sizeof(conn_data_t));
    conn_data->fd = client_fd;
    conn_data->thread_id = thread_id;
    
    uring_shim_event_add(&thread_contexts[thread_id].shim, client_fd, RECV_MULTIISHOT, 
                         req_handler, (void *)conn_data);
}

void *worker_thread(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    
    // Initialize libevent for this thread
    ctx->base = event_base_new();
    if (!ctx->base) {
        fprintf(stderr, "Thread %d: Could not create event base\n", ctx->thread_id);
        return NULL;
    }
    
    // Initialize io_uring for this thread
    int event_fd = uring_shim_init(&ctx->shim, 256);
    if (event_fd < 0) {
        fprintf(stderr, "Thread %d: Could not initialize io_uring\n", ctx->thread_id);
        return NULL;
    }
    
    if (uring_shim_setup(&ctx->shim, ctx->thread_id, BUF_COUNT, BUF_SIZE) < 0) {
        fprintf(stderr, "Thread %d: Error setting up uring_shim\n", ctx->thread_id);
        return NULL;
    }
    
    // Add io_uring completion event to libevent
    struct event *uring_event = event_new(ctx->base, event_fd, 
                                        EV_READ | EV_PERSIST,
                                        handle_uring_event, ctx);
    event_add(uring_event, NULL);
    
    printf("Thread %d started\n", ctx->thread_id);
    event_base_dispatch(ctx->base);
    
    return NULL;
}

int main() {
    // Initialize libevent with thread support
    evthread_use_pthreads();
    
    server_fd = setup_server_socket(8080);
    printf("Server listening on port 8080\n");
    
    pthread_t threads[MAX_THREADS];
    
    // Create worker threads
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_contexts[i].thread_id = i;
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_contexts[i]) != 0) {
            error_exit("pthread_create");
        }
    }

    struct event_base *base;
    base = event_base_new();
    // Add accept event only to first thread
    struct event *accept_event = event_new(base, server_fd, 
                                             EV_READ | EV_PERSIST,
                                             handle_new_connection, NULL);
    event_add(accept_event, NULL);
    event_base_dispatch(base);
    
    // Wait for all threads
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    event_free(accept_event);
    event_base_free(base);
    for (int i = 0; i < MAX_THREADS; i++) {
        event_base_free(thread_contexts[i].base);
    }
    close(server_fd);
    return 0;
}