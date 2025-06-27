#ifndef SHIM_URING
#define SHIM_URING


#include <liburing.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>


#define DEFAULT_QUEUE_DEPTH 256
#define DEFAULT_BUF_SIZE 4096
#define DEFAULT_BUFFERS_COUNT 128
#define MAX_FDS 65536

typedef void (*process_handler)(void *user_data);

typedef struct buffer_info {
    int buf_id;
    char *buf_addr;
    size_t len;
    size_t read_offset; // Number of bytes already read from this segment
    struct buffer_info *next;
} buffer_info_t;

typedef struct uring_shim {

    struct io_uring ring;      /* thread specific ring */
    struct io_uring_buf_ring* br; /* thread specific buffer ring */
    char *buffers; /* buffers for the buffer ring */
    int buf_count; /* number of buffers */
    int buf_size; /* size of each buffer */
    int bgid;                  /* buffer group ID */
    buffer_info_t *fds[MAX_FDS]; /* map of buffers */
    int event_fd;

} uring_shim_t;


typedef struct callback_data {
    process_handler handler;
    void *user_data;
    int sockfd;
    int mode;
} callback_data_t;

enum io_mode {
    RECV,
    RECV_MULTIISHOT,
    WRITE,
    CANCEL,
};

// Core initialization functions
extern int uring_shim_init(uring_shim_t *shim, int queue_depth);
extern int uring_shim_setup(uring_shim_t *shim, int bgid, unsigned int buf_count, unsigned int buf_size);
extern int uring_shim_setup_buffer_ring(uring_shim_t *shim, int bgid);

// Event handling functions
extern int uring_shim_event_add(uring_shim_t *shim, int fd, int mode, process_handler handler, void *user_data);
extern int uring_shim_handler(uring_shim_t *shim);
extern int uring_shim_event_cancel(callback_data_t *cb_data, struct io_uring_sqe *sqe);

// IO operations
extern int uring_shim_recv_multishot(callback_data_t *cb_data, struct io_uring_sqe *sqe, int bgid);
extern void uring_shim_write(callback_data_t *cb_data, char* buffer, size_t len, struct io_uring_sqe *sqe);
extern int uring_shim_read(uring_shim_t *shim, int fd, void **buf, size_t len);
extern int uring_shim_read_copy(uring_shim_t *shim, int fd, void *buf, size_t len);

// Buffer management functions (static inline, remain in header)
static inline void recycle_buffer(uring_shim_t *shim, buffer_info_t *buf_info) {
    if (buf_info->buf_addr) {
        // printf("Recycling buffer with ID %d at address %p\n", buf_info->buf_id, buf_info->buf_addr);
        io_uring_buf_ring_add(shim->br,
            buf_info->buf_addr,
            shim->buf_size,
            buf_info->buf_id,
            io_uring_buf_ring_mask(shim->buf_count),
            0);
        io_uring_buf_ring_advance(shim->br, 1);
    }
}

static inline buffer_info_t* create_buffer_info(int buf_idx, char *buf_addr, int len) {
    buffer_info_t *new_info = malloc(sizeof(buffer_info_t));
    if (!new_info) {
        return NULL;
    }
    new_info->buf_id = buf_idx;
    new_info->buf_addr = buf_addr;
    new_info->len = len;
    new_info->read_offset = 0; // Initialize read_offset to 0
    new_info->next = NULL;
    return new_info;
}

static inline void append_buffer_info(buffer_info_t **head, buffer_info_t *new_info) {
    if (!*head) {
        *head = new_info;
        return;
    }
    buffer_info_t *curr = *head;
    while (curr->next) {
        curr = curr->next;
    }
    curr->next = new_info;
}

static inline void print_buffer_info_list(int fd, buffer_info_t *head) {
    printf("---- Buffer List for fd %d ----\n", fd);
    if (!head) {
        printf("  [Empty]\n");
        printf("---- End Buffer List for fd %d ----\n", fd);
        return;
    }
    buffer_info_t *curr = head;
    int i = 0;
    while (curr != NULL) {
        printf("  Node %d: buf_id=%d, buf_addr=%p, len=%zu, read_offset=%zu, next=%p\n",
               i, curr->buf_id, curr->buf_addr, curr->len, curr->read_offset, curr->next);
        curr = curr->next;
        i++;
    }
    printf("---- End Buffer List for fd %d ----\n", fd);
}

#endif