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
#define MAX_FDS 1024 /* Must be a power of 2 */

typedef void (*process_handler)(void *user_data, int fd);

typedef struct buffer_info {
    int buf_id;
    char *buf_addr;
    size_t len;
    size_t offset;
    struct buffer_info *next; // Pointer to the next buffer in the list
} buffer_info_t;

typedef struct uring_shim {

    struct io_uring ring;
    struct io_uring_buf_ring* br; /* thread specific buffer ring */
    char *buffers;                /* buffers for the buffer ring */
    int buf_count;                /* number of buffers */
    int buf_size;                 /* size of each buffer */
    int bgid;                     /* buffer group ID */
    buffer_info_t *fds[MAX_FDS];  /* map of buffer lists, one for each fd */
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
    NOP,
    SEND,
    CANCEL,
    ACCEPT,
    POLL,
};

int uring_shim_init(uring_shim_t *shim, int queue_depth, int use_eventfd);
int uring_shim_setup(uring_shim_t *shim, int bgid, unsigned int buf_count, unsigned int buf_size);
int uring_shim_setup_buffer_ring(uring_shim_t *shim, int bgid);
void uring_shim_cleanup(uring_shim_t *shim);

int uring_shim_event_add(uring_shim_t *shim, int fd, int mode, process_handler handler, void *user_data, void *buf, size_t len);
int uring_shim_handler(uring_shim_t *shim);
int uring_poll(uring_shim_t *shim, int timeout_usec);
int uring_shim_event_cancel(callback_data_t *cb_data, struct io_uring_sqe *sqe);

int uring_shim_recv_multishot(callback_data_t *cb_data, struct io_uring_sqe *sqe, int bgid);
void uring_shim_write(callback_data_t *cb_data, char* buffer, size_t len, struct io_uring_sqe *sqe);
size_t uring_shim_read_copy(uring_shim_t *shim, int fd, char *buf, size_t len);

static inline void recycle_buffer(uring_shim_t *shim, buffer_info_t *buf_info) {
    if (buf_info->buf_addr) {
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
    new_info->offset = 0;
    new_info->next = NULL; // Initialize next pointer to NULL
    return new_info;
}

static inline int mask_fd(int fd) {
    return fd & (MAX_FDS - 1);
}

#endif