#include "uring_shim.h" // Include the header file
#include <errno.h>     // For strerror

// Core initialization functions
int uring_shim_init(uring_shim_t *shim, int queue_depth) {
    
    // Setup io_uring
    struct io_uring_params params = {0};
    params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN;
    
    int ret = io_uring_queue_init_params(queue_depth, &shim->ring, &params);
    if (ret < 0) {
        fprintf(stderr, "io_uring_queue_init_params: %s\n", strerror(-ret));
        return -1;
    }
    // Create eventfd for io_uring notifications[1]
    shim->event_fd = eventfd(0, EFD_CLOEXEC);
    if (shim->event_fd < 0) {
        perror("eventfd");
        io_uring_queue_exit(&shim->ring); // Clean up ring on error
        return -1;
    }

    // Register eventfd with io_uring[1][9]
    if (io_uring_register_eventfd(&shim->ring, shim->event_fd) < 0) {
        perror("io_uring_register_eventfd");
        close(shim->event_fd); // Clean up event_fd
        io_uring_queue_exit(&shim->ring); // Clean up ring
        return -1;
    }
    
    return shim->event_fd;
}

int uring_shim_setup(uring_shim_t *shim, int bgid, 
        unsigned int buf_count, unsigned int buf_size) {
    shim->bgid = bgid;
    shim->buf_count = buf_count;
    shim->buf_size = buf_size;
    
    // Setup buffer ring
    int ret = uring_shim_setup_buffer_ring(shim, bgid);
    if (ret < 0) {
        fprintf(stderr, "Failed to setup buffer ring\n");
        return -1;
    }
    
    return 0;
}

int uring_shim_setup_buffer_ring(uring_shim_t *uring_shim, int bgid) {

    struct io_uring_buf_ring *buf_ring;

    if (posix_memalign((void **)&uring_shim->buffers, sysconf(_SC_PAGESIZE), 
            uring_shim->buf_count * uring_shim->buf_size)) {
        perror("posix_memalign for buffers");
        return -1;
    }
    
    // Setup the buffer ring structure (handled by io_uring_setup_buf_ring)
    int ret;
    buf_ring = io_uring_setup_buf_ring(&uring_shim->ring, uring_shim->buf_count, bgid, 0, &ret);
    if (!buf_ring) {
        fprintf(stderr, "Error setting up buf ring: %s\n", strerror(-ret));
        free(uring_shim->buffers);
        uring_shim->buffers = NULL;
        return -1;
    }

    // Add buffers to the ring
    for (unsigned int i = 0; i < uring_shim->buf_count; i++) {
        char *buf = uring_shim->buffers + (i * uring_shim->buf_size);
        io_uring_buf_ring_add(buf_ring, 
            buf, // buffer address
            uring_shim->buf_size, // buffer length
            i, // buffer ID
            io_uring_buf_ring_mask(uring_shim->buf_count),
            i); // ring buffer offset
    }


    // Make buffers visible to the kernel
    io_uring_buf_ring_advance(buf_ring, uring_shim->buf_count);
    uring_shim->br = buf_ring;

    return 0;
}

int uring_shim_recv_multishot(callback_data_t *cb_data, struct io_uring_sqe *sqe, int bgid) {
    
    // Setup for multishot receive
    io_uring_prep_recv_multishot(sqe, cb_data->sockfd, NULL, 0, 0);
    io_uring_sqe_set_data(sqe, cb_data);

    sqe->buf_group = bgid;
    sqe->flags |= IOSQE_BUFFER_SELECT;
    return 0;
}

void uring_shim_write(callback_data_t *cb_data, char* buffer, size_t len, struct io_uring_sqe *sqe) {
    io_uring_prep_write(sqe, cb_data->sockfd, buffer, len, 0);
    io_uring_sqe_set_data(sqe, cb_data);
}

int uring_shim_event_cancel(callback_data_t *cb_data, struct io_uring_sqe *sqe) {

    // Cancel the event
    io_uring_prep_cancel_fd(sqe, cb_data->sockfd, IORING_ASYNC_CANCEL_ALL);
    io_uring_sqe_set_data(sqe, cb_data);

    return 0;
}

// Event handling functions
int uring_shim_event_add(uring_shim_t *shim, int fd, int mode, process_handler handler, void *user_data) {
    struct io_uring_sqe *sqe;
    
    sqe = io_uring_get_sqe(&shim->ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_get_sqe: failed\n");
        return -1;
    }

    callback_data_t *cb_data;
    
    // Allocate memory for callback data (must be freed after callback completes)
    cb_data = malloc(sizeof(callback_data_t));
    if (!cb_data) {
        perror("malloc callback_data_t");
        // Since we got an SQE, we should ideally return it or submit a NOP
        // For simplicity here, we just return error. Proper handling might involve
        // io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN) or similar if not using it.
        return -1;
    }
    cb_data->handler = handler;
    cb_data->user_data = user_data;
    cb_data->sockfd = fd;
    cb_data->mode = mode;

    switch (mode)
    {
    case RECV:
        /* not supported */
        fprintf(stderr, "RECV mode not supported in uring_shim_event_add\n");
        free(cb_data);
        return -1;
        break;
    case RECV_MULTIISHOT:
        if (uring_shim_recv_multishot(cb_data, sqe,shim->bgid) < 0) {
            fprintf(stderr, "Failed to add multishot receive\n");
            free(cb_data);
            return -1;
        }
        break;
    case WRITE:
        /* not supported directly via event_add, use uring_shim_write */
        fprintf(stderr, "WRITE mode not supported directly in uring_shim_event_add, use uring_shim_write\n");
        free(cb_data);
        return -1;
        break;
    case CANCEL:
        if (uring_shim_event_cancel(cb_data, sqe) < 0) {
            fprintf(stderr, "Failed to cancel event\n");
            free(cb_data);
            return -1;
        }
        break;
    default:
        fprintf(stderr, "Unknown mode in uring_shim_event_add\n");
        free(cb_data);
        return -1;
        break;
    }
    // Set up the SQE for the event
    io_uring_submit(&shim->ring);
    return 0;
}

int uring_shim_read(uring_shim_t *shim, int fd, char *buf, size_t len) {
    if (fd < 0 || fd >= MAX_FDS) {
        fprintf(stderr, "Invalid fd %d\n", fd);
        return -1;
    }
    if (len == 0) { // Changed from <= 0 to == 0, as len is size_t (unsigned)
        return 0;
    }

    buffer_info_t *buf_info = shim->fds[fd];
    if (buf_info == NULL) {
        fprintf(stderr, "Buffer info not found for fd %d (after printing list)\n", fd); // Debug
        return -1; // No data available
        // TODO: EAGAIN
    }

    if (buf_info->buf_id == -1) { // Indicates a special condition, e.g., EOF
        fprintf(stderr, "Buffer id is -1 for fd %d\n", fd); // Debug
        buffer_info_t *next = buf_info->next;
        size_t ret = buf_info->len; // This might be error code or 0 for EOF
        free(buf_info);
        shim->fds[fd] = next;
        return ret; // Return the stored result (e.g. 0 for EOF, or error code)
    }

    // Calculate available data in current buffer
    size_t available = buf_info->len - buf_info->read_offset;

    if (available == 0) {
        // Current buffer is fully consumed, move to next
        buffer_info_t *next = buf_info->next;
        recycle_buffer(shim, buf_info);
        free(buf_info);
        shim->fds[fd] = next;
        
        // Recursively try next buffer
        return uring_shim_read(shim, fd, buf, len);
    }

    // Determine how much to read
    size_t to_read = (len < available) ? len : available;
    
    // Copy data from current read position
    char *read_pos = buf_info->buf_addr + buf_info->read_offset;
    memcpy(buf, read_pos, to_read);
    
    // Update read offset
    buf_info->read_offset += to_read;
    
    // If buffer is fully consumed, recycle it and move to next
    if (buf_info->read_offset >= buf_info->len) {
        buffer_info_t *next = buf_info->next;
        recycle_buffer(shim, buf_info);
        free(buf_info);
        shim->fds[fd] = next;
    }
    
    return to_read;
}

// The main event loop function
int uring_shim_handler(uring_shim_t *shim) {
    eventfd_t v;
    if (eventfd_read(shim->event_fd, &v) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; // No event, not an error
        }
        perror("eventfd_read");
        return -1;
    }

    struct io_uring_cqe *cqe;
    unsigned head;
    unsigned completed = 0;
    
    io_uring_for_each_cqe(&shim->ring, head, cqe) {
        callback_data_t *cb_data = (callback_data_t *)io_uring_cqe_get_data(cqe); // Use accessor
        char *buf_addr = NULL;
        int buf_idx = 0;

        if (cb_data && cb_data->mode == CANCEL) {
            fprintf(stderr, "fd=%d event monitoring cancelled with res=%d (%s)\n", cb_data->sockfd, cqe->res, cqe->res < 0 ? strerror(-cqe->res) : "OK");
            free(cb_data);
            cb_data = NULL;
        }
        // Process the completion
        else if (cqe->res > 0) { // res can be 0 for EOF on recv
            if (cqe->flags & IORING_CQE_F_BUFFER) {
                buf_idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                buf_addr = shim->buffers + (buf_idx * shim->buf_size);

                buffer_info_t *new_info = create_buffer_info(buf_idx, buf_addr, cqe->res);
                if (!new_info) {
                    fprintf(stderr, "Failed to allocate buffer info for fd %d\n", cb_data ? cb_data->sockfd : -1);
                    // Error handling: potentially recycle buffer if not stored
                    return -1;
                } 
                append_buffer_info(&shim->fds[cb_data->sockfd], new_info);
            }
        

            if (cb_data && cb_data->handler != NULL) {
                cb_data->handler(cb_data->user_data);
            } else {
                fprintf(stderr, "No handler set for fd %d\n", cb_data ? cb_data->sockfd : -1);
                return -1;
            }

            // Check if multishot has terminated
            if (cb_data->mode == RECV_MULTIISHOT && !(cqe->flags & IORING_CQE_F_MORE)) {
                if (uring_shim_event_add(shim, cb_data->sockfd, 
                    RECV_MULTIISHOT, cb_data->handler, cb_data->user_data) < 0) {
                    fprintf(stderr, "Failed to re-arm multishot receive for fd %d\n", cb_data->sockfd);
                    free(cb_data);
                    return -1;
                }
                free(cb_data);
            }
        }
        else {
            if (cqe->res < 0) {
                fprintf(stderr, "CQE error for fd=%d: %s (res=%d)\n", cb_data ? cb_data->sockfd : -1, strerror(-cqe->res), cqe->res);
            }
            uring_shim_event_add(shim, cb_data->sockfd, CANCEL, NULL, NULL);
            buffer_info_t *new_info = create_buffer_info(-1, NULL, cqe->res);
            if (!new_info) {
                fprintf(stderr, "Failed to allocate buffer info\n");
                free(cb_data);
                return -1;
            }
            // Append new buffer info to the linked list
            append_buffer_info(&shim->fds[cb_data->sockfd], new_info);
            if (cb_data->handler != NULL) {
                cb_data->handler(cb_data->user_data);
            }
            free(cb_data);
        }

        io_uring_cq_advance(&shim->ring, 1);

        completed++;
    }
    // Mark these CQEs as processed
    // if (completed > 0) {
    //     io_uring_cq_advance(&shim->ring, completed);
    // }
    
    return 0;
}