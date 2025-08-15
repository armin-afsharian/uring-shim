#include "uring_shim.h"
#include <errno.h>
#include <poll.h>

// Core initialization functions
int uring_shim_init(uring_shim_t *shim, int queue_depth, int use_eventfd) {
    
    // Setup io_uring
    struct io_uring_params params = {0};
    params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_CQSIZE;
    params.cq_entries = queue_depth * 4;    
    
    int ret = io_uring_queue_init_params(queue_depth, &shim->ring, &params);
    if (ret < 0) {
        fprintf(stderr, "io_uring_queue_init_params: %s\n", strerror(-ret));
        return -1;
    }
    if(use_eventfd) {
        shim->event_fd = eventfd(0, EFD_CLOEXEC);
        if (shim->event_fd < 0) {
            perror("eventfd");
            io_uring_queue_exit(&shim->ring);
            return -1;
        }
        if (io_uring_register_eventfd(&shim->ring, shim->event_fd) < 0) {
            perror("io_uring_register_eventfd");
            close(shim->event_fd);
            io_uring_queue_exit(&shim->ring);
            return -1;
        }
    } else {
        shim->event_fd = -1;
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
    
    // Setup the buffer ring structure
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
            buf,
            uring_shim->buf_size,
            i,
            io_uring_buf_ring_mask(uring_shim->buf_count),
            i);
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

int uring_shim_send(callback_data_t *cb_data, void* buffer, size_t len, struct io_uring_sqe *sqe) {
    io_uring_prep_send(sqe, cb_data->sockfd, buffer, len, 0);
    io_uring_sqe_set_data(sqe, cb_data);
    
    return 0;
}

int uring_shim_event_cancel(callback_data_t *cb_data, struct io_uring_sqe *sqe) {

    // Cancel the event
    io_uring_prep_cancel_fd(sqe, cb_data->sockfd, IORING_ASYNC_CANCEL_ALL);
    io_uring_sqe_set_data(sqe, cb_data);

    return 0;
}

int uring_shim_event_accept(callback_data_t *cb_data, struct io_uring_sqe *sqe) {
    io_uring_prep_multishot_accept(sqe, cb_data->sockfd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, cb_data);
    
    return 0;
}

int uring_shim_event_poll(callback_data_t *cb_data, struct io_uring_sqe *sqe) {
    io_uring_prep_poll_multishot(sqe, cb_data->sockfd, POLLIN);
    io_uring_sqe_set_data(sqe, cb_data);
    
    return 0;
}

// Event handling functions
int uring_shim_event_add(uring_shim_t *shim, int fd, int mode, process_handler handler, void *user_data, void *buf, size_t len) {
    struct io_uring_sqe *sqe;
    
    sqe = io_uring_get_sqe(&shim->ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_get_sqe: failed\n");
        return -1;
    }
    callback_data_t *cb_data;
    cb_data = malloc(sizeof(callback_data_t));

    if (!cb_data) {
        perror("malloc callback_data_t");
        return -1;
    }
    cb_data->handler = handler;
    cb_data->user_data = user_data;
    cb_data->sockfd = fd;
    cb_data->mode = mode;


    if(mode == RECV) {
        printf("Adding RECV mode for fd %d\n", fd);
        exit(1);
    }

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
    case NOP:
        io_uring_prep_nop(sqe);
        io_uring_sqe_set_data(sqe, cb_data);
        break;
    case SEND:
        if (uring_shim_send(cb_data, buf, len, sqe) < 0) {
            fprintf(stderr, "Failed to add send event\n");
            free(cb_data);
            return -1;
        }
        break;
    case CANCEL:
        if (uring_shim_event_cancel(cb_data, sqe) < 0) {
            fprintf(stderr, "Failed to cancel event\n");
            free(cb_data);
            return -1;
        }
        break;
    case ACCEPT:
        if(uring_shim_event_accept(cb_data, sqe) < 0) {
            fprintf(stderr, "Failed to add accept event\n");
            free(cb_data);
            return -1;
        }
        break;
    case POLL:
        if(uring_shim_event_poll(cb_data, sqe) < 0) {
            fprintf(stderr, "Failed to add poll event\n");
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

    io_uring_submit(&shim->ring);
    return 0;
}

size_t uring_shim_read_copy(uring_shim_t *shim, int fd, char *buf, size_t len) {

    if (fd < 0) {
        fprintf(stderr, "Invalid fd %d\n", fd);
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    buffer_info_t *buf_info = shim->fds[mask_fd(fd)];

    // No data available
    if (!buf_info) {
        errno = EAGAIN; 
        return -1;
    }

    if (buf_info->buf_id == -1) { // Indicates a special condition, e.g., EOF
        size_t ret = buf_info->len;
        free(buf_info);
        shim->fds[mask_fd(fd)] = NULL;
        return ret;
    }

    if (len < buf_info->len) {
        fprintf(stderr, "Invalid read length: %zu, len should be >= buffer length\n", len);
        return -1;
    }

    memcpy(buf, buf_info->buf_addr, buf_info->len);
    
    recycle_buffer(shim, buf_info);
    size_t ret = buf_info->len;
    free(buf_info);
    shim->fds[mask_fd(fd)] = NULL;
    
    return ret;
}

int uring_poll(uring_shim_t *shim, int timeout_usec) {
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts;
    struct __kernel_timespec *ts_ptr = NULL;

    if(timeout_usec) {
        ts.tv_sec = timeout_usec / 1000000;
        ts.tv_nsec = (timeout_usec % 1000000) * 1000;
        ts_ptr = &ts;
    }
   
    int ret = io_uring_submit_and_wait_timeout(&shim->ring, &cqe, 1, ts_ptr, NULL);
    if(ret >= 0 || ret == -ETIME) {
        return uring_shim_handler(shim);
    } else {
        fprintf(stderr, "io_uring_submit_and_wait_timeout failed: %s\n", strerror(-ret));
        return -1;
    }

}

int handle_recv_multishot_event(uring_shim_t *shim, callback_data_t *cb_data, struct io_uring_cqe *cqe) {
    char *buf_addr = NULL;
    int buf_idx = 0;
    if (cqe->flags & IORING_CQE_F_BUFFER) {
        buf_idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        buf_addr = shim->buffers + (buf_idx * shim->buf_size);

        buffer_info_t *new_info = create_buffer_info(buf_idx, buf_addr, cqe->res);
        if (!new_info) {
            fprintf(stderr, "Failed to allocate buffer info for fd %d\n", cb_data ? cb_data->sockfd : -1);
            return -1;
        } 
        shim->fds[mask_fd(cb_data->sockfd)] = new_info;
    }

    if (cb_data && cb_data->handler != NULL) {
        cb_data->handler(cb_data->user_data, cb_data->sockfd);
    } else {
        fprintf(stderr, "No handler set for fd %d\n", cb_data ? cb_data->sockfd : -1);
        return -1;
    }

    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        if (uring_shim_event_add(shim, cb_data->sockfd, 
            RECV_MULTIISHOT, cb_data->handler, cb_data->user_data, NULL, 0) < 0) {
            fprintf(stderr, "Failed to re-arm multishot receive for fd %d\n", cb_data->sockfd);
            free(cb_data);
            return -1;
        }
        free(cb_data);
    }
    
    return 0;
}

int handle_accept_event(uring_shim_t *shim, callback_data_t *cb_data, struct io_uring_cqe *cqe) {
    int new_sockfd = cqe->res;
    if (cb_data && cb_data->handler) {
        cb_data->handler(cb_data->user_data, new_sockfd);
    } else {
        fprintf(stderr, "No handler set for accept event on fd %d\n", cb_data->sockfd);
    }

    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        if (uring_shim_event_add(shim, cb_data->sockfd, 
            ACCEPT, cb_data->handler, cb_data->user_data, NULL, 0) < 0) {
            fprintf(stderr, "Failed to re-arm multishot receive for fd %d\n", cb_data->sockfd);
            free(cb_data);
            return -1;
        }
        free(cb_data);
    }

    return 0;
}

int handle_poll_event(uring_shim_t *shim, callback_data_t *cb_data, struct io_uring_cqe *cqe) {
    if (cb_data && cb_data->handler) {
        cb_data->handler(cb_data->user_data, cb_data->sockfd);
    } else {
        fprintf(stderr, "No handler set for poll event on fd %d\n", cb_data->sockfd);
    }

    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        if (uring_shim_event_add(shim, cb_data->sockfd, 
            POLL, cb_data->handler, cb_data->user_data, NULL, 0) < 0) {
            fprintf(stderr, "Failed to re-arm poll event for fd %d\n", cb_data->sockfd);
            free(cb_data);
            return -1;
        }
        free(cb_data);
    }

    return 0;
}

int handle_send_event(uring_shim_t *shim, callback_data_t *cb_data, struct io_uring_cqe *cqe) {
    if (cb_data && cb_data->handler) {
        cb_data->handler(cb_data->user_data, cb_data->sockfd);
    } else {
        fprintf(stderr, "No handler set for poll event on fd %d\n", cb_data->sockfd);
    }

    free(cb_data);

    return 0;
}

// The main event loop function
int uring_shim_handler(uring_shim_t *shim) {
    eventfd_t v;
    if (shim->event_fd > 0 && eventfd_read(shim->event_fd, &v) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        perror("eventfd_read");
        abort();
        return -1;
    }

    struct io_uring_cqe *cqe;
    unsigned head;
    
    io_uring_for_each_cqe(&shim->ring, head, cqe) {
        callback_data_t *cb_data = (callback_data_t *)io_uring_cqe_get_data(cqe);
        if (cb_data && cb_data->mode == CANCEL) {
            free(cb_data);
            cb_data = NULL;
        }
        
        else if (cqe->res > 0) { 
            switch (cb_data->mode)
            {
                case RECV_MULTIISHOT:
                    if(handle_recv_multishot_event(shim, cb_data, cqe) < 0) {
                        fprintf(stderr, "Failed to handle multishot receive for fd %d\n", cb_data->sockfd);
                        free(cb_data);
                        return -1;
                    }
                    break;

                case ACCEPT:
                    if(handle_accept_event(shim, cb_data, cqe) < 0) {
                        fprintf(stderr, "Failed to handle accept event for fd %d\n", cb_data->sockfd);
                        free(cb_data);
                        return -1;
                    }
                    break;
                case POLL:
                    if(handle_poll_event(shim, cb_data, cqe) < 0) {
                        fprintf(stderr, "Failed to handle poll event for fd %d\n", cb_data->sockfd);
                        free(cb_data);
                        return -1;
                    }
                    break;
                case SEND:
                    if (handle_send_event(shim, cb_data, cqe) < 0) {
                        fprintf(stderr, "Failed to handle send event for fd %d\n", cb_data->sockfd); 
                        return -1;
                    }
                    break;
                default:
                    fprintf(stderr, "Unhandled mode %d for fd %d\n", cb_data->mode, cb_data->sockfd);
                    free(cb_data);
                    return -1;
                    break;
            }
        }
        else {

            if (cb_data && cb_data->handler != NULL && cb_data->mode == NOP && cqe->res == 0) {
                cb_data->handler(cb_data->user_data, cb_data->sockfd);
                io_uring_cq_advance(&shim->ring, 1);
                free(cb_data);
                continue;
            }

            uring_shim_event_add(shim, cb_data->sockfd, CANCEL, NULL, NULL, NULL, 0);
            buffer_info_t *new_info = create_buffer_info(-1, NULL, cqe->res);
            if (!new_info) {
                fprintf(stderr, "Failed to allocate buffer info\n");
                free(cb_data);
                return -1;
            }
            shim->fds[mask_fd(cb_data->sockfd)] = new_info;
            if (cb_data->handler != NULL) {
                cb_data->handler(cb_data->user_data, cb_data->sockfd);
            }
            free(cb_data);
        }

        io_uring_cq_advance(&shim->ring, 1);
    }
    io_uring_submit(&shim->ring);
    return 0;
}

void uring_shim_cleanup(uring_shim_t *shim) {
    
    if (shim->br) {
        io_uring_free_buf_ring(&shim->ring, shim->br, shim->buf_count, shim->bgid);
        shim->br = NULL;
    }
    
    if (shim->event_fd >= 0) {
        io_uring_unregister_eventfd(&shim->ring);
        close(shim->event_fd);
        shim->event_fd = -1;
    }
    
    io_uring_queue_exit(&shim->ring);

    for (int i = 0; i < MAX_FDS; i++) {
        if (shim->fds[i]) {
            free(shim->fds[i]);
            shim->fds[i] = NULL;
        }
    }

    if (shim->buffers) {
        free(shim->buffers);
        shim->buffers = NULL;
    }
}