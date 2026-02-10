#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <time.h>

#include "logger.h"
#include "message.h"
#include "ipc_controller.h"
#include "router.h"

static int server_fd = -1;
static int pending_client_count = 0;
static int active_client_count = 0;

pending_client_t pending[MAX_PENDING_CLIENTS];
active_client_t  active[MAX_ACTIVE_CLIENTS];

/* Internal helper functions declarations */
static int get_pending_client_index(int fd);
static int get_active_client_index(int fd);
static int add_active_client(pending_client_t *pending_client);
static int remove_active_client(int fd);
static int add_pending_client(int fd);
static int remove_pending_client(int fd);
static int move_pending_client_to_active(int fd);
static int make_nonblocking(int fd);
static uint64_t monotonic_ms(void);
static int client_array_reset(void);
static void buffer_consume(active_client_t *c, size_t bytes);
static void process_client_rx_buffer(active_client_t *c);
int ipc_controller_handle_fd_events(struct pollfd *pfd);
int ipc_client_interview_handle_fd_events(struct pollfd *pfd);
int ipc_client_handle_fd_events(struct pollfd *pfd);

/* Internal helper functions - starts */

static int get_pending_client_index(int fd)
{
    for (int i = 0; i < MAX_PENDING_CLIENTS; i++) {
        if (pending[i].fd == fd) {
            return i;
        }
    }
    return -1;
}

static int get_active_client_index(int fd)
{
    for (int i = 0; i < MAX_ACTIVE_CLIENTS; i++) {
        if (active[i].fd == fd) {
            return i;
        }
    }
    return -1;
}

static int add_active_client(pending_client_t *pending_client)
{
    if (pending_client->fd < 0) return -1; /* No invalid fds */

    for (int i = 0; i < MAX_ACTIVE_CLIENTS; i++) {
        if (active[i].fd == -1) {
            active[i].fd = pending_client->fd;
            active[i].connected_ts_ms = pending_client->connected_ts_ms;
            memcpy(active[i].service_type, pending_client->service_type, sizeof(active[i].service_type)-1);
            memcpy(active[i].instance_name, pending_client->instance_name, sizeof(active[i].instance_name)-1);
            for (int j = 0; j < MAX_SUBSCRIPTIONS_PER_CLIENT; j++) {
                memcpy(active[i].subscriptions_list[j], pending_client->subscriptions_list[j], sizeof(active[i].subscriptions_list[j])-1);
            }
            memset(active[i].incoming_msg_buffer, 0, sizeof(active[i].incoming_msg_buffer));
            active[i].incoming_msg_buffer_offset = 0;
            memset(active[i].message_queue, 0, sizeof(active[i].message_queue));
            active[i].queue_start_idx = 0;
            active[i].queue_end_idx = 0;
            active_client_count++;
            return 0;
        }
    }

    return -1;
}

static int remove_active_client(int fd)
{
    int idx = get_active_client_index(fd);
    if (idx >= 0) {
        close(active[idx].fd);
        active[idx].fd = -1;
        active_client_count--;
        return 0;
    }
    LOG_ERROR("Failed to find active client with fd=%d to remove", fd);
    return -1;
}

static int add_pending_client(int fd)
{
    if (pending_client_count + active_client_count >= MAX_ACTIVE_CLIENTS) {
        return -1;
    }
    for (int i = 0; i < MAX_PENDING_CLIENTS; i++) {
        if (pending[i].fd == -1) {
            pending[i].fd = fd;
            pending[i].connected_ts_ms = monotonic_ms();
            memset(pending[i].service_type, 0, sizeof(pending[i].service_type));
            memset(pending[i].instance_name, 0, sizeof(pending[i].instance_name));
            for (int j = 0; j < MAX_SUBSCRIPTIONS_PER_CLIENT; j++) {
                memset(pending[i].subscriptions_list[j], 0, sizeof(pending[i].subscriptions_list[j]));
            }
            pending[i].incoming_msg_buffer_offset = 0;
            memset(pending[i].incoming_msg_buffer, 0, sizeof(pending[i].incoming_msg_buffer));
            pending_client_count++;
            return 0;
        }
    }
    return -1;
}

static int remove_pending_client(int fd)
{
    int idx = get_pending_client_index(fd);
    if (idx >= 0) {
        close(pending[idx].fd);
        pending[idx].fd = -1;
        pending_client_count--;
        return 0;
    }
    LOG_ERROR("Failed to find pending client with fd=%d to remove", fd);
    return -1;
}

static int move_pending_client_to_active(int fd)
{
    for (int i = 0; i < MAX_PENDING_CLIENTS; i++) {
        if (pending[i].fd == fd) {
            int ret = add_active_client(&pending[i]);
            if (ret == 0) {
                pending[i].fd = -1;
                pending_client_count--;
            }
            return ret;
        }
    }
    return -1;
}

static int make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int client_array_reset(void)
{
    for (int i = 0; i < MAX_PENDING_CLIENTS; i++) {
        pending[i].fd = -1;
    }
    for (int i = 0; i < MAX_ACTIVE_CLIENTS; i++) {
        active[i].fd = -1;
    }
    pending_client_count = 0;
    active_client_count = 0;
    return 0;
}

static int extract_single_frame(char *buf, int *offset, char *out_payload, size_t out_size)
{
    if (*offset < 4) return 0; /* need more data */

    uint32_t len_le;
    memcpy(&len_le, buf, 4);
    uint32_t len = le32toh(len_le);

    if (len == 0 || len > IPC_MAX_MSG_LEN) return -1;

    if (*offset < (int)(4 + len)) return 0;

    if (len >= out_size) return -1;

    memcpy(out_payload, buf + 4, len);
    out_payload[len] = '\0';

    memmove(buf, buf + 4 + len, *offset - (4 + len));
    *offset -= (4 + len);

    return 1; /* frame extracted */
}

static void buffer_consume(active_client_t *c, size_t bytes)
{
    if (bytes >= (size_t)c->incoming_msg_buffer_offset) {
        c->incoming_msg_buffer_offset = 0;
        return;
    }

    memmove(c->incoming_msg_buffer,
            c->incoming_msg_buffer + bytes,
            c->incoming_msg_buffer_offset - bytes);

    c->incoming_msg_buffer_offset -= bytes;
}

static void process_client_rx_buffer(active_client_t *c)
{
    while (1) {
        /* Need at least length prefix */
        if (c->incoming_msg_buffer_offset < 4)
            return;

        uint32_t frame_len_le;
        memcpy(&frame_len_le, c->incoming_msg_buffer, 4);

        uint32_t frame_len = le32toh(frame_len_le);

        if (frame_len == 0 || frame_len > IPC_MAX_MSG_LEN) {
            LOG_ERROR("Invalid frame length %u from fd=%d", frame_len, c->fd);
            return;
        }

        size_t total_needed = 4 + frame_len;

        if ((size_t)c->incoming_msg_buffer_offset < total_needed)
            return; /* wait for more data */

        /* We have a full frame */
        char payload[IPC_MAX_MSG_LEN + 1];
        memcpy(payload, c->incoming_msg_buffer + 4, frame_len);
        payload[frame_len] = '\0';

        LOG_DEBUG("RX frame from fd=%d (%u bytes): %s", c->fd, frame_len, payload);

        router_route_message(c->fd, payload, frame_len);

        /* Consume this frame */
        buffer_consume(c, total_needed);
    }
}

static int write_framed_buffer(int fd, const char *payload, size_t payload_len, size_t *offset)   /* IN/OUT: bytes already sent */
{
    uint32_t len_le = htole32((uint32_t)payload_len);
    size_t total = 4 + payload_len;

    if (*offset >= total)
        return 0;

    struct iovec iov[2];

    if (*offset < 4) {
        iov[0].iov_base = ((char *)&len_le) + *offset;
        iov[0].iov_len  = 4 - *offset;
        iov[1].iov_base = (void *)payload;
        iov[1].iov_len  = payload_len;
    } else {
        size_t off = *offset - 4;
        iov[0].iov_base = (void *)(payload + off);
        iov[0].iov_len  = payload_len - off;
        iov[1].iov_len  = 0;
    }

    ssize_t n = writev(fd, iov, (iov[1].iov_len > 0) ? 2 : 1);
    if (n < 0)
        return -1;

    *offset += (size_t)n;
    return (*offset >= total) ? 0 : 1; /* 1 = partial */
}

int ipc_send_frame(int fd, const char *payload, size_t len)
{
    if (!payload || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t offset = 0;

    while (1) {
        int ret = write_framed_buffer(fd, payload, len, &offset);

        if (ret == 0)
            return 0;

        if (ret < 0) {
            if (errno == EINTR)
                continue;

            if (errno == EPIPE || errno == ECONNRESET) {
                LOG_WARN("client fd=%d disconnected while sending frame", fd);
            } else {
                LOG_ERROR("write failed fd=%d: %s", fd, strerror(errno));
            }
            return -1;
        }
    }
}

static int flush_client_tx(active_client_t *c)
{
    while (c->queue_start_idx != c->queue_end_idx) {
        queued_message_t *q = &c->message_queue[c->queue_start_idx];

        int ret = write_framed_buffer(
            c->fd,
            q->data,
            q->len,
            &c->tx_offset
        );

        if (ret == 1)
            return 0; /* partial, wait for POLLOUT */

        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;

            LOG_WARN("TX write failed fd=%d: %s", c->fd, strerror(errno));
            remove_active_client(c->fd);
            return -1;
        }

        /* frame completed */
        c->tx_offset = 0;
        c->queue_start_idx =
            (c->queue_start_idx + 1) % MAX_MESSAGES_QUEUED_PER_CLIENT;
    }

    return 0;
}

int ipc_controller_handle_fd_events(struct pollfd *pfd){
    if (pfd->revents & POLLIN) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            LOG_WARN("accept failed: %s", strerror(errno));
            return 0;
        }

        make_nonblocking(client_fd);

        if (add_pending_client(client_fd) < 0) {
            LOG_WARN("too many clients in pending state, rejecting new client fd=%d", client_fd);
            hello_message_t err = {0};
            get_hello_error_message("too many pending clients", &err);
            if (ipc_send_frame(client_fd, err.data, err.length) < 0) {
                LOG_WARN("write failed while rejecting client fd=%d: %s", client_fd, strerror(errno));
            }
            close(client_fd);
            return 0;
        }

        LOG_INFO("Client connected fd=%d", client_fd);
    }
    return  0;
}

int ipc_client_interview_handle_fd_events(struct pollfd *pfd)
{
    int idx = get_pending_client_index(pfd->fd);
    if (idx < 0) return 0;

    pending_client_t *c = &pending[idx];

    ssize_t n = read(pfd->fd, c->incoming_msg_buffer + c->incoming_msg_buffer_offset,
                        sizeof(c->incoming_msg_buffer) - c->incoming_msg_buffer_offset);

    if (n <= 0) {
        LOG_ERROR("read failed for pending client fd=%d: %s", pfd->fd, n < 0 ? strerror(errno) : "EOF");
        remove_pending_client(pfd->fd);
        return 0;
    }

    c->incoming_msg_buffer_offset += n;

    char payload[IPC_MAX_MSG_LEN + 1];

    while (1) {
        int rc = extract_single_frame(c->incoming_msg_buffer, &c->incoming_msg_buffer_offset, payload, sizeof(payload));

        if (rc == 0) return 0; /* wait for more data */

        if (rc < 0) {
            LOG_ERROR("invalid handshake frame from fd=%d", pfd->fd);
            remove_pending_client(pfd->fd);
            return 0;
        }

        /* ---- process HELLO payload ---- */

        message_out_t msg_type = {0};
        get_message_type(payload, &msg_type);

        if (strcmp(msg_type.value, "hello") != 0) {
            LOG_WARN("unexpected handshake msg from fd=%d: %s", pfd->fd, payload);
            hello_message_t err = {0};
            get_hello_error_message("expected hello", &err);
            ipc_send_frame(pfd->fd, err.data, err.length);
            remove_pending_client(pfd->fd);
            return 0;
        }

        message_out_t service = {0};
        message_out_t instance = {0};
        message_out_t subs = {0};

        get_message_service(payload, &service);
        get_message_instance(payload, &instance);
        get_message_subscriptions(payload, &subs);

        memcpy(c->service_type, service.value, sizeof(c->service_type) - 1);
        memcpy(c->instance_name, instance.value, sizeof(c->instance_name) - 1);

        str_to_array(subs.value, MAX_SUBSCRIPTIONS_PER_CLIENT, STANDARD_WORD_SIZE, c->subscriptions_list);

        if (move_pending_client_to_active(pfd->fd) < 0) {
            hello_message_t err = {0};
            get_hello_error_message("too many active clients", &err);
            ipc_send_frame(pfd->fd, err.data, err.length);
            remove_pending_client(pfd->fd);
            return 0;
        }

        hello_message_t ack = {0};
        get_hello_ack_message(service.value, instance.value, subs.value, &ack);

        ipc_send_frame(pfd->fd, ack.data, ack.length);
        LOG_INFO("Client fd=%d registered", pfd->fd);
        return 0;
    }
}

int ipc_client_handle_fd_events(struct pollfd *pfd)
{
    int idx = get_active_client_index(pfd->fd);
    if (idx < 0)
        return 0;

    active_client_t *c = &active[idx];

    if (pfd->revents & POLLIN) {
        ssize_t n = read(pfd->fd, c->incoming_msg_buffer + c->incoming_msg_buffer_offset,
                            sizeof(c->incoming_msg_buffer) - c->incoming_msg_buffer_offset);

        if (n <= 0) {
            LOG_ERROR("read failed for active client fd=%d: %s", pfd->fd, n < 0 ? strerror(errno) : "EOF");
            remove_active_client(pfd->fd);
            return 0;
        }

        c->incoming_msg_buffer_offset += n;

        if (c->incoming_msg_buffer_offset > (int)sizeof(c->incoming_msg_buffer)) {
            c->incoming_msg_buffer_offset = 0; /* reset buffer to avoid overflow */
            LOG_ERROR("RX buffer overflow fd=%d", pfd->fd);
            return 0;
        }

        process_client_rx_buffer(c);
    }

    if (pfd->revents & POLLOUT) {
        if (flush_client_tx(c) < 0)
            return 0;
    }

    return 0;
}

/* Internal helper functions - ends */

/* Public method definitions - starts */

int ipc_controller_init(void)
{
    struct sockaddr_un addr;

    unlink(IPC_SOCKET_PATH);

    server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server_fd < 0) {
        LOG_ERROR("socket failed: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("bind failed: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, MAX_ACTIVE_CLIENTS) < 0) {
        LOG_ERROR("listen failed: %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    if (make_nonblocking(server_fd) < 0)
    {
        LOG_ERROR("failed to make server socket non-blocking");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    // Clear client slots
    client_array_reset();

    LOG_INFO("IPC Controller listening on %s", IPC_SOCKET_PATH);
    return 0;
}

int ipc_controller_get_fd(void)
{
    return server_fd;
}

int ipc_controller_build_pollset(struct pollfd *pfds, poll_ctx_t *ctx, int max)
{
    int n = 0;

    /* server socket */
    pfds[n].fd = server_fd;
    pfds[n].events = POLLIN;
    ctx[n].role = POLL_ROLE_SERVER;
    n++;

    /* active clients */
    for (int i = 0; i < MAX_ACTIVE_CLIENTS; i++) {
        if (active[i].fd >= 0) {
            pfds[n].fd = active[i].fd;
            
            /* Enable POLLOUT only if TX queue not empty */
            if (active[i].queue_start_idx != active[i].queue_end_idx) {
                pfds[n].events = POLLIN | POLLOUT;
            } else {
                pfds[n].events = POLLIN;
            }

            ctx[n].role = POLL_ROLE_ACTIVE;
            ctx[n].index = i;
            n++;
        }
    }

    /* pending clients */
    for (int i = 0; i < MAX_PENDING_CLIENTS; i++) {
        if (pending[i].fd >= 0) {
            pfds[n].fd = pending[i].fd;
            pfds[n].events = POLLIN;
            ctx[n].role = POLL_ROLE_PENDING;
            ctx[n].index = i;
            n++;
        }
    }

    if (n > max) {
        LOG_ERROR("Too many fds to poll: %d (max %d)", n, max);
        return max;
    }

    return n;
}

int ipc_handle_fd_events(struct pollfd *pfd, poll_ctx_t *ctx)
{
    int ret = 0;
    switch (ctx->role) {

    case POLL_ROLE_SERVER:
        ret = ipc_controller_handle_fd_events(pfd);
        break;

    case POLL_ROLE_PENDING:
        ret = ipc_client_interview_handle_fd_events(pfd);
        break;

    case POLL_ROLE_ACTIVE:
        ret = ipc_client_handle_fd_events(pfd);
        break;
    }

    if (pending_client_count > 0) ipc_client_interview_timeout();
    return ret;
}

int ipc_client_interview_timeout(void)
{
    uint64_t now = monotonic_ms();

    for (int i = 0; i < MAX_PENDING_CLIENTS; i++) {
        if (pending[i].fd < 0) continue;

        if (now - pending[i].connected_ts_ms > IPC_HANDSHAKE_TIMEOUT_MS) {
            LOG_WARN("Client fd=%d handshake timeout", pending[i].fd);
            hello_message_t timeout_msg;
            get_hello_timeout_message(&timeout_msg);
            if (write(pending[i].fd, timeout_msg.data, timeout_msg.length) < 0) {
                LOG_WARN("write failed while sending timeout client fd=%d: %s", pending[i].fd, strerror(errno));
            }
            remove_pending_client(pending[i].fd);
        }
    }
    return 0;
}

/* Public method definitions - ends */