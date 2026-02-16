#pragma once

#define IPC_SOCKET_PATH "/run/ipc_controller.sock"

#define IPC_MAX_MSG_LEN 4096
#define STANDARD_WORD_SIZE 64
#define MAX_PENDING_CLIENTS 16
#define MAX_ACTIVE_CLIENTS  32
#define IPC_HANDSHAKE_TIMEOUT_MS 5000
#define MAX_SUBSCRIPTIONS_PER_CLIENT 20
#define MAX_MESSAGES_QUEUED_PER_CLIENT 1000

/* MAX_POLL_FDS: max fds to poll at a time.
 * = 1 (server socket) + MAX_ACTIVE_CLIENTS (active client sockets)
 * Note: pending clients are not included in this count as they are temporary and
 * when the total client count (pending + active) exceeds MAX_ACTIVE_CLIENTS, new connections are rejected.
 */
#define MAX_POLL_FDS (1 + MAX_ACTIVE_CLIENTS)

typedef struct {
    char type[64];
    char version[64];
    char uid[64];
    char source[64];
    char target[64];
    char topic[64];
    char priority[64];
    char timestamp[64];
} message_header_t;

typedef struct {
    char data[IPC_MAX_MSG_LEN];
    size_t len;
} queued_message_t;

typedef struct {
    int fd;
    char service_type[STANDARD_WORD_SIZE];
    char instance_name[STANDARD_WORD_SIZE];
    char subscriptions_list[MAX_SUBSCRIPTIONS_PER_CLIENT][STANDARD_WORD_SIZE];
    uint64_t connected_ts_ms;
    char incoming_msg_buffer[IPC_MAX_MSG_LEN];
    int  incoming_msg_buffer_offset;
} pending_client_t;

typedef struct {
    int fd;
    uint64_t connected_ts_ms;
    char service_type[STANDARD_WORD_SIZE];
    char instance_name[STANDARD_WORD_SIZE];
    char subscriptions_list[MAX_SUBSCRIPTIONS_PER_CLIENT][STANDARD_WORD_SIZE];
    char incoming_msg_buffer[IPC_MAX_MSG_LEN * 2];
    int incoming_msg_buffer_offset;
    queued_message_t message_queue[MAX_MESSAGES_QUEUED_PER_CLIENT];
    int queue_start_idx;
    int queue_end_idx;
    size_t tx_offset;
} active_client_t;
