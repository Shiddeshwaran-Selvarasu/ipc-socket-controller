#pragma once

#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "logger.h"

extern volatile sig_atomic_t sigpipe_seen;

typedef enum {
    POLL_ROLE_SERVER,
    POLL_ROLE_PENDING,
    POLL_ROLE_ACTIVE
} poll_role_t;

typedef struct {
    poll_role_t role;
    int index;   // index into pending[] or active[]
} poll_ctx_t;

typedef int (*fd_event_handler_t)(struct pollfd *pfd, poll_ctx_t *ctx);
typedef int (*timeout_handler_t)(void);

void loop(struct pollfd *pfds, poll_ctx_t *poll_ctx, int nfds,
    int timeout_ms, fd_event_handler_t fd_handler, timeout_handler_t timeout_handler);

int loop_once(struct pollfd *pfds, poll_ctx_t *poll_ctx, int nfds,
    int timeout_ms, fd_event_handler_t fd_handler, timeout_handler_t timeout_handler);