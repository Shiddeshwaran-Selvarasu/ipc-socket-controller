#pragma once
#include <poll.h>
#include <stdint.h>

#include "ipc_protocol.h"
#include "event_loop.h"

extern pending_client_t pending[MAX_PENDING_CLIENTS];
extern active_client_t  active[MAX_ACTIVE_CLIENTS];

/* lifecycle */
int ipc_controller_init(void);
int ipc_controller_get_fd(void);
int ipc_controller_build_pollset(struct pollfd *pfds, poll_ctx_t *ctx, int max);
int ipc_handle_fd_events(struct pollfd *pfd, poll_ctx_t *ctx);
int ipc_client_interview_timeout(void);

