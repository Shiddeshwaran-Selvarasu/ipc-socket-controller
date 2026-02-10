/**
 ******************************************************************************
 * @file    eventLoop.c
 * @author  Shiddeshwaran-S
 * @brief   Event loop implementation.
 ******************************************************************************
 */

#include "event_loop.h"

extern volatile sig_atomic_t sigpipe_seen;

static void check_and_log_sigpipe(void)
{
    if (sigpipe_seen)
    {
        LOG_WARN("SIGPIPE received (client disconnected during write)");
        sigpipe_seen = 0;
    }
}

void loop(
    struct pollfd *pfds,
    poll_ctx_t *poll_ctx,
    int nfds,
    int timeout_ms,
    fd_event_handler_t fd_handler,
    timeout_handler_t timeout_handler)
{
    while (1)
    {
        int poll_ret = poll(pfds, nfds, timeout_ms);

        if (poll_ret < 0)
        {
            if (errno == EINTR)
                continue;
            LOG_ERROR("poll failed: %s", strerror(errno));
            break;
        }

        if (poll_ret == 0)
        {
            if (timeout_handler && timeout_handler() < 0)
            {
                LOG_ERROR("Error handling sequence timeout");
            }
            continue;
        }

        for (int i = 0; i < nfds; i++)
        {
            if (pfds[i].revents == 0)
                continue;

            if (fd_handler == NULL)
                continue;

            if (fd_handler(&pfds[i], &poll_ctx[i]) < 0)
            {
                LOG_ERROR("fd handler failed (index=%d)", i);
                return;
            }
        }

        check_and_log_sigpipe();
    }
}

int loop_once(
    struct pollfd *pfds,
    poll_ctx_t *poll_ctx,
    int nfds,
    int timeout_ms,
    fd_event_handler_t fd_handler,
    timeout_handler_t timeout_handler)
{
    int poll_ret = poll(pfds, nfds, timeout_ms);

    if (poll_ret < 0)
    {
        if (errno == EINTR) return 0;
        LOG_ERROR("poll failed: %s", strerror(errno));
        return -1;
    }

    if (poll_ret == 0)
    {
        if (timeout_handler && timeout_handler() < 0)
        {
            LOG_ERROR("Error handling sequence timeout");
        }
        return 0;
    }

    for (int i = 0; i < nfds; i++)
    {
        if (pfds[i].revents == 0)
            continue;

        if (fd_handler == NULL)
            continue;

        if (fd_handler(&pfds[i], &poll_ctx[i]) < 0)
        {
            LOG_ERROR("fd handler failed (index=%d)", i);
            return -1;
        }
    }

    check_and_log_sigpipe();
    return 0;
}
