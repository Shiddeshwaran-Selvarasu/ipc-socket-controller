#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <signal.h>

#include "ipc_controller.h"
#include "event_loop.h"
#include "logger.h"

#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)

#define APP_NAME "IPC Controller"
#define APP_VER_MAJOR 1
#define APP_VER_MINOR 0
#define APP_VER_PATCH 0

// Version string: IPC Controller v1.0.0
#define APP_VERSION_STRING APP_NAME " v" STRINGIFY(APP_VER_MAJOR) "." STRINGIFY(APP_VER_MINOR) "." STRINGIFY(APP_VER_PATCH)

volatile sig_atomic_t sigpipe_seen = 0;

static void sigpipe_handler(int sig)
{
    (void)sig;
    sigpipe_seen = 1;
}

static void setup_signal_handlers(void)
{
    struct sigaction sa;

    sa.sa_handler = sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGPIPE, &sa, NULL);
}

int main(void)
{
    LOG_INFO("Started %s\n", APP_VERSION_STRING);
    setup_signal_handlers();

    ipc_controller_init();

    while (1) {
        struct pollfd pfds[MAX_POLL_FDS] = {0};
        poll_ctx_t     ctx[MAX_POLL_FDS] = {0};
        int nfds = 0;

        nfds = ipc_controller_build_pollset(pfds, ctx, MAX_POLL_FDS);
        if (nfds < 0) {
            LOG_ERROR("Failed to build pollset");
            break;
        }

        if (loop_once(pfds, ctx, MAX_POLL_FDS, IPC_HANDSHAKE_TIMEOUT_MS, ipc_handle_fd_events, NULL) < 0) {
            LOG_ERROR("Error in event loop");
            break;
        }
    }

    return 0;
}