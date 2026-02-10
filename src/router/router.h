#pragma once
#include <stddef.h>

int router_init(void);

/* Route a decoded frame payload */
int router_route_message(int src_fd, const char *payload, size_t len);