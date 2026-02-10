#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "ipc_protocol.h"
#include "ipc_controller.h"
#include "message.h"
#include "logger.h"
#include "router.h"

/* from ipc_controller.c */
extern active_client_t active[MAX_ACTIVE_CLIENTS];

/* -------- topic matcher -------- */
static int topic_match(const char *sub, const char *topic)
{
    /* exact match */
    if (strcmp(sub, topic) == 0)
        return 1;

    /* wildcard match */
    const char *wc = strchr(sub, '*');
    if (!wc) return 0;

    size_t prefix_len = wc - sub;
    return strncmp(sub, topic, prefix_len) == 0;
}

/* -------- enqueue -------- */
static int enqueue_message(active_client_t *c, const char *data, size_t len)
{
    int next = (c->queue_end_idx + 1) % MAX_MESSAGES_QUEUED_PER_CLIENT;

    if (next == c->queue_start_idx) {
        LOG_WARN("TX queue full fd=%d, dropping message", c->fd);
        return -1;
    }

    queued_message_t *q = &c->message_queue[c->queue_end_idx];
    memcpy(q->data, data, len);
    q->len = len;

    c->queue_end_idx = next;
    return 0;
}

/* -------- routing core -------- */
int router_route_message(int src_fd, const char *payload, size_t len)
{
    int use_topic = 0;
    int use_target = 0;

    message_out_t target = {0};
    get_message_target(payload, &target);

    message_out_t topic = {0};
    get_message_topic(payload, &topic);

    if (target.length != 0) {
        use_target = 1;
        LOG_DEBUG("Routing message with target='%s' from fd=%d", target.value, src_fd);
    } else if (topic.length != 0) {
        use_topic = 1;
        LOG_DEBUG("Routing message with topic='%s' from fd=%d", topic.value, src_fd);
    } else {
        LOG_WARN("Dropping message without topic or target (fd=%d)", src_fd);
        return -1;
    }

    int routed = 0;

    for (int i = 0; i < MAX_ACTIVE_CLIENTS; i++) {
        active_client_t *c = &active[i];
        if (c->fd < 0 || c->fd == src_fd) continue;

        if (use_target) {
            if (strcmp(target.value, c->service_type) == 0) {
                if (enqueue_message(c, payload, len) < 0) {
                    LOG_WARN("Failed to enqueue message for fd=%d", c->fd);
                } else {
                    LOG_DEBUG("Enqueued message for fd=%d matching target='%s'", c->fd, target.value);
                    routed++;
                } 
            } else if (strcmp(target.value, c->instance_name) == 0) {
                if (enqueue_message(c, payload, len) < 0) {
                    LOG_WARN("Failed to enqueue message for fd=%d", c->fd);
                } else {
                    LOG_DEBUG("Enqueued message for fd=%d matching target='%s'", c->fd, target.value);
                    routed = 1;
                    break; /* instance name is unique, can stop routing after first match */
                }
            }
        } else if (use_topic) {
            for (int j = 0; j < MAX_SUBSCRIPTIONS_PER_CLIENT; j++) {
                if (c->subscriptions_list[j][0] == '\0') continue;

                if (topic_match(c->subscriptions_list[j], topic.value)) {
                    if (enqueue_message(c, payload, len) < 0) {
                        LOG_WARN("Failed to enqueue message for fd=%d", c->fd);
                    } else {
                        LOG_DEBUG("Enqueued message for fd=%d matching topic='%s' with subscription='%s'", c->fd, topic.value, c->subscriptions_list[j]);
                        routed++;
                    }
                    break; /* stop checking subscriptions after first match */
                }
            }
        }
    }

    LOG_DEBUG("Routed message to %d clients", routed);
    return routed;
}

int router_init(void)
{
    return 0;
}
