#pragma once

#include <stdint.h>

#include "ipc_protocol.h"

typedef struct
{
    char data[IPC_MAX_MSG_LEN];
    int length;
} hello_message_t;

typedef struct
{
    char value[256];
    int length;
} message_out_t;

/* Message generator functions */
void get_hello_ack_message(const char *service, const char *instance, const char *subscriptions, hello_message_t *out_data);
void get_hello_timeout_message(hello_message_t *out_data);
void get_hello_error_message(const char *reason, hello_message_t *out_data);

/* Message Parser functions */
void get_message_type(const char *msg, message_out_t *out_type);
void get_message_version(const char *msg, message_out_t *out_version);
void get_message_uid(const char *msg, message_out_t *out_uid);
void get_message_source(const char *msg, message_out_t *out_source);
void get_message_target(const char *msg, message_out_t *out_target);
void get_message_topic(const char *msg, message_out_t *out_topic);
void get_message_priority(const char *msg, message_out_t *out_priority);
void get_message_timestamp(const char *msg, message_out_t *out_timestamp);
void get_message_payload(const char *msg, message_out_t *out_payload);

void get_message_service(const char *msg, message_out_t *out_service);
void get_message_instance(const char *msg, message_out_t *out_instance);
void get_message_subscriptions(const char *msg, message_out_t *out_subscriptions);

/* Helper functions */
int str_to_array(char *str, int max_items, int item_size, char arr[max_items][item_size]);

