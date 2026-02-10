#include <string.h>
#include <stdio.h>
#define JSMN_STATIC
#include "jsmn.h"
#include "message.h"
#include "logger.h"

/**
 * Internal Helper: The One-Pass Search
 * Since jsmn doesn't use a DOM tree, we find the key and its corresponding 
 * value token. This handles nested objects and arrays by respecting token hierarchy.
 */
static void extract_json_value(const char *json, const char *key, message_out_t *out) {
    if (!json || !key || !out) return;

    out->length = 0;
    out->value[0] = '\0';

    jsmn_parser p;
    jsmn_init(&p);

    /* 256 tokens is usually plenty for a single IPC message level */
    jsmntok_t tokens[256]; 
    int r = jsmn_parse(&p, json, strlen(json), tokens, 256);

    if (r < 0) {
        if (r == JSMN_ERROR_NOMEM) {
            LOG_ERROR("JSON too complex (token limit exceeded)");
        } else if (r == JSMN_ERROR_INVAL) {
            LOG_ERROR("Invalid JSON string");
        } else if (r == JSMN_ERROR_PART) {
            LOG_ERROR("Incomplete JSON string");
        } else {
            LOG_ERROR("Unknown JSON parsing error: %d", r);
        }
        return;
    }

    /* We start at 1 because 0 is the root object */
    for (int i = 1; i < r; i++) {
        /* 1. Check if the token is a string and matches our key */
        int key_len = tokens[i].end - tokens[i].start;
        if (tokens[i].type == JSMN_STRING && 
            (int)strlen(key) == key_len &&
            strncmp(json + tokens[i].start, key, key_len) == 0) {
            
            /* 2. The value is the next token */
            jsmntok_t *v = &tokens[i + 1];
            int val_len = v->end - v->start;

            /* 3. Handle data copy based on type */
            if (val_len >= (int)sizeof(out->value)) {
                val_len = sizeof(out->value) - 1;
            }

            memcpy(out->value, json + v->start, val_len);
            out->value[val_len] = '\0';
            out->length = val_len;
            return;
        }
    }
}

/* --- Parser Function Definitions --- */
/* These now leverage the library to handle complex JSON structures correctly */

void get_message_type(const char *msg, message_out_t *out_type)           { extract_json_value(msg, "type", out_type); }
void get_message_version(const char *msg, message_out_t *out_version)     { extract_json_value(msg, "version", out_version); }
void get_message_uid(const char *msg, message_out_t *out_uid)             { extract_json_value(msg, "uid", out_uid); }
void get_message_source(const char *msg, message_out_t *out_source)       { extract_json_value(msg, "source", out_source); }
void get_message_target(const char *msg, message_out_t *out_target)       { extract_json_value(msg, "target", out_target); }
void get_message_topic(const char *msg, message_out_t *out_topic)         { extract_json_value(msg, "topic", out_topic); }
void get_message_priority(const char *msg, message_out_t *out_priority)   { extract_json_value(msg, "priority", out_priority); }
void get_message_timestamp(const char *msg, message_out_t *out_timestamp) { extract_json_value(msg, "timestamp", out_timestamp); }
void get_message_payload(const char *msg, message_out_t *out_payload)     { extract_json_value(msg, "payload", out_payload); }
void get_message_service(const char *msg, message_out_t *out_service)     { extract_json_value(msg, "service", out_service); }
void get_message_instance(const char *msg, message_out_t *out_instance)   { extract_json_value(msg, "instance", out_instance); }
void get_message_subscriptions(const char *msg, message_out_t *out_subs)  { extract_json_value(msg, "subscriptions", out_subs); }

// str = "["item1","item2"]"" -> fills arr with "item1", "item2" and returns count
int str_to_array(char *str, int max_items, int item_size, char arr[max_items][item_size]) {
    jsmn_parser p;
    jsmn_init(&p);

    jsmntok_t tokens[256];
    int r = jsmn_parse(&p, str, strlen(str), tokens, 256);
    if (r < 0) {
        LOG_ERROR("Failed to parse JSON array: %d", r);
        return 0;
    }

    if (r < 1 || tokens[0].type != JSMN_ARRAY) {
        LOG_ERROR("Expected JSON array");
        return 0;
    }

    int count = 0;
    for (int i = 1; i < r && count < max_items; i++) {
        if (tokens[i].type == JSMN_STRING) {
            int len = tokens[i].end - tokens[i].start;
            if (len >= item_size) len = item_size - 1;
            memcpy(arr[count], str + tokens[i].start, len);
            arr[count][len] = '\0';
            count++;
        }
    }
    return count;
}

/* --- Generator Function Definitions --- */

void get_hello_ack_message(const char *service, const char *instance, const char *subscriptions, hello_message_t *out_data) {
    out_data->length = snprintf(out_data->data, IPC_MAX_MSG_LEN,
        "{\"type\":\"hello\",\"status\":\"ok\",\"service\":\"%s\",\"instance\":\"%s\",\"subscriptions\":%s,\"max_msg_len\":%d}",
        service, instance, subscriptions, IPC_MAX_MSG_LEN);
}

void get_hello_timeout_message(hello_message_t *out_data) {
    out_data->length = snprintf(out_data->data, IPC_MAX_MSG_LEN, 
        "{\"type\":\"hello\",\"status\":\"error\",\"reason\":\"timeout\"}");
}

void get_hello_error_message(const char *reason, hello_message_t *out_data) {
    out_data->length = snprintf(out_data->data, IPC_MAX_MSG_LEN, 
        "{\"type\":\"hello\",\"status\":\"error\",\"reason\":\"%s\"}", reason);
}