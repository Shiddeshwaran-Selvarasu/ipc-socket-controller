# Architecture

## Overview

IPC Socket Controller is a single-process, single-threaded message broker. All I/O is non-blocking and driven by one `poll()` call per iteration. There are no worker threads, no mutexes, and no external runtime dependencies beyond libc.

```
+--------------------------------------------------------------------+
|                       ipc_controller (process)                     |
|                                                                    |
|  main()                                                            |
|   |                                                                |
|   +-- event_loop_init_signals()   (SIGPIPE -> flag, not crash)     |
|   |                                                                |
|   +-- ipc_controller_init()       (bind/listen on UNIX socket)     |
|   |                                                                |
|   \-- loop forever                                                 |
|        |                                                           |
|        +-- ipc_controller_build_pollset()  --> [pfds[], ctx[]]     |
|        |                                                           |
|        \-- loop_once(poll -> dispatch)                             |
|                |                                                   |
|                +-- POLL_ROLE_SERVER  -> accept() new connection    |
|                +-- POLL_ROLE_PENDING -> handshake (HELLO/ACK)      |
|                \-- POLL_ROLE_ACTIVE  -> RX frame -> route/TX flush |
+--------------------------------------------------------------------+
```

## Module Dependency Graph

```
ipc_controller (binary)
    +-- ipc_proto.so         <- IPC Controller Module
    |       +-- ipc_logger.so
    |       +-- ipc_message.so
    |       |       \-- ipc_logger.so
    |       \-- ipc_router.so  <--------------------------+
    |               +-- ipc_logger.so                     |
    |               \-- ipc_message.so                    |
    +-- ipc_eventloop.so                                  |
    |       \-- ipc_logger.so                             |
    \-- (ipc_proto also references ipc_router -- circular)|
                                                          |
        ipc_proto <---------------------------------------+
        (circular: resolved at load time via --allow-shlib-undefined)

ipc_storage.so  (standalone -- not linked into the binary yet)
```

The `ipc_proto` <-> `ipc_router` circular dependency exists because the router needs to walk the `active[]` client table (owned by `ipc_proto`) while the controller needs to call `router_route_message()`. Both `.so` files are built with `-Wl,--allow-shlib-undefined` and the dynamic linker resolves symbols at runtime.

## Client Lifecycle

A connecting process goes through two states before it can exchange messages.

```
   TCP-style accept()
         |
         v
   +-------------+   send HELLO frame   +--------------+
   |   PENDING   | -------------------> |    ACTIVE    |
   |  (max 16)   |                      |   (max 32)   |
   +-------------+                      +--------------+
         |                                     |
   timeout (5 s)                         disconnect / error
   bad message                                 |
   capacity full                               v
         |                              free TX queue
         v                              close fd
    close fd
```

**Pending state** (`pending_client_t`):
- Holds a 4 KB incoming buffer for the HELLO frame
- Timestamped at connect; evicted after `IPC_HANDSHAKE_TIMEOUT_MS` (5 000 ms)
- `add_pending_client` rejects new connections when `pending + active >= MAX_ACTIVE_CLIENTS` (32), keeping the total `pollfd` array bounded at 33 entries

**Active state** (`active_client_t`):
- Carries an 8 KB incoming buffer (double the max frame size, for partial reads)
- A circular queue of up to 1 000 heap-allocated outbound frames (`queued_message_t`)
- A `tx_offset` cursor for partial-write resumption
- `POLLOUT` is added to the fd's event mask only when the TX queue is non-empty

## Wire Protocol

Every message -- in both directions -- is a **length-prefixed frame**:

```
Offset  Size  Description
------  ----  ----------------------------------
0       4     Payload length (uint32, little-endian)
4       N     JSON payload (N = value from header)
```

The 4-byte header and the payload may arrive in separate `read()` calls. `extract_single_frame()` (pending) and `process_client_rx_buffer()` (active) implement the reassembly loop. Writes use `writev()` scatter-gather and track a `tx_offset` so partial sends are resumed on the next `POLLOUT` event.

## Routing

`router_route_message(src_fd, payload, len)` dispatches a received frame to zero or more active clients.

### Decision logic

```
Incoming frame
      |
      +-- has "target" field?
      |       |
      |       +-- match service_type of any active client?  -> enqueue to all
      |       \-- match instance_name of any active client? -> enqueue to first, stop
      |
      \-- has "topic" field?
              |
              \-- for each active client, check subscriptions_list[]
                      topic_match(subscription, topic)
                          +-- exact match
                          \-- prefix wildcard: "alerts.*" matches "alerts.critical"
                                              (everything after '*' is ignored)
```

The sender (identified by `src_fd`) is always excluded from routing.

### Subscription wildcards

`topic_match(sub, topic)` checks:
1. Exact string equality
2. If `sub` contains `*`, the prefix before `*` must match the start of `topic`

Example: subscription `"sensor.*"` matches `"sensor.temp"`, `"sensor.humidity"`, but not `"actuator.fan"`.

## Message Format

Messages are JSON objects. The set of recognised fields:

| Field | Used in | Description |
|---|---|---|
| `type` | HELLO | `"hello"` during handshake |
| `service` | HELLO | Service class name (e.g. `"sensor_service"`) |
| `instance` | HELLO | Unique instance name (e.g. `"sensor_001"`) |
| `subscriptions` | HELLO | JSON array of topic patterns to subscribe to |
| `target` | DATA | Route to all clients of this service, or uniquely to this instance |
| `topic` | DATA | Publish to all clients subscribed to a matching pattern |
| `payload` | DATA | Application-defined body (any JSON value) |
| `source` | DATA | Sender identifier (set by the client, not validated) |
| `uid` | DATA | Message ID (set by the client, not validated) |
| `priority` | DATA | Application-defined priority string |
| `timestamp` | DATA | Application-defined timestamp string |
| `version` | DATA | Protocol version string |

Parsing uses **JSMN** (embedded in `src/include/jsmn.h`), a zero-allocation stream tokenizer. `extract_json_value()` performs a single linear scan over the token array; it does not build a DOM.

## Event Loop

`loop_once()` performs one iteration of the poll/dispatch cycle:

```c
poll(pfds, nfds, timeout_ms)
  -> for each ready fd:
       ipc_handle_fd_events(pfd, ctx)
         -> switch(ctx->role):
             SERVER  -> accept() -> add_pending_client()
             PENDING -> read frame -> validate HELLO -> move_pending_to_active()
             ACTIVE  -> POLLIN:  read -> process_client_rx_buffer() -> router_route_message()
                        POLLOUT: flush_client_tx()
  -> check_and_log_sigpipe()
```

`main()` rebuilds the `pollfd` array on every iteration via `ipc_controller_build_pollset()`. This keeps the poll set consistent when clients are added or removed during dispatch without requiring dynamic fd-set management.

## Storage Module

`src/storage/` contains a **slotted-page allocator** (`libipc_storage.so`) that is built but not yet wired into the main binary. It stores variable-length JSON blobs in 4 KB pages using a standard slot-directory layout:

```
Page (4096 bytes)
+--------------+------------------------------------------+
|  PageHeader  |              data[]                      |
|  slot_count  |  <- free space ->   [blob N] ... [blob 1]|
|  free_ptr    |                                          |
+--------------+------------------------------------------+
              Slots grow forward; blobs packed backward.
              free_ptr points at the next available byte.
```

API: `page_init()`, `add_json_to_page()`, `get_json_from_page()`.

## Capacity and Limits

| Constant | Value | Where defined |
|---|---|---|
| `IPC_SOCKET_PATH` | `/run/ipc_controller.sock` | `ipc_protocol.h` |
| `IPC_MAX_MSG_LEN` | 4096 | `ipc_protocol.h` |
| `MAX_ACTIVE_CLIENTS` | 32 | `ipc_protocol.h` |
| `MAX_PENDING_CLIENTS` | 16 | `ipc_protocol.h` |
| `MAX_POLL_FDS` | 33 (1 + 32) | `ipc_protocol.h` |
| `MAX_SUBSCRIPTIONS_PER_CLIENT` | 20 | `ipc_protocol.h` |
| `MAX_MESSAGES_QUEUED_PER_CLIENT` | 1000 | `ipc_protocol.h` |
| `IPC_HANDSHAKE_TIMEOUT_MS` | 5000 | `ipc_protocol.h` |
| `STANDARD_WORD_SIZE` | 64 | `ipc_protocol.h` |
| `PAGE_SIZE` (storage) | 4096 | `storage.h` |

All limits are compile-time constants; changing them requires only a rebuild.

## Shared Library Layout

```
build/exports/
+-- ipc_controller              <- RPATH: $ORIGIN/lib
\-- lib/
    +-- libipc_logger.so        <- no deps
    +-- libipc_message.so       <- ipc_logger
    +-- libipc_eventloop.so     <- ipc_logger
    +-- libipc_router.so        <- ipc_logger, ipc_message  (undefined: active[])
    +-- libipc_proto.so         <- ipc_logger, ipc_message, ipc_router
    \-- libipc_storage.so       <- no deps
```

Each library's RPATH is set to `$ORIGIN` so the dynamic linker finds sibling `.so` files without requiring an install step or `LD_LIBRARY_PATH`.
