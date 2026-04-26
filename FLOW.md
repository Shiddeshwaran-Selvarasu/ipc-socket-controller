# FLOW — Message Lifecycle in the IPC Socket Controller

This document traces what *actually happens* — at the byte, function, and state-machine level — when a message travels through the controller. Where `Architecture.md` answers *"what are the parts?"*, this answers *"where does each byte go and what code touches it?"*.

The controller is **one process, one thread, one `poll()` loop**. There are no queues that span threads, no locks, no async callbacks. Everything is sequential within a single `loop_once()` iteration. Keep that mental model — it makes every flow below predictable.

---

## Cast of Components

| Component | Source | Role in a message's life |
|---|---|---|
| `main()` | [src/main.c](src/main.c) | Owns the forever-loop. Rebuilds pollset every tick. |
| `loop_once()` | [src/core/event_loop.c:87](src/core/event_loop.c#L87) | One `poll()` call → dispatch ready fds → SIGPIPE check. |
| `ipc_controller_build_pollset()` | [src/ipc/ipc_controller.c:560](src/ipc/ipc_controller.c#L560) | Rebuilds `pfds[]` and `ctx[]` from `active[]` + `pending[]`. |
| `ipc_handle_fd_events()` | [src/ipc/ipc_controller.c:607](src/ipc/ipc_controller.c#L607) | Fans out to handler by `poll_role_t`. Also reaps handshake timeouts. |
| `ipc_controller_handle_fd_events()` | [src/ipc/ipc_controller.c:375](src/ipc/ipc_controller.c#L375) | `accept()` → `add_pending_client()`. |
| `ipc_client_interview_handle_fd_events()` | [src/ipc/ipc_controller.c:401](src/ipc/ipc_controller.c#L401) | Reads HELLO frame, validates, promotes. |
| `ipc_client_handle_fd_events()` | [src/ipc/ipc_controller.c:476](src/ipc/ipc_controller.c#L476) | Active client RX (route) and TX (flush). |
| `process_client_rx_buffer()` | [src/ipc/ipc_controller.c:245](src/ipc/ipc_controller.c#L245) | Frame-reassembly loop on the 8 KB RX buffer. |
| `router_route_message()` | [src/router/router.c:56](src/router/router.c#L56) | Decides who gets the frame; calls `enqueue_message()` on each match. |
| `enqueue_message()` | [src/router/router.c:31](src/router/router.c#L31) | `malloc`-copies the frame into a recipient's circular TX queue. |
| `flush_client_tx()` | [src/ipc/ipc_controller.c:340](src/ipc/ipc_controller.c#L340) | Drains the TX queue with `writev()`, partial-write resumable. |
| `extract_json_value()` | [src/message/message.c:13](src/message/message.c#L13) | One-pass JSMN scan that pulls a single key's value out of the JSON. |

---

## Flow A — The Cold Start

```
main()
  │
  ├─ event_loop_init_signals()   ── installs SIGPIPE handler that just sets a flag
  │
  ├─ ipc_controller_init()       ── unlink old socket → socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK)
  │                                  → bind("/run/ipc_controller.sock") → listen(backlog=32)
  │                                  → client_array_reset()  // pending[]=NULL, active[]=NULL
  │
  └─ while (1):
        ├─ ipc_controller_build_pollset(pfds, ctx, 33)   // server fd is always slot 0
        └─ loop_once(pfds, ctx, nfds, 5000ms, ipc_handle_fd_events, NULL)
```

**Why `SOCK_NONBLOCK` from the very start?** The server's `accept()` is non-blocking, so a spurious `POLLIN` (e.g. client connected then immediately disconnected) returns `EAGAIN` instead of stalling the entire event loop.

**Why the 5000 ms `poll()` timeout?** It bounds how long a stalled handshake can keep `pending_client_count > 0`. Even if no fd is readable, the loop wakes up at least once per 5 s and `ipc_client_interview_timeout()` runs at the bottom of every `ipc_handle_fd_events()` call.

---

## Flow B — Client Connects (Pending State)

```
client                           controller (poll loop)
  │
  ├─ socket(AF_UNIX, SOCK_STREAM)
  ├─ connect("/run/ipc_controller.sock")  ──►  poll() returns POLLIN on server_fd
  │                                              │
  │                                              └─ ipc_controller_handle_fd_events:
  │                                                   accept() → client_fd
  │                                                   make_nonblocking(client_fd)
  │                                                   add_pending_client(client_fd):
  │                                                     ┌──────────────────────────────┐
  │                                                     │ pending_client_count + active │
  │                                                     │ >= MAX_ACTIVE_CLIENTS (32)?   │
  │                                                     │   YES → reject (see Flow B') │
  │                                                     │   NO  → malloc + slot       │
  │                                                     └──────────────────────────────┘
  │                                                   pending[i] = { fd, ts=now_ms,
  │                                                                  empty buffers }
  │
  ├─ pollfd populated next tick:
  │     pfds[N] = { fd=client_fd, events=POLLIN }, ctx[N].role = POLL_ROLE_PENDING
  │
  └─ (5 s clock starts ticking against this fd)
```

**Pending state is small on purpose.** A `pending_client_t` is just enough to buffer one HELLO frame (4 KB) and a connect-timestamp. No TX queue, no subscriptions yet. This keeps memory bounded for the worst case where 16 clients all connect and never speak.

### Flow B' — Capacity rejection

If `add_pending_client()` returns `-1` (slots full), the controller still has the fd. It immediately constructs a hello-error frame via `get_hello_error_message("too many pending clients", ...)`, blasts it down the socket with `ipc_send_frame()` (a *blocking* loop variant — see notes below), then `close()`s the fd. The client gets one frame and an EOF.

> `ipc_send_frame()` ([src/ipc/ipc_controller.c:311](src/ipc/ipc_controller.c#L311)) is the **only** path in the codebase that does a tight `write()` retry loop without going through the TX queue. It exists for *administrative* frames sent during rejection/timeout paths where there's no `active_client_t` to enqueue into. It can briefly block if the kernel buffer fills up, but those frames are tiny (~80 bytes), so this is acceptable in practice.

---

## Flow C — The Handshake (HELLO → ACK)

This is where a client earns the right to send/receive data messages.

```
client                                    controller
  │
  ├─ build HELLO JSON:
  │   {"type":"hello","service":"sensor_service",
  │    "instance":"sensor_001","subscriptions":["alerts.*","config.update"]}
  │
  ├─ prepend 4-byte LE length (e.g. 0x60 0x00 0x00 0x00 for 96 bytes)
  ├─ write(fd, frame, 4+len)
  │                                       ──►  poll() returns POLLIN on pending fd
  │                                              │
  │                                              └─ ipc_client_interview_handle_fd_events:
  │                                                   read() into pending->incoming_msg_buffer
  │                                                   incoming_msg_buffer_offset += n
  │                                                   while extract_single_frame() == 1:
  │                                                       ┌─ frame_len = le32toh(buf[0..3])
  │                                                       ├─ frame_len validated 0 < len <= 4096
  │                                                       └─ payload = buf[4..4+len], NUL-terminated
  │
  │                                                   get_message_type(payload, &msg_type)
  │                                                       │
  │                                                       └─ extract_json_value runs jsmn_parse,
  │                                                          scans tokens for "type" key,
  │                                                          copies the next token's text
  │
  │                                                   IF type != "hello":
  │                                                       send hello-error("expected hello")
  │                                                       remove_pending_client → close fd
  │                                                       (DONE)
  │
  │                                                   get_message_service / instance / subscriptions
  │                                                       (subs.value is the raw JSON array string)
  │
  │                                                   memcpy into pending->service_type, instance_name
  │                                                   str_to_array(subs.value, ...) parses array
  │                                                       into pending->subscriptions_list[20][64]
  │
  │                                                   move_pending_client_to_active(fd):
  │                                                       ┌─ find empty slot in active[]
  │                                                       ├─ malloc active_client_t
  │                                                       ├─ copy fd, ts, service_type,
  │                                                       │   instance_name, subscriptions_list
  │                                                       ├─ zero TX queue (queue_start=end=0)
  │                                                       ├─ tx_offset = 0
  │                                                       └─ free pending slot, decrement count
  │
  │                                                   build ACK:
  │                                                     {"type":"hello","status":"ok",
  │                                                      "service":...,"instance":...,
  │                                                      "subscriptions":[...],"max_msg_len":4096}
  │
  │  ◄────────────────────────────────────────────── ipc_send_frame(fd, ack.data, ack.length)
  │
  ├─ read 4-byte length, then payload
  └─ parse ACK, treat status:"ok" as ready
```

**Why do `service_type` and `instance_name` live in *both* the `pending_client_t` and the `active_client_t`?** Because the structs were originally separate types with different responsibilities (interview vs. exchange), and `move_pending_client_to_active()` is just `memcpy + free`. The duplication is intentional symmetry, not a bug.

**Why is the subscriptions list parsed *twice*?** Once by JSMN inside `extract_json_value("subscriptions")` (which gives back the raw `[...]` substring), and again by `str_to_array()` (which JSMN-parses that substring into individual array elements). It's two passes over a small string — easier to read than threading the token array through.

---

## Flow D — Handshake Timeout

```
        every loop tick, after fd dispatch:
                  │
                  ├─ if pending_client_count > 0:
                  │     ipc_client_interview_timeout():
                  │        for each pending[i]:
                  │           if (now_ms - pending[i]->connected_ts_ms > 5000):
                  │              build hello-timeout frame
                  │              ipc_send_frame(fd, ...)
                  │              remove_pending_client(fd) → close
```

The check runs **after every dispatched event** (regardless of which client triggered the wakeup), and also when `poll()` itself returns `0` (idle for the full 5-second timeout). So worst-case latency for a timeout eviction is ~5 s; best-case is "right now" if any fd is busy.

---

## Flow E — Data Message Lifecycle (Direct Target Routing)

This is the headline flow — what most messages do.

### Setup

Suppose three active clients are connected:

| fd | service_type | instance_name | subscriptions |
|---|---|---|---|
| 4 | `dashboard` | `dashboard_main` | `["sensor.*"]` |
| 5 | `sensor_service` | `sensor_001` | `["config.update"]` |
| 6 | `sensor_service` | `sensor_002` | `["config.update"]` |

Client `fd=4` (the dashboard) sends:

```json
{"target":"sensor_service","payload":{"cmd":"read_temp"}}
```

framed as `[44 00 00 00][{"target":"sensor_service",...}]`.

### Step-by-step

```
1) RX on fd=4
   poll() returns POLLIN on fd=4
   ipc_client_handle_fd_events(pfd):
     read() into active[i_4]->incoming_msg_buffer
     incoming_msg_buffer_offset += n

2) Frame reassembly
   process_client_rx_buffer(c):
     loop:
       offset < 4? → return (need more) ──┐
       parse frame_len from header        │  No: we have full frame
       offset < 4 + frame_len? → return ──┘
       copy payload into stack buf[4097]
       NUL-terminate
       LOG_DEBUG("RX frame from fd=4 ...")
       router_route_message(4, payload, frame_len)   ←── HANDS OVER
       buffer_consume(c, 4 + frame_len)              ←── shift remaining bytes left
     repeat (in case multiple frames coalesced in one read)

3) Routing decision
   router_route_message(src_fd=4, payload, len):
     get_message_target(payload, &target)  → target.value = "sensor_service"
     get_message_topic(payload, &topic)    → topic.length = 0
     use_target = 1
     for i in 0..32:
       c = active[i]; skip NULL; skip src_fd==4
       if strcmp(target.value, c->service_type) == 0:    ← MATCH for fd=5, fd=6
         enqueue_message(c, payload, len)
       else if strcmp(target.value, c->instance_name) == 0:
         enqueue_message(c, payload, len); break        ← unicast: stop on first hit
     LOG_DEBUG("Routed message to 2 clients")

4) Enqueue (per recipient)
   enqueue_message(c=fd_5, data, len):
     next = (queue_end_idx + 1) % 1000
     if next == queue_start_idx → queue full, drop, return -1
     buf = malloc(len)
     memcpy(buf, data, len)
     c->message_queue[queue_end_idx] = { data=buf, len=len }
     c->queue_end_idx = next
     (same for fd_6)

5) POLLOUT enabled (next loop iteration)
   ipc_controller_build_pollset rebuilds:
     for active[fd=5]: queue_start != queue_end → events = POLLIN | POLLOUT
     for active[fd=6]: same

6) TX flush (when kernel has buffer space)
   poll() returns POLLOUT on fd=5
   ipc_client_handle_fd_events(pfd):
     flush_client_tx(c):
       while queue not empty:
         q = &message_queue[queue_start_idx]
         write_framed_buffer(fd, q->data, q->len, &c->tx_offset)
           uses writev() with iovec[2]:
             - iovec[0]: 4-byte length prefix (or remainder if partial)
             - iovec[1]: payload (or remainder)
           tx_offset += bytes_written
           returns:
             0  → fully sent
             1  → partial, EAGAIN-style (return now, wait for next POLLOUT)
            -1  → error (close client)
         on full send: free(q->data); q->data=NULL; tx_offset=0; advance queue_start_idx

7) Client receives
   client read()s 4-byte length, then payload
   processes the JSON
```

### What about partial reads / partial writes?

- **Partial RX**: the 8 KB `incoming_msg_buffer` (twice the max frame size) holds bytes between reads. `process_client_rx_buffer()` keeps invoking until `offset < 4` or `offset < 4 + frame_len`, then returns — no busy-wait, just yields to the next `poll()`.
- **Partial TX**: `tx_offset` tracks how many bytes of the *current* queue head have been sent. If `writev()` returns short, the next `POLLOUT` resumes from that offset using the iovec-shifting logic in `write_framed_buffer()`.

---

## Flow F — Data Message Lifecycle (Topic Pub/Sub)

Same plumbing as Flow E up through the read. The branch happens at `router_route_message()`:

```
get_message_target → length == 0
get_message_topic  → topic.value = "sensor.temperature"
use_topic = 1

for each active client (excluding src_fd):
    for j in 0..MAX_SUBSCRIPTIONS_PER_CLIENT (20):
        if subscriptions_list[j][0] == '\0': skip
        if topic_match(subscriptions_list[j], topic.value):
            enqueue_message(c, payload, len)
            break    ← stop at first matching subscription per client
```

### `topic_match()` semantics

```c
topic_match("sensor.*",       "sensor.temp")    → 1   // wildcard prefix
topic_match("sensor.*",       "sensor.humidity")→ 1
topic_match("sensor.*",       "actuator.fan")   → 0
topic_match("config.update",  "config.update")  → 1   // exact
topic_match("config.update",  "config.updateX") → 0   // no wildcard, must equal
topic_match("a.*.b",          "a.x.b")          → 1   // ⚠ everything after '*' is IGNORED
```

> **Subtle behavior worth remembering:** the wildcard isn't a glob — only the prefix before `*` matters. `"sensor.*.alert"` matches `"sensor.foo"` because the matcher only checks `strncmp("sensor.", topic, 7)`. This is documented quirk, not a bug.

---

## Flow G — Capacity Pressure (TX Queue Full)

If a slow consumer can't drain its queue and a fast publisher keeps producing, eventually the consumer's `message_queue[1000]` is saturated.

```
enqueue_message:
  next = (queue_end_idx + 1) % 1000
  if next == queue_start_idx:       ← buffer full
      LOG_WARN("TX queue full fd=N, dropping message")
      return -1
  ...
```

**Drop policy: tail-drop.** New messages targeted at the saturated consumer are dropped — older messages already in the queue are preserved. Other consumers of the same publish are unaffected (they have their own queues). The publisher is **not** notified — it's a fire-and-forget broker by design.

This is also the reason `MAX_MESSAGES_QUEUED_PER_CLIENT = 1000`: each `queued_message_t` is just `{char *data; size_t len}` (16 bytes on 64-bit), so the queue array itself is 16 KB; the heap blobs it points at are bounded by 4 KB each but typically much smaller. A "full" queue is bounded above at ~4 MB per client.

---

## Flow H — Disconnect / Error Cleanup

Active client closes the connection or `read()` returns 0:

```
ipc_client_handle_fd_events:
  read() returns 0 (EOF) or -1 (error other than EAGAIN)
    LOG_ERROR("read failed for active client fd=N")
    remove_active_client(fd):
      ┌─ for each q in queue: free(q->data)
      ├─ close(fd)
      ├─ free(active_client_t)
      └─ active[idx] = NULL; active_client_count--
```

Next `build_pollset()` will simply omit this slot. No stale fds in `pfds[]`.

### SIGPIPE during write

If the client closes mid-write, the kernel raises `SIGPIPE`. The custom handler just sets `sigpipe_seen = 1`. After every `loop_once()` dispatch, `check_and_log_sigpipe()` logs and resets the flag. The actual `write()` returns `-1` with `errno == EPIPE`, which `flush_client_tx()` converts to `remove_active_client()`. So the cleanup path is always the same — SIGPIPE is just a courtesy log, not a control-flow signal.

---

## Flow I — Malformed Input Defenses

| Scenario | Detection point | Recovery |
|---|---|---|
| Frame length = 0 | `process_client_rx_buffer` → `frame_len == 0` | drop client (`return -1` → `remove_active_client`) |
| Frame length > 4096 | same place | drop client |
| Invalid JSON | `extract_json_value` → `jsmn_parse` returns negative | logs error, returns empty `message_out_t` (length=0); routing logic treats this as "no target/topic" → message dropped silently |
| Pending client RX buffer fills before HELLO | `incoming_msg_buffer_offset` reaches 4 KB without a full frame | next `read()` returns 0 bytes available → `extract_single_frame` returns 0 forever; handshake timeout (5 s) eventually evicts |
| Active client RX buffer full | `available == 0` in `ipc_client_handle_fd_events` | `remove_active_client` (drop connection) |
| HELLO with wrong `type` | `ipc_client_interview_handle_fd_events` → `strcmp(msg_type.value, "hello") != 0` | send hello-error("expected hello"), `remove_pending_client` |
| Message with neither `target` nor `topic` | `router_route_message` → both `length == 0` | `LOG_WARN("Dropping message without topic or target")`, return `-1`; sender keeps connection |

The pattern: **malformed framing kills the connection; malformed semantics drops the message.** Framing errors mean the byte stream is desynchronized — there's no safe way to resync, so close the fd. Semantic errors (unroutable, bad JSON inside the frame) leave the stream intact, so we just discard the offending message.

---

## Flow J — Polling Decision Tree (per loop iteration)

```
build_pollset:
   pfds[0] = server_fd (POLLIN)
   for each active[i]:
      events = POLLIN
      if queue_start_idx != queue_end_idx: events |= POLLOUT
      ctx[i] = { role=ACTIVE, index=i }
   for each pending[i]:
      events = POLLIN
      ctx[i] = { role=PENDING, index=i }

poll(pfds, nfds, 5000ms):
   timeout?
     → loop_once returns 0; main loop iterates → rebuild pollset
     (timeout path also flushes interview-timeout via the fall-through in ipc_handle_fd_events)
   error (EINTR)?
     → ignore, retry
   error (other)?
     → exit loop
   ready fds:
     for each pfd with revents != 0:
        ipc_handle_fd_events(pfd, ctx) →
           SERVER  → accept new client
           PENDING → handshake step
           ACTIVE  → POLLIN: read+route, POLLOUT: flush
        ipc_client_interview_timeout()  // every dispatch
     check_and_log_sigpipe()
```

Each tick is **independent**: state lives only in `pending[]` / `active[]`, never in stack-local. That's what allows the pollset to be rebuilt from scratch every iteration without corrupting in-flight work.

---

## Special Scenarios — Quick Reference

| Scenario | What happens | Code path |
|---|---|---|
| Two clients with the same `instance_name` | Whichever's slot is checked first wins; second one still gets messages addressed to its `service_type`, but never to its `instance_name` | `router_route_message` loop break on first instance match |
| Subscription list contains 21 patterns | `str_to_array` only fills first 20; rest silently dropped | `str_to_array` `count < max_items` guard |
| Client sends frame with both `target` AND `topic` | `target` wins (checked first); `topic` ignored | `router_route_message` if/else if |
| HELLO arrives in two `read()` calls | First `read()` buffers partial bytes; `extract_single_frame` returns 0; loop yields; second `read()` completes the frame | `pending_client_t::incoming_msg_buffer` accumulates across reads |
| Client connects but never sends | Still in `pending[]` after 5 s → `ipc_client_interview_timeout` evicts with hello-error("timeout") | Flow D |
| 33 clients try to connect simultaneously | First 32 get pending slots; 33rd accept gets through (`accept` always succeeds at kernel level) but `add_pending_client` rejects it; controller sends hello-error("too many pending clients") and closes | Flow B' |
| Active client A subscribes to `sensor.*`, client B publishes `topic="sensor.temp"`. While A's queue is being flushed, A also publishes `target="dashboard"` | Both directions independent; `flush_client_tx` only writes from A's queue, doesn't interact with A's RX buffer | RX/TX are separate `iovec` paths; `tx_offset` and `incoming_msg_buffer_offset` are independent |
| Server restart while clients are connected | Old socket file unlinked at startup (`unlink(IPC_SOCKET_PATH)`); existing client fds in old kernel just see ECONNRESET on next operation | `ipc_controller_init` start |
| Client sends 4 KB frame then disconnects mid-payload | RX buffer holds partial bytes; next `read()` returns 0 (EOF); `remove_active_client` cleans up — partial frame discarded | `ipc_client_handle_fd_events` n <= 0 branch |

---

## Lifecycle Visualization (state diagram)

```
                     ┌──────────────┐
                     │  (no state)  │
                     └──────┬───────┘
                            │ accept()
                            ▼
                     ┌──────────────┐  invalid frame / bad type / 5s timeout / capacity
                     │   PENDING    │ ──────────────────────────────────────────────────►  CLOSED
                     │ (max 16)     │
                     └──────┬───────┘
                            │ valid HELLO + slot available
                            ▼
                     ┌──────────────┐
                     │   ACTIVE     │  ◄──┐
                     │ (max 32)     │     │ POLLIN: read → route
                     │              │ ────┘
                     │              │  ◄──┐
                     │              │     │ POLLOUT: flush_client_tx
                     │              │ ────┘
                     └──────┬───────┘
                            │ EOF / error / TX-write-failure
                            ▼
                     ┌──────────────┐
                     │   CLOSED     │  free TX queue, free struct, close fd
                     └──────────────┘
```

---

## What the FLOW.html does (tl;dr)

`FLOW.html` is the visual companion to this document. It animates a tick-by-tick simulation:

1. Two clients connect and shake hands (Flow B + C).
2. One client publishes a message addressed by `target` (Flow E) — you watch the bytes travel through the controller, into the router, into the recipient's TX queue, out to the wire.
3. A topic pub/sub fan-out (Flow F).
4. A timeout eviction (Flow D).
5. A queue-full drop scenario (Flow G).

Every animated step is annotated with the exact function name and line number from the source so you can trace the visual to the code.
