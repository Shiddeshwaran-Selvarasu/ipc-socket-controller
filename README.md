# IPC Socket Controller

A lightweight, poll-based Unix domain socket message broker written in C. It lets local processes discover each other and exchange JSON messages using either direct addressing or publish/subscribe topic routing — with no external dependencies beyond libc.

## Features

- **Unix domain socket transport** — zero-copy local IPC via `/run/ipc_controller.sock`
- **Two routing modes** — direct target addressing (by service type or unique instance name) and pub/sub topic routing with wildcard support (`sensor.*`)
- **Stateful handshake** — clients register with a service type, instance name, and subscription list before they can send or receive messages
- **Non-blocking I/O** — single-threaded `poll()`-based event loop; no threads, no locks
- **Per-client TX queue** — up to 1000 messages buffered per client with backpressure
- **Modular shared-library design** — each subsystem is a separate `.so` so components can be reused independently
- **Embedded JSMN** — zero-dependency JSON parsing via the MIT-licensed JSMN tokenizer

## Quick Start

**Requirements:** GCC, CMake ≥ 3.10, Linux.

```bash
# Build
cmake -B build && cmake --build build

# Run (needs /run to be writable, or adjust IPC_SOCKET_PATH in ipc_protocol.h)
sudo ./build/exports/ipc_controller
```

The server listens on `/run/ipc_controller.sock`.

## Protocol

All messages are **length-prefixed JSON frames**:

```
[ 4-byte LE uint32 length ][ JSON payload (UTF-8) ]
```

Max payload size is **4096 bytes**.

### 1. Handshake (HELLO)

A newly connected client must send a `hello` message within **5 seconds** or it is dropped.

```json
{
  "type": "hello",
  "service": "sensor_service",
  "instance": "sensor_001",
  "subscriptions": ["alerts.*", "config.update"]
}
```

The server replies with an ACK:

```json
{
  "type": "hello",
  "status": "ok",
  "service": "sensor_service",
  "instance": "sensor_001",
  "subscriptions": ["alerts.*", "config.update"],
  "max_msg_len": 4096
}
```

On failure (timeout, capacity, bad message) the server sends an error frame and closes the connection:

```json
{ "type": "hello", "status": "error", "reason": "timeout" }
```

### 2. Routing Messages

After the handshake, clients send regular JSON frames. The router dispatches them based on which field is present:

**Direct target routing** — routes to all clients whose `service` matches, or to exactly one client whose `instance` matches (stops at first hit):

```json
{
  "target": "sensor_service",
  "payload": { "cmd": "read_temp" }
}
```

**Topic pub/sub routing** — routes to every client that has a matching subscription. Wildcards match any suffix after the prefix:

```json
{
  "topic": "alerts.critical",
  "payload": { "msg": "over-temperature" }
}
```

A message must contain exactly one of `target` or `topic`; messages with neither are dropped.

## Limits

| Parameter | Value |
|---|---|
| Max active clients | 32 |
| Max pending (handshaking) clients | 16 |
| Max subscriptions per client | 20 |
| Max queued outbound messages per client | 1000 |
| Max message size | 4096 bytes |
| Handshake timeout | 5 000 ms |
| Socket path | `/run/ipc_controller.sock` |

## Repository Layout

```
.
├── CMakeLists.txt          # Build definition — 6 shared libs + 1 executable
├── Makefile                # Thin wrapper around CMake
└── src/
    ├── main.c              # Entry point
    ├── include/            # Public headers for every module
    │   ├── ipc_protocol.h  # Protocol constants and wire structs
    │   ├── ipc_controller.h
    │   ├── event_loop.h
    │   ├── message.h
    │   ├── router.h
    │   ├── logger.h
    │   └── jsmn.h          # Embedded JSMN JSON tokenizer
    ├── ipc/
    │   └── ipc_controller.c   # Socket server, client lifecycle, frame framing
    ├── core/
    │   └── event_loop.c       # poll() loop, SIGPIPE handling
    ├── message/
    │   └── message.c          # JSON parsing (JSMN) and hello message generation
    ├── router/
    │   └── router.c           # Routing logic (direct + pub/sub)
    ├── common/
    │   └── logger.c           # Levelled stderr logger
    └── storage/
        ├── storage.h          # Slotted-page storage (4 KB pages)
        └── storage.c
```

## Build Output

CMake places all artifacts under `build/exports/`:

```
build/exports/
├── ipc_controller          # Main executable
└── lib/
    ├── libipc_logger.so
    ├── libipc_message.so
    ├── libipc_eventloop.so
    ├── libipc_router.so
    ├── libipc_proto.so
    └── libipc_storage.so
```

RPATH is set to `$ORIGIN/lib` so the executable finds its libraries without `LD_LIBRARY_PATH`.

## License

MIT — see [LICENSE](LICENSE).
