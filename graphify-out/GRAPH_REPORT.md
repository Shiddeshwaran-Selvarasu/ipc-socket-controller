# Graph Report - .  (2026-04-25)

## Corpus Check
- Corpus is ~6,101 words - fits in a single context window. You may not need a graph.

## Summary
- 110 nodes · 177 edges · 22 communities detected
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.81)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_IPC Client Lifecycle|IPC Client Lifecycle]]
- [[_COMMUNITY_Message Parsing & Framing|Message Parsing & Framing]]
- [[_COMMUNITY_Build & Architecture|Build & Architecture]]
- [[_COMMUNITY_Client State & Protocol|Client State & Protocol]]
- [[_COMMUNITY_JSMN Parser Internals|JSMN Parser Internals]]
- [[_COMMUNITY_Event Loop & Signals|Event Loop & Signals]]
- [[_COMMUNITY_JSMN Public API|JSMN Public API]]
- [[_COMMUNITY_Header Interfaces|Header Interfaces]]
- [[_COMMUNITY_Message Router|Message Router]]
- [[_COMMUNITY_Storage Operations|Storage Operations]]
- [[_COMMUNITY_Slotted Page Storage|Slotted Page Storage]]
- [[_COMMUNITY_App Entry Point|App Entry Point]]
- [[_COMMUNITY_Logging|Logging]]
- [[_COMMUNITY_Protocol Constants|Protocol Constants]]
- [[_COMMUNITY_Message API|Message API]]
- [[_COMMUNITY_Logger API|Logger API]]
- [[_COMMUNITY_Router API|Router API]]
- [[_COMMUNITY_Event Loop API|Event Loop API]]
- [[_COMMUNITY_IPC Controller API|IPC Controller API]]
- [[_COMMUNITY_Storage API|Storage API]]
- [[_COMMUNITY_Router Interface|Router Interface]]
- [[_COMMUNITY_Storage Header|Storage Header]]

## God Nodes (most connected - your core abstractions)
1. `extract_json_value()` - 13 edges
2. `IPC Controller Module` - 13 edges
3. `Router Module` - 10 edges
4. `Message Parser/Generator Module` - 10 edges
5. `ipc_client_interview_handle_fd_events()` - 7 edges
6. `Main Entry Point` - 7 edges
7. `Logger Module` - 7 edges
8. `CMakeLists Build Configuration` - 7 edges
9. `ipc_client_handle_fd_events()` - 6 edges
10. `IPC Protocol Constants and Structs Header` - 6 edges

## Surprising Connections (you probably didn't know these)
- `CMakeLists Build Configuration` --references--> `IPC Controller Module`  [EXTRACTED]
  CMakeLists.txt → src/ipc/ipc_controller.c
- `IPC Controller Module` --conceptually_related_to--> `Circular Dependency: ipc_router <-> ipc_proto`  [EXTRACTED]
  src/ipc/ipc_controller.c → CMakeLists.txt
- `CMakeLists Build Configuration` --references--> `Message Parser/Generator Module`  [EXTRACTED]
  CMakeLists.txt → src/message/message.c
- `CMakeLists Build Configuration` --references--> `Storage (Slotted Page) Module`  [EXTRACTED]
  CMakeLists.txt → src/storage/storage.c
- `CMakeLists Build Configuration` --references--> `Event Loop Module`  [EXTRACTED]
  CMakeLists.txt → src/core/event_loop.c

## Hyperedges (group relationships)
- **Client Lifecycle: Pending -> Interview -> Active -> Routing** — ipc_controller_module, handshake_protocol, pending_client_t, active_client_t, router_module [EXTRACTED 0.95]
- **Message Framing, Parsing, and Routing Pipeline** — length_prefixed_framing, message_module, router_module [INFERRED 0.88]
- **Poll-Based Event Dispatch (event_loop, ipc_controller, poll_ctx_t)** — event_loop_module, ipc_controller_module, poll_ctx_t [EXTRACTED 0.92]

## Communities

### Community 0 - "IPC Client Lifecycle"
Cohesion: 0.17
Nodes (22): add_active_client(), add_pending_client(), buffer_consume(), client_array_reset(), extract_single_frame(), flush_client_tx(), get_active_client_index(), get_pending_client_index() (+14 more)

### Community 1 - "Message Parsing & Framing"
Cohesion: 0.19
Nodes (13): extract_json_value(), get_message_instance(), get_message_payload(), get_message_priority(), get_message_service(), get_message_source(), get_message_subscriptions(), get_message_target() (+5 more)

### Community 2 - "Build & Architecture"
Cohesion: 0.36
Nodes (9): Circular Dependency: ipc_router <-> ipc_proto, CMakeLists Build Configuration, Event Loop Module, logLevel_t Enum, Logger Module, Router Module, Direct Target Routing (service_type or instance_name), Topic-Based Pub/Sub Routing (+1 more)

### Community 3 - "Client State & Protocol"
Cohesion: 0.5
Nodes (8): active_client_t Struct, Client Handshake Protocol (HELLO/ACK), hello_message_t Struct, IPC Controller Module, IPC Protocol Constants and Structs Header, Length-Prefixed Frame Protocol (4-byte LE header), pending_client_t Struct, queued_message_t Struct

### Community 4 - "JSMN Parser Internals"
Cohesion: 0.62
Nodes (5): jsmn_alloc_token(), jsmn_fill_token(), jsmn_parse(), jsmn_parse_primitive(), jsmn_parse_string()

### Community 5 - "Event Loop & Signals"
Cohesion: 0.47
Nodes (3): check_and_log_sigpipe(), loop(), loop_once()

### Community 6 - "JSMN Public API"
Cohesion: 0.47
Nodes (6): JSMN JSON Tokenizer (MIT, Serge Zaitsev), jsmn_parser Struct, jsmntok_t Token Struct, Message Interface Header, Message Parser/Generator Module, message_out_t Struct

### Community 7 - "Header Interfaces"
Cohesion: 0.53
Nodes (6): Event Loop Interface Header, IPC Controller Interface Header, Logger Interface Header, Main Entry Point, poll_ctx_t Struct, poll_role_t Enum

### Community 8 - "Message Router"
Cohesion: 0.6
Nodes (3): enqueue_message(), router_route_message(), topic_match()

### Community 9 - "Storage Operations"
Cohesion: 0.5
Nodes (0): 

### Community 10 - "Slotted Page Storage"
Cohesion: 0.67
Nodes (3): Page Struct (Slotted Page), Slot Struct, Storage (Slotted Page) Module

### Community 11 - "App Entry Point"
Cohesion: 1.0
Nodes (0): 

### Community 12 - "Logging"
Cohesion: 1.0
Nodes (0): 

### Community 13 - "Protocol Constants"
Cohesion: 1.0
Nodes (0): 

### Community 14 - "Message API"
Cohesion: 1.0
Nodes (0): 

### Community 15 - "Logger API"
Cohesion: 1.0
Nodes (0): 

### Community 16 - "Router API"
Cohesion: 1.0
Nodes (0): 

### Community 17 - "Event Loop API"
Cohesion: 1.0
Nodes (0): 

### Community 18 - "IPC Controller API"
Cohesion: 1.0
Nodes (0): 

### Community 19 - "Storage API"
Cohesion: 1.0
Nodes (0): 

### Community 20 - "Router Interface"
Cohesion: 1.0
Nodes (1): Router Interface Header

### Community 21 - "Storage Header"
Cohesion: 1.0
Nodes (1): Storage Header (Slotted Page)

## Knowledge Gaps
- **6 isolated node(s):** `Router Interface Header`, `Storage Header (Slotted Page)`, `Page Struct (Slotted Page)`, `Slot Struct`, `logLevel_t Enum` (+1 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `App Entry Point`** (2 nodes): `main()`, `main.c`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Logging`** (2 nodes): `logger()`, `logger.c`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Protocol Constants`** (1 nodes): `ipc_protocol.h`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Message API`** (1 nodes): `message.h`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Logger API`** (1 nodes): `logger.h`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Router API`** (1 nodes): `router.h`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Event Loop API`** (1 nodes): `event_loop.h`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `IPC Controller API`** (1 nodes): `ipc_controller.h`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Storage API`** (1 nodes): `storage.h`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Router Interface`** (1 nodes): `Router Interface Header`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Storage Header`** (1 nodes): `Storage Header (Slotted Page)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `IPC Controller Module` connect `Client State & Protocol` to `Build & Architecture`, `JSMN Public API`, `Header Interfaces`?**
  _High betweenness centrality (0.028) - this node is a cross-community bridge._
- **Why does `Message Parser/Generator Module` connect `JSMN Public API` to `Slotted Page Storage`, `Build & Architecture`, `Client State & Protocol`?**
  _High betweenness centrality (0.025) - this node is a cross-community bridge._
- **Why does `Router Module` connect `Build & Architecture` to `Client State & Protocol`, `JSMN Public API`?**
  _High betweenness centrality (0.017) - this node is a cross-community bridge._
- **What connects `Router Interface Header`, `Storage Header (Slotted Page)`, `Page Struct (Slotted Page)` to the rest of the system?**
  _6 weakly-connected nodes found - possible documentation gaps or missing edges._