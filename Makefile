# =====================
# Directories
# =====================
BUILD_DIR 	= .build
OBJ_DIR   	= $(BUILD_DIR)/obj
EXPORT_DIR  = $(BUILD_DIR)/exports
LIB_DIR   	= $(EXPORT_DIR)/lib

# =====================
# Toolchain
# =====================
# For native compilation, uncomment the following line
CC = gcc
# For cross-compilation to ARM64, uncomment the following line
# CC = aarch64-linux-gnu-gcc

# =====================
# Flags
# =====================
INCLUDES = -Isrc/include
CFLAGS   = -Wall -Wextra -O2 -g -fPIC $(INCLUDES)
LDFLAGS  = -L$(LIB_DIR) -Wl,-rpath='./lib'

# =====================
# Shared Library Names
# =====================
# Common logger
LIB_LOGGER_NAME    = libipc_logger.so
# Core event loop
LIB_EVENTLOOP_NAME = libipc_eventloop.so
# Message parsing
LIB_MESSAGE_NAME   = libipc_message.so
# Router (protocol related)
LIB_ROUTER_NAME    = libipc_router.so
# IPC Controller (main logic, proto)
LIB_PROTO_NAME     = libipc_proto.so

# =====================
# Targets
# =====================
TARGET_BIN = $(EXPORT_DIR)/ipc_controller

LIB_LOGGER    = $(LIB_DIR)/$(LIB_LOGGER_NAME)
LIB_MESSAGE   = $(LIB_DIR)/$(LIB_MESSAGE_NAME)
LIB_EVENTLOOP = $(LIB_DIR)/$(LIB_EVENTLOOP_NAME)
LIB_ROUTER    = $(LIB_DIR)/$(LIB_ROUTER_NAME)
LIB_PROTO     = $(LIB_DIR)/$(LIB_PROTO_NAME)

# Source Files
SRC_MAIN      = src/main.c
SRC_LOGGER    = src/common/logger.c
SRC_MESSAGE   = src/message/message.c
SRC_EVENTLOOP = src/core/event_loop.c
SRC_ROUTER    = src/router/router.c
SRC_PROTO     = src/ipc/ipc_controller.c

# Object Files
OBJ_MAIN      = $(OBJ_DIR)/main.o
OBJ_LOGGER    = $(OBJ_DIR)/logger.o
OBJ_MESSAGE   = $(OBJ_DIR)/message.o
OBJ_EVENTLOOP = $(OBJ_DIR)/event_loop.o
OBJ_ROUTER    = $(OBJ_DIR)/router.o
OBJ_PROTO     = $(OBJ_DIR)/ipc_controller.o

# =====================
# Rules
# =====================
all: directories $(LIB_LOGGER) $(LIB_MESSAGE) $(LIB_EVENTLOOP) $(LIB_ROUTER) $(LIB_PROTO) $(TARGET_BIN)

directories:
	mkdir -p $(OBJ_DIR) $(EXPORT_DIR) $(LIB_DIR)

# --- Compile Objects ---
$(OBJ_MAIN): $(SRC_MAIN)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_LOGGER): $(SRC_LOGGER)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_MESSAGE): $(SRC_MESSAGE)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_EVENTLOOP): $(SRC_EVENTLOOP)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_ROUTER): $(SRC_ROUTER)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_PROTO): $(SRC_PROTO)
	$(CC) $(CFLAGS) -c $< -o $@

# --- Link Shared Libraries ---
$(LIB_LOGGER): $(OBJ_LOGGER)
	$(CC) -shared -o $@ $^

$(LIB_MESSAGE): $(OBJ_MESSAGE) $(LIB_LOGGER)
	$(CC) -shared -o $@ $(OBJ_MESSAGE) -L$(LIB_DIR) -lipc_logger

$(LIB_EVENTLOOP): $(OBJ_EVENTLOOP) $(LIB_LOGGER)
	$(CC) -shared -o $@ $(OBJ_EVENTLOOP) -L$(LIB_DIR) -lipc_logger

# Use -Wl,--allow-shlib-undefined for circular dependency between router and proto
$(LIB_ROUTER): $(OBJ_ROUTER) $(LIB_LOGGER) $(LIB_MESSAGE)
	$(CC) -shared -Wl,--allow-shlib-undefined -o $@ $(OBJ_ROUTER) -L$(LIB_DIR) -lipc_logger -lipc_message

$(LIB_PROTO): $(OBJ_PROTO) $(LIB_LOGGER) $(LIB_MESSAGE) $(LIB_ROUTER)
	$(CC) -shared -Wl,--allow-shlib-undefined -o $@ $(OBJ_PROTO) -L$(LIB_DIR) -lipc_logger -lipc_message -lipc_router

# --- Link Executable ---
$(TARGET_BIN): $(OBJ_MAIN) $(LIB_LOGGER) $(LIB_MESSAGE) $(LIB_EVENTLOOP) $(LIB_ROUTER) $(LIB_PROTO)
	$(CC) $(CFLAGS) -o $@ $(OBJ_MAIN) $(LDFLAGS) -lipc_proto -lipc_router -lipc_eventloop -lipc_message -lipc_logger

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean directories
