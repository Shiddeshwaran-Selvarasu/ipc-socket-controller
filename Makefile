# =====================
# Directories
# =====================
BUILD_DIR = .build
OBJ_DIR   = $(BUILD_DIR)/obj

# =====================
# Toolchain
# =====================
# For native compilation, uncomment the following line
# CC = gcc
# For cross-compilation to ARM64, uncomment the following line
CC = aarch64-linux-gnu-gcc

# =====================
# Source Files
# =====================
C_SRCS = src/main.c \
		 src/core/event_loop.c \
         src/common/logger.c \
		 src/message/message.c \
		 src/router/router.c \
		 src/ipc/ipc_controller.c

# =====================
# Object Files
# =====================
OBJS = $(addprefix $(OBJ_DIR)/, $(notdir $(C_SRCS:.c=.o)))

# =====================
# Include Paths
# =====================
INCLUDES = -Isrc -Isrc/common -Isrc/message -Isrc/ipc -Isrc/core -Isrc/router

# =====================
# Compiler Flags
# =====================
CFLAGS = -Wall -Wextra -O2 -g $(INCLUDES)

# =====================
# Linker Flags
# =====================
LDFLAGS =

# =====================
# Output Files
# =====================
TARGET = $(BUILD_DIR)/ipc_controller

# =====================
# Default Target
# =====================
all: $(TARGET)

# =====================
# vpath for source files
# =====================
vpath %.c . src src/common src/message src/ipc src/core src/router

# =====================
# Build Rules
# =====================

# Single build rule for all C sources
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR): | $(BUILD_DIR)
	mkdir -p $(OBJ_DIR)

# Link objects to executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

# =====================
# Clean Rule
# =====================
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
