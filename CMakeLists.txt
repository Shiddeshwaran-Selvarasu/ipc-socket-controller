cmake_minimum_required(VERSION 3.10)
project(ipc_controller C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Compile options
add_compile_options(-Wall -Wextra -O2 -g -fPIC)

# Output directories matching the Makefile structure
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exports)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exports/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exports/lib)

# Include directories
include_directories(src/include)

# -----------------------------------------------------------------------------
# Shared Libraries
# -----------------------------------------------------------------------------

# 1. Logger
add_library(ipc_logger SHARED src/common/logger.c)

# 2. Message
add_library(ipc_message SHARED src/message/message.c)
target_link_libraries(ipc_message ipc_logger)

# 3. Event Loop
add_library(ipc_eventloop SHARED src/core/event_loop.c)
target_link_libraries(ipc_eventloop ipc_logger)

# 4. Router
# Note: Router has a circular dependency with Proto (ipc_controller).
# We allow undefined symbols so they can refer to each other's symbols
# which will be resolved at runtime by the loader.
add_library(ipc_router SHARED src/router/router.c)
target_link_options(ipc_router PRIVATE "-Wl,--allow-shlib-undefined")
target_link_libraries(ipc_router ipc_logger ipc_message)

# 5. Proto (IPC Controller Logic)
add_library(ipc_proto SHARED src/ipc/ipc_controller.c)
target_link_options(ipc_proto PRIVATE "-Wl,--allow-shlib-undefined")
target_link_libraries(ipc_proto ipc_logger ipc_message ipc_router)

# -----------------------------------------------------------------------------
# Main Executable
# -----------------------------------------------------------------------------

add_executable(ipc_controller src/main.c)

# Link all shared libraries
target_link_libraries(ipc_controller 
    ipc_proto 
    ipc_router 
    ipc_eventloop 
    ipc_message 
    ipc_logger
)

# -----------------------------------------------------------------------------
# RPATH Configuration
# -----------------------------------------------------------------------------

# Set RPATH to look for libraries in the ./lib directory relative to the binary
# $ORIGIN resolves to the directory containing the executable.
set_target_properties(ipc_controller PROPERTIES
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN/lib"
    LINK_FLAGS "-Wl,-rpath,'./lib'"
)
