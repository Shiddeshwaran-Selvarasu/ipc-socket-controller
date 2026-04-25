#pragma once

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define PAGE_SIZE 4096

// Individual Slot metadata
typedef struct {
    uint16_t offset;
    uint16_t length;
} Slot;

// The Header for a 4KB Page
typedef struct {
    uint16_t slot_count;   // How many messages are in this page
    uint16_t free_ptr;     // Offset to the start of free space (grows backward)
} PageHeader;

// A wrapper for our 4KB memory block
typedef struct {
    PageHeader header;
    uint8_t data[PAGE_SIZE - sizeof(PageHeader)]; 
} Page;

void page_init(Page *pg);
int add_json_to_page(Page *pg, const char *json_blob);
char* get_json_from_page(Page *pg, uint16_t slot_index);
