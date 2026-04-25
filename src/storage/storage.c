#include "storage.h"

_Static_assert(sizeof(PageHeader) == 4, "PageHeader layout changed");

void page_init(Page *pg) {
    memset(pg, 0, sizeof(Page));
    pg->header.free_ptr = PAGE_SIZE - sizeof(PageHeader);
}

int add_json_to_page(Page *pg, const char *json_blob) {
    uint16_t len = (uint16_t)strlen(json_blob);
    uint16_t space_needed = sizeof(Slot) + len;
    
    // Calculate current free space
    // (Free pointer minus the space taken by the slot directory)
    uint16_t current_free_space = pg->header.free_ptr - (pg->header.slot_count * sizeof(Slot));

    if (space_needed > current_free_space) return -1;

    pg->header.free_ptr -= len;
    memcpy(&(pg->data[pg->header.free_ptr]), json_blob, len);

    Slot *slots = (Slot *)pg->data;
    slots[pg->header.slot_count].offset = pg->header.free_ptr;
    slots[pg->header.slot_count].length = len;
    pg->header.slot_count++;
    
    return pg->header.slot_count - 1; // Return the slot index
}

char* get_json_from_page(Page *pg, uint16_t slot_index) {
    if (slot_index >= pg->header.slot_count) return NULL;

    Slot *slots = (Slot *)pg->data;
    uint16_t offset = slots[slot_index].offset;
    uint16_t len = slots[slot_index].length;

    char *result = malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, &pg->data[offset], len);
    result[len] = '\0'; 
    
    return result;
}