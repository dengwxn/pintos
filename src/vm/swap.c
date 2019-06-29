#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"

static struct block *swap_block;
static struct bitmap *swap_available;

static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;

static size_t swap_size;

void vm_swap_init (){
    swap_block = block_get_role(BLOCK_SWAP);
    swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
    swap_available = bitmap_create(swap_size);
    bitmap_set_all(swap_available, true);
}


swap_index_t vm_swap_out (void *page){
    size_t swap_index = bitmap_scan (swap_available, 0, 1, true);

    size_t i;
    for (i = 0; i < SECTORS_PER_PAGE; ++ i) {
        block_write(swap_block, swap_index * SECTORS_PER_PAGE + i, page + (BLOCK_SECTOR_SIZE * i));
    }

    bitmap_set(swap_available, swap_index, false);
    return swap_index;
}


void vm_swap_in (swap_index_t swap_index, void *page){
    size_t i;
    for (i = 0; i < SECTORS_PER_PAGE; ++ i) {
        block_read (swap_block, swap_index * SECTORS_PER_PAGE + i, page + (BLOCK_SECTOR_SIZE * i));
    }
    bitmap_set(swap_available, swap_index, true);
    return;
}

void vm_swap_free (swap_index_t swap_index){
    bitmap_set(swap_available, swap_index, true);
}
