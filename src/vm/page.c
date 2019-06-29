#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "filesys/file.h"

static bool spte_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    struct supplemental_page_table_entry *a_entry = hash_entry(a, struct supplemental_page_table_entry, elem);
    struct supplemental_page_table_entry *b_entry = hash_entry(b, struct supplemental_page_table_entry, elem);
    return a_entry->upage < b_entry->upage;
}
static void spte_destroy_func(struct hash_elem *elem, void *aux UNUSED){
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);

    if (entry->kpage != NULL)
        vm_frame_remove_entry (entry->kpage);
    else if(entry->status == ON_SWAP)
        vm_swap_free (entry->swap_index);
    free (entry);
}

static unsigned spte_hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);
    return hash_int( (int)entry->upage );
}

bool vm_supt_set_page(struct supplemental_page_table *supt, void *upage, void *kpage){
    struct supplemental_page_table_entry *tmp;
    tmp = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

    tmp->upage = upage;
    tmp->kpage = kpage;
    tmp->status = ON_FRAME;
    tmp->dirty = false;
    tmp->swap_index = -1;

    struct hash_elem *judge;
    judge = hash_insert (&supt->page_map, &tmp->elem);
    if (judge == NULL)
        return true;
    else {
        free (tmp);
        return false;
    }
}

bool vm_supt_install_zeropage (struct supplemental_page_table *supt, void *upage){
    struct supplemental_page_table_entry *tmp;
    tmp = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

    tmp->upage = upage;
    tmp->kpage = NULL;
    tmp->status = ALL_ZERO;
    tmp->dirty = false;

    struct hash_elem *judge;
    judge = hash_insert (&supt->page_map, &tmp->elem);
    if (judge == NULL)
        return true;
    else
        return false;
}

bool vm_supt_set_swap (struct supplemental_page_table *supt, void *page, swap_index_t swap_index){
    // mark an page is swapped out
    struct supplemental_page_table_entry *tmp;
    tmp = vm_supt_lookup(supt, page);
    if(tmp == NULL)
        return false;

    tmp->status = ON_SWAP;
    tmp->kpage = NULL;
    tmp->swap_index = swap_index;
    return true;
}


bool vm_supt_install_filesys (struct supplemental_page_table *supt, void *upage,
                         struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable){
    struct supplemental_page_table_entry *tmp;
    tmp = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

    tmp->upage = upage;
    tmp->kpage = NULL;
    tmp->status = FROM_FILESYS;
    tmp->dirty = false;
    tmp->file = file;
    tmp->file_offset = offset;
    tmp->read_bytes = read_bytes;
    tmp->zero_bytes = zero_bytes;
    tmp->writable = writable;

    struct hash_elem *judge;
    judge = hash_insert (&supt->page_map, &tmp->elem);
    if (judge == NULL)
        return true;
    else
        return false;
}


struct supplemental_page_table_entry*
vm_supt_lookup (struct supplemental_page_table *supt, void *page) {
    struct supplemental_page_table_entry tmp;
    tmp.upage = page;

    struct hash_elem *elem = hash_find (&supt->page_map, &tmp.elem);
    if(elem == NULL)
        return NULL;
    return hash_entry(elem, struct supplemental_page_table_entry, elem);
}

bool vm_supt_has_entry (struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry *tmp = vm_supt_lookup(supt, page);
    if(tmp == NULL)
        return false;
    else
        return true;
}

bool vm_supt_set_dirty (struct supplemental_page_table *supt, void *page, bool value){
    struct supplemental_page_table_entry *tmp = vm_supt_lookup(supt, page);
    if (tmp == NULL)
        PANIC("There isn't the page.");

    tmp->dirty = tmp->dirty || value;
    return true;
}

static bool vm_load_page_from_filesys(struct supplemental_page_table_entry *, void *);

bool vm_load_page(struct supplemental_page_table *supt, uint32_t *pagedir, void *upage) {
    struct supplemental_page_table_entry *spte;
    spte = vm_supt_lookup(supt, upage);
    if(spte == NULL)
        return false;
    if(spte->status == ON_FRAME)
        return true;

    // get a frame to store it
    void *frame_page = vm_frame_allocate(PAL_USER, upage);
    if(frame_page == NULL)
        return false;

    // load data
    bool writable = true;
    switch (spte->status){
        case ALL_ZERO:
            memset (frame_page, 0, PGSIZE);
            break;
        case ON_FRAME:
            break;
        case ON_SWAP:
            vm_swap_in (spte->swap_index, frame_page);
            break;
        case FROM_FILESYS:
            if( vm_load_page_from_filesys(spte, frame_page) == false) {
                vm_frame_free(frame_page);
                return false;
            }
            writable = spte->writable;
            break;
        default:
            return false;
    }

    if(!pagedir_set_page (pagedir, upage, frame_page, writable)) {
        vm_frame_free(frame_page);
        return false;
    }

    spte->kpage = frame_page;
    spte->status = ON_FRAME;

    pagedir_set_dirty (pagedir, frame_page, false);

    vm_frame_unpin(frame_page);

    return true;
}

bool vm_supt_mm_unmap(
        struct supplemental_page_table *supt, uint32_t *pagedir,
        void *page, struct file *f, off_t offset, size_t bytes){
    struct supplemental_page_table_entry *tmp = vm_supt_lookup(supt, page);

    if (tmp->status == ON_FRAME)
        vm_frame_pin (tmp->kpage);


    switch (tmp->status){
        case ON_FRAME:
            ASSERT (tmp->kpage != NULL);
            // dirty handling (write into file)
            bool is_dirty = tmp->dirty;
            is_dirty = is_dirty || pagedir_is_dirty(pagedir, tmp->upage);
            is_dirty = is_dirty || pagedir_is_dirty(pagedir, tmp->kpage);
            if(is_dirty) {
                file_write_at (f, tmp->upage, bytes, offset);
            }

            vm_frame_free (tmp->kpage);
            pagedir_clear_page (pagedir, tmp->upage);
            break;

        case ON_SWAP:{
            bool is_dirty = tmp->dirty;
            is_dirty = is_dirty || pagedir_is_dirty(pagedir, tmp->upage);
            if (is_dirty) {
                // load from swap, write back
                void *tmp_page = palloc_get_page(0);
                vm_swap_in (tmp->swap_index, tmp_page);
                file_write_at (f, tmp_page, PGSIZE, offset);
                palloc_free_page(tmp_page);
            }
            else
                vm_swap_free (tmp->swap_index);
        }
            break;

        case FROM_FILESYS:
            break;

        default:
            return false;
    }

    hash_delete(&supt->page_map, &tmp->elem);
    return true;
}


static bool vm_load_page_from_filesys(struct supplemental_page_table_entry *spte, void *kpage){
    file_seek (spte->file, spte->file_offset);

    // read bytes from the file
    int n_read = file_read (spte->file, kpage, spte->read_bytes);
    if(n_read != (int)spte->read_bytes)
        return false;

    // remain bytes are just zero
    memset (kpage + n_read, 0, spte->zero_bytes);
    return true;
}


void vm_pin_page(struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry *spte;
    spte = vm_supt_lookup(supt, page);
    if(spte == NULL)
        return;
    vm_frame_pin (spte->kpage);
}

void vm_unpin_page(struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry *spte;
    spte = vm_supt_lookup(supt, page);
    if (spte->status == ON_FRAME)
        vm_frame_unpin (spte->kpage);
}

struct supplemental_page_table* vm_supt_create (void) {
    struct supplemental_page_table *supt =
            (struct supplemental_page_table*) malloc(sizeof(struct supplemental_page_table));

    hash_init (&supt->page_map, spte_hash_func, spte_less_func, NULL);
    return supt;
}

void vm_supt_destroy (struct supplemental_page_table *supt) {
    hash_destroy (&supt->page_map, spte_destroy_func);
    free (supt);
}
