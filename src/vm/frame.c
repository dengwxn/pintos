#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "swap.h"


static struct lock frame_lock;

static struct hash frame_map;

static struct list frame_list;
static struct list_elem *clock_ptr;

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct frame_table_entry *entry = hash_entry(elem, struct frame_table_entry, helem);
    return hash_bytes( &entry->kpage, sizeof entry->kpage );
}

static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    struct frame_table_entry *a_entry = hash_entry(a, struct frame_table_entry, helem);
    struct frame_table_entry *b_entry = hash_entry(b, struct frame_table_entry, helem);
    return a_entry->kpage < b_entry->kpage;
}

static struct frame_table_entry* pick_frame_to_evict(uint32_t* pagedir);
static void vm_frame_do_free (void *kpage, bool free_page);


void vm_frame_init (){
    lock_init (&frame_lock);
    list_init (&frame_list);
    hash_init (&frame_map, frame_hash_func, frame_less_func, NULL);
    clock_ptr = NULL;
}

void* vm_frame_allocate (enum palloc_flags flags, void *upage){
    lock_acquire (&frame_lock);

    void *frame_page = palloc_get_page (PAL_USER | flags);
    if (frame_page == NULL) {
        struct frame_table_entry *f_evicted = pick_frame_to_evict( thread_current()->pagedir );
        pagedir_clear_page(f_evicted->t->pagedir, f_evicted->upage);

        bool o = false;
        o = o || pagedir_is_dirty(f_evicted->t->pagedir, f_evicted->upage);
        o = o || pagedir_is_dirty(f_evicted->t->pagedir, f_evicted->kpage);

        swap_index_t swap_idx = vm_swap_out( f_evicted->kpage );
        vm_supt_set_swap(f_evicted->t->supt, f_evicted->upage, swap_idx);
        vm_supt_set_dirty(f_evicted->t->supt, f_evicted->upage, o);
        vm_frame_do_free(f_evicted->kpage, true);

        frame_page = palloc_get_page (PAL_USER | flags);
    }

    struct frame_table_entry *frame = malloc(sizeof(struct frame_table_entry));
    if(frame == NULL) {
        lock_release (&frame_lock);
        return NULL;
    }

    frame->t = thread_current ();
    frame->upage = upage;
    frame->kpage = frame_page;
    frame->pinned = true;

    hash_insert (&frame_map, &frame->helem);
    list_push_back (&frame_list, &frame->lelem);

    lock_release (&frame_lock);
    return frame_page;
}

void vm_frame_free (void *kpage){
    lock_acquire (&frame_lock);
    vm_frame_do_free (kpage, true);
    lock_release (&frame_lock);
}

void vm_frame_remove_entry (void *kpage){
    lock_acquire (&frame_lock);
    vm_frame_do_free (kpage, false);
    lock_release (&frame_lock);
}

void vm_frame_do_free (void *kpage, bool free_page){
    struct frame_table_entry f_tmp;
    f_tmp.kpage = kpage;

    struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));

    struct frame_table_entry *f;
    f = hash_entry(h, struct frame_table_entry, helem);

    hash_delete (&frame_map, &f->helem);
    list_remove (&f->lelem);

    if(free_page) palloc_free_page(kpage);
    free(f);
}

struct frame_table_entry* clock_frame_next(void);
struct frame_table_entry* pick_frame_to_evict( uint32_t *pagedir ){
    size_t n = hash_size(&frame_map);
    size_t it;
    for(it = 0; it <= n + n; ++ it){
        struct frame_table_entry *e = clock_frame_next();
        if(e->pinned) continue;
        else if( pagedir_is_accessed(pagedir, e->upage)) {
            pagedir_set_accessed(pagedir, e->upage, false);
            continue;
        }
        return e;
    }
    PANIC ("No memory");
}
struct frame_table_entry* clock_frame_next(void){
    if (clock_ptr == NULL || clock_ptr == list_end(&frame_list))
        clock_ptr = list_begin (&frame_list);
    else
        clock_ptr = list_next (clock_ptr);
    struct frame_table_entry *e = list_entry(clock_ptr, struct frame_table_entry, lelem);
    return e;
}


static void vm_frame_set_pinned (void *kpage, bool new_value){
    lock_acquire (&frame_lock);
    struct frame_table_entry f_tmp;
    f_tmp.kpage = kpage;
    struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
    struct frame_table_entry *f;
    f = hash_entry(h, struct frame_table_entry, helem);
    f->pinned = new_value;
    lock_release (&frame_lock);
}

void vm_frame_unpin (void* kpage) {
    vm_frame_set_pinned (kpage, false);
}

void
vm_frame_pin (void* kpage) {
    vm_frame_set_pinned (kpage, true);
}