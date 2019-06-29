#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/palloc.h"

struct frame_table_entry {
    void *kpage;               /* page to p-address */

    struct hash_elem helem;
    struct list_elem lelem;

    void *upage;               /* User (Virtual Memory) Address*/
    struct thread *t;

    bool pinned;               /* prevent a frame from being evicted.
                                  true -> never evicted. */
};

void vm_frame_init (void);
void vm_frame_free (void*);
void vm_frame_pin (void* kpage);
void vm_frame_unpin (void* kpage);
void* vm_frame_allocate (enum palloc_flags flags, void *upage);
void vm_frame_remove_entry (void*);

#endif /* vm/frame.h */
