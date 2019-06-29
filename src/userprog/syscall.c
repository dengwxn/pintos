#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <threads/synch.h>
#include <devices/shutdown.h>
#include <threads/palloc.h>
#include <filesys/file.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#ifdef VM
#include "vm/page.h"
#endif

static void syscall_handler(struct intr_frame *);

unsigned int get_user(const unsigned char *uaddr) {
    if (!is_user_vaddr(uaddr))
        fail_invalid_memory_access();
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
    if (result == -1)
        fail_invalid_memory_access();
    return result;
}

void put_user(unsigned char *udst, unsigned char byte) {
    if (!is_user_vaddr(udst))
        fail_invalid_memory_access();
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a"(error_code), "=m"(*udst) : "q"(byte));
    if (error_code == -1)
        fail_invalid_memory_access();
}

void check_user(const char *ptr) {
    get_user((const unsigned char *) ptr);
}

void check_string(const char *ptr) {
    for (; get_user((const unsigned char *) ptr) != 0; ++ptr);
}

unsigned long long read_stack(void **ptr, int size) {
    unsigned long long val = 0;
    unsigned char *dst = (unsigned char *) &val;
    for (int i = 0; i < size; ++i) {
        *(dst + i) = get_user(*ptr) & 0xffu;
        ++(*ptr);
    }
    return val;
}

struct file_descriptor *get_file_descriptor(struct thread *cur, int id) {
    if (!list_empty(&cur->fd_list)) {
        struct list_elem *e;
        for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
            struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
            if (fd->id == id)
                return fd;
        }
    }
    return NULL;
}

#ifdef VM
mmapid_t sys_mmap(int fd, void *);
bool sys_munmap(mmapid_t);

static struct mmap_desc* find_mmap_desc(struct thread *, mmapid_t fd);

void preload_and_pin_pages(const void *, size_t);
void unpin_preloaded_pages(const void *, size_t);
#endif


static struct lock filesys_lock;

void
syscall_init(void) {
    lock_init(&filesys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void fail_invalid_memory_access() {
    if (filesys_lock.holder == thread_current())
        lock_release(&filesys_lock);
    sys_exit(-1);
}

static void
syscall_handler(struct intr_frame *f) {
    void *esp = f->esp;
    int id = read_stack(&esp, sizeof(int));
    thread_current()->current_esp = f->esp;

    switch (id) {
        case SYS_HALT: {
            sys_halt();
            break;
        }
        case SYS_EXIT: {
            int exitcode = read_stack(&esp, sizeof(exitcode));
            sys_exit(exitcode);
            break;
        }
        case SYS_EXEC: {
            char *cmdline = (char *) read_stack(&esp, sizeof(cmdline));
            f->eax = sys_exec(cmdline);
            break;
        }
        case SYS_WAIT: {
            pid_t pid = read_stack(&esp, sizeof(pid));
            f->eax = sys_wait(pid);
            break;
        }
        case SYS_CREATE: {
            const char *name = (const char *) read_stack(&esp, sizeof(name));
            unsigned size = read_stack(&esp, sizeof(size));
            f->eax = sys_create(name, size);
            break;
        }
        case SYS_REMOVE: {
            const char *name = (const char *) read_stack(&esp, sizeof(name));
            f->eax = sys_remove(name);
            break;
        }
        case SYS_OPEN: {
            const char *name = (const char *) read_stack(&esp, sizeof(name));
            f->eax = sys_open(name);
            break;
        }
        case SYS_FILESIZE: {
            int fd = read_stack(&esp, sizeof(fd));
            f->eax = sys_filesize(fd);
            break;
        }
        case SYS_READ: {
            int fd = read_stack(&esp, sizeof(fd));
            void *buffer = (void *) read_stack(&esp, sizeof(buffer));
            unsigned size = read_stack(&esp, sizeof(size));
            f->eax = sys_read(fd, buffer, size);
            break;
        }
        case SYS_WRITE: {
            int fd = read_stack(&esp, sizeof(fd));
            const void *buffer = (const void *) read_stack(&esp, sizeof(buffer));
            unsigned size = read_stack(&esp, sizeof(size));
            f->eax = sys_write(fd, buffer, size);
            break;
        }
        case SYS_SEEK: {
            int fd = read_stack(&esp, sizeof(fd));
            unsigned pos = read_stack(&esp, sizeof(pos));
            sys_seek(fd, pos);
            break;
        }
        case SYS_TELL: {
            int fd = read_stack(&esp, sizeof(fd));
            f->eax = sys_tell(fd);
            break;
        }
        case SYS_CLOSE: {
            int fd = read_stack(&esp, sizeof(fd));
            sys_close(fd);
            break;
        }
#ifdef VM
        case SYS_MMAP:{
            int fd = read_stack(&esp, sizeof(fd));
            void *addr = (void *) read_stack(&esp, sizeof(addr));
            mmapid_t ret = sys_mmap (fd, addr);
            f->eax = ret;
            break;
        }
        case SYS_MUNMAP:{
            mmapid_t mid = read_stack(&esp, sizeof(mid));
            sys_munmap(mid);
            break;
        }
#endif
        default: {
            printf("[DEBUG] system call %d is not defined.\n", id);
            break;
        }
    }
}

void sys_halt() {
    shutdown_power_off();
}

void sys_exit(int exitcode) {
    struct thread *cur = thread_current();
    printf("%s: exit(%d)\n", cur->name, exitcode);
    if (cur->pcb != NULL)
        cur->pcb->exitcode = exitcode;
    thread_exit();
}

pid_t sys_exec(const char *cmdline) {
    check_string(cmdline);
    lock_acquire(&filesys_lock);
    pid_t pid = process_execute(cmdline);
    lock_release(&filesys_lock);
    return pid;
}

int sys_wait(pid_t pid) {
    return process_wait(pid);
}

bool sys_create(const char *name, unsigned size) {
    check_string(name);
    lock_acquire(&filesys_lock);
    bool ret_value = filesys_create(name, size);
    lock_release(&filesys_lock);
    return ret_value;
}

bool sys_remove(const char *name) {
    check_string(name);
    lock_acquire(&filesys_lock);
    bool ret_value = filesys_remove(name);
    lock_release(&filesys_lock);
    return ret_value;
}

int sys_open(const char *name) {
    check_string(name);
    struct file *file_opened;
    struct file_descriptor *fd = palloc_get_page(0);
    if (fd == NULL)
        return -1;
    lock_acquire(&filesys_lock);
    file_opened = filesys_open(name);
    if (file_opened == NULL) {
        palloc_free_page(fd);
        lock_release(&filesys_lock);
        return -1;
    }

    fd->file = file_opened;
    struct list *fd_list = &thread_current()->fd_list;
    if (list_empty(fd_list)) fd->id = 3;
    else fd->id = list_entry(list_back(fd_list), struct file_descriptor, elem)->id + 1;
    list_push_back(fd_list, &fd->elem);
    lock_release(&filesys_lock);
    return fd->id;
}

int sys_filesize(int fd_) {
    struct file_descriptor *fd;
    lock_acquire(&filesys_lock);
    fd = get_file_descriptor(thread_current(), fd_);
    if (fd == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int len = file_length(fd->file);
    lock_release(&filesys_lock);
    return len;
}

int sys_read(int fd_, void *buffer, unsigned size) {
    check_user(buffer);
    check_user(buffer + size - 1);
    lock_acquire(&filesys_lock);
    int ret = -1;
    if (fd_ == STDIN_FILENO) {
        unsigned i;
        for (i = 0; i < size; ++i)
            put_user(buffer + i, input_getc());
        ret = size;
    } else {
        struct file_descriptor *fd = get_file_descriptor(thread_current(), fd_);
        if (fd != NULL && fd->file != NULL) {
#ifdef VM
            preload_and_pin_pages(buffer, size);
#endif
            ret = file_read(fd->file, buffer, size);
#ifdef VM
            unpin_preloaded_pages(buffer, size);
#endif
        }
    }
    lock_release(&filesys_lock);
    return ret;
}

int sys_write(int fd_, const void *buffer, unsigned size) {
    check_user(buffer);
    check_user(buffer + size - 1);
    lock_acquire(&filesys_lock);
    int ret = -1;
    if (fd_ == STDOUT_FILENO) {
        putbuf(buffer, size);
        ret = size;
    } else {
        struct file_descriptor *fd = get_file_descriptor(thread_current(), fd_);
        if (fd != NULL && fd->file != NULL) {
#ifdef VM
            preload_and_pin_pages(buffer, size);
#endif
            ret = file_write(fd->file, buffer, size);
#ifdef VM
            unpin_preloaded_pages(buffer, size);
#endif
        }
    }
    lock_release(&filesys_lock);
    return ret;
}


#ifdef VM
mmapid_t sys_mmap(int fd, void *upage) {
  if (upage == NULL || pg_ofs(upage) != 0) return -1;
  if (fd <= 1) return -1; // 0 and 1 are unmappable
  struct thread *curr = thread_current();

  lock_acquire (&filesys_lock);

  /* open file */
  struct file *f = NULL;
  struct file_descriptor* file_d = get_file_descriptor(thread_current(), fd);
  if(file_d && file_d->file) {
    // reopen file so that it doesn't interfere with process itself
    // it will be store in the mmap_desc struct (later closed on munmap)
    f = file_reopen (file_d->file);
  }
  if(f == NULL) goto MMAP_FAIL;

  size_t file_size = file_length(f);
  if(file_size == 0) goto MMAP_FAIL;

  /* mapping memory*/
  size_t offset;
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;
    if (vm_supt_has_entry(curr->supt, addr)) goto MMAP_FAIL;
  }

  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;

    size_t read_bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
    size_t zero_bytes = PGSIZE - read_bytes;

    vm_supt_install_filesys(curr->supt, addr,
        f, offset, read_bytes, zero_bytes, /*writable*/true);
  }

  /* assign mmapid */
  mmapid_t mid;
  if (! list_empty(&curr->mmap_list)) {
    mid = list_entry(list_back(&curr->mmap_list), struct mmap_desc, elem)->id + 1;
  }
  else mid = 1;

  struct mmap_desc *mmap_d = (struct mmap_desc*) malloc(sizeof(struct mmap_desc));
  mmap_d->id = mid;
  mmap_d->file = f;
  mmap_d->addr = upage;
  mmap_d->size = file_size;
  list_push_back (&curr->mmap_list, &mmap_d->elem);

  lock_release (&filesys_lock);
  return mid;


MMAP_FAIL:
  // finally: release and return
  lock_release (&filesys_lock);
  return -1;
}

bool sys_munmap(mmapid_t mid){
  struct thread *curr = thread_current();
  struct mmap_desc *mmap_d = find_mmap_desc(curr, mid);

  if(mmap_d == NULL) { // not found such mid
    return false; // or fail_invalid_access() ?
  }

  lock_acquire (&filesys_lock);
  {
    // Iterate through each page
    size_t offset, file_size = mmap_d->size;
    for(offset = 0; offset < file_size; offset += PGSIZE) {
      void *addr = mmap_d->addr + offset;
      size_t bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
      vm_supt_mm_unmap (curr->supt, curr->pagedir, addr, mmap_d->file, offset, bytes);
    }

    // Free resources, and remove from the list
    list_remove(& mmap_d->elem);
    file_close(mmap_d->file);
    free(mmap_d);
  }
  lock_release (&filesys_lock);

  return true;
}

static struct mmap_desc* find_mmap_desc(struct thread *t, mmapid_t mid){
  ASSERT (t != NULL);

  struct list_elem *e;

  if (! list_empty(&t->mmap_list)) {
    for(e = list_begin(&t->mmap_list);
        e != list_end(&t->mmap_list); e = list_next(e)){
      struct mmap_desc *desc = list_entry(e, struct mmap_desc, elem);
      if(desc->id == mid) {
        return desc;
      }
    }
  }
  return NULL;
}


void preload_and_pin_pages(const void *buffer, size_t size){
  struct supplemental_page_table *supt = thread_current()->supt;
  uint32_t *pagedir = thread_current()->pagedir;
  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE){
    vm_load_page (supt, pagedir, upage);
    vm_pin_page (supt, upage);
  }
}

void unpin_preloaded_pages(const void *buffer, size_t size){
  struct supplemental_page_table *supt = thread_current()->supt;
  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    vm_unpin_page (supt, upage);
  }
}

#endif


void sys_seek(int fd_, unsigned position) {
    lock_acquire(&filesys_lock);
    struct file_descriptor *fd = get_file_descriptor(thread_current(), fd_);
    if (fd != NULL && fd->file != NULL)
        file_seek(fd->file, position);
    lock_release(&filesys_lock);
}

int sys_tell(int fd_) {
    lock_acquire(&filesys_lock);
    struct file_descriptor *fd = get_file_descriptor(thread_current(), fd_);
    int ret = -1;
    if (fd != NULL && fd->file != NULL)
        ret = file_tell(fd->file);
    lock_release(&filesys_lock);
    return ret;
}

void sys_close(int fd_) {
    lock_acquire(&filesys_lock);
    struct file_descriptor *fd = get_file_descriptor(thread_current(), fd_);
    if (fd != NULL && fd->file != NULL) {
        file_close(fd->file);
        list_remove(&fd->elem);
        palloc_free_page(fd);
    }
    lock_release(&filesys_lock);
}
