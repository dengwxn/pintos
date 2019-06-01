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
        if (fd != NULL && fd->file != NULL)
            ret = file_read(fd->file, buffer, size);
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
        if (fd != NULL && fd->file != NULL)
            ret = file_write(fd->file, buffer, size);
    }
    lock_release(&filesys_lock);
    return ret;
}

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
