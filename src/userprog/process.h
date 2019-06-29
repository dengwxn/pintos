#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <threads/synch.h>
#include "threads/thread.h"

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

struct process_control_block {
    pid_t pid;
    const char *cmdline;
    struct list_elem elem;

    bool waited;
    bool exited;
    bool orphan;
    int exitcode;

    struct semaphore sema_init;
    struct semaphore sema_wait;
};

struct file_descriptor {
    int id;
    struct list_elem elem;
    struct file *file;
};

#ifdef VM
typedef int mmapid_t;

struct mmap_desc {
  mmapid_t id;
  struct list_elem elem;
  struct file* file;

  void *addr;   // where it is mapped to? store the user virtual address
  size_t size;  // file size
};
#endif

pid_t process_execute(const char *file_name);

int process_wait(pid_t);

void process_exit(void);

void process_activate(void);

#endif /* userprog/process.h */
