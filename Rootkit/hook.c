#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>

#define HIJACK_SIZE 12

void hijack_start ( void *target, void *new, unsigned char** o_code);
void hijack_pause ( void *target );
void hijack_resume ( void *target );
inline void restore_wp ( unsigned long cr0 );
inline unsigned long disable_wp ( void );
void hijack_stop ( void *target, unsigned char* o_code);



struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

LIST_HEAD(hooked_syms);

inline void mywrite_cr0(unsigned long cr0) {
  asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void enable_write_protection(void) {
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}

void disable_write_protection(void) {
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}


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