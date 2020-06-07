
KERNEL_DIR=/usr/src/kernel-headers-$(shell uname -r)

all: netlink_test.c nl_recv.c 
	$(CC) nl_recv.c -o nl_recv
	$(MAKE) -C $(KERNEL_DIR) M=$(shell pwd) modules
