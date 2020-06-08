

KERNEL_DIR=/usr/src/kernel-headers-$(shell uname -r)
obj-m += netlink_test.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement

all:
	$(CC) nl_recv.c -o nl_recv
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f nl_recv
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
