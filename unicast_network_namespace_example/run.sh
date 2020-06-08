#!/bin/sh

PATH=$PATH:/usr/sbin

rmmod netlink_test
insmod ./netlink_test.ko

./nl_recv

