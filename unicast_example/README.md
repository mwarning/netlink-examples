# Unicast Example

Example adapted to newer Linux kernel versions.

Compile kernel module and user space program.

```
make
```

Load kernel module:

```
insmod ./netlink_test.ko
```

Also check kernel log `dmesg` for module debug output.

```
./nl_recv
Hello you!
```

Unload kernel module:
```
rmmod netlink_test.ko
```
