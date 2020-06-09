# Multicast Example

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
./nl_recv "Hello you!"
Listen for message...
Received from kernel: Hello you!
Listen for message...
```

Execute `./nl_recv` in another console as well and see how the message is send to the kernel and back to all running nl_recv instances. Note: Only root or the kernel can send a message to a multicast group!

Unload kernel module:
```
rmmod netlink_test.ko
```
