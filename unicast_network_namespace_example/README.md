# Netlink Unicast Example - Network Namespace Aware

Compile kernel module and user space program.

```
make
```

Load kernel module:

```
insmod ./netlink_test.ko
```

Check kernel log `dmesg` for module debug output.

```
./nl_recv "Hello you!"
Hello you!
```

Unload kernel module:
```
rmmod netlink_test.ko
```
