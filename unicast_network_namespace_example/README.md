# Netlink Unicast Example - Network Namespace Aware

This kernel module does maintain its own state per Linux network namespace.
The module here does not really expose any state, so read the source. :-)

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
