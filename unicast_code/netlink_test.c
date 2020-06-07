struct sock *nl_sk = NULL;

MODULE_LICENSE("GPL");

void nl_data_ready (struct sock *sk, int len)
{
  wake_up_interruptible(sk->sleep);
}

//void netlink_test()
static int __init netlink_test_init(void) {
{
  struct sk_buff *skb = NULL;
  struct nlmsghdr *nlh = NULL;
  int err;
  u32 pid;

  nl_sk = netlink_kernel_create(NETLINK_TEST,
                                   nl_data_ready);
  /* wait for message coming down from user-space */
  skb = skb_recv_datagram(nl_sk, 0, 0, &err);

  nlh = (struct nlmsghdr *)skb->data;
  printk("%s: received netlink message payload:%s\n",
        __FUNCTION__, NLMSG_DATA(nlh));

  pid = nlh->nlmsg_pid; /*pid of sending process */
  NETLINK_CB(skb).groups = 0; /* not in mcast group */
  NETLINK_CB(skb).pid = 0;      /* from kernel */
  NETLINK_CB(skb).dst_pid = pid;
  NETLINK_CB(skb).dst_groups = 0;  /* unicast */
  netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
  sock_release(nl_sk->socket);
}

}

static void __exit netlink_test_exit(void) {
  // Nothing to do
}

module_init(netlink_test_init);
module_exit(netlink_test_exit);
