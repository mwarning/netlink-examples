#define MAX_PAYLOAD 1024
struct sock *nl_sk = NULL;

void netlink_test() {
  sturct sk_buff *skb = NULL;
  struct nlmsghdr *nlh;
  int err;

  nl_sk = netlink_kernel_create(NETLINK_TEST,
                               nl_data_ready);
  skb=alloc_skb(NLMSG_SPACE(MAX_PAYLOAD),GFP_KERNEL);
  nlh = (struct nlmsghdr *)skb->data;
  nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
  nlh->nlmsg_pid = 0;  /* from kernel */
  nlh->nlmsg_flags = 0;
  strcpy(NLMSG_DATA(nlh), "Greeting from kernel!");
  /* sender is in group 1<<0 */
  NETLINK_CB(skb).groups = 1;
  NETLINK_CB(skb).pid = 0;  /* from kernel */
  NETLINK_CB(skb).dst_pid = 0;  /* multicast */
  /* to mcast group 1<<0 */
  NETLINK_CB(skb).dst_groups = 1;

  /*multicast the message to all listening processes*/
  netlink_broadcast(nl_sk, skb, 0, 1, GFP_KERNEL);
  sock_release(nl_sk->socket);
}