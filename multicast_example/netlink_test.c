#if 0
#define MAX_PAYLOAD 1024
struct sock *nl_sk = NULL;

void netlink_test() {
  sturct sk_buff *skb = NULL;
  struct nlmsghdr *nlh;
  int err;

  nl_sk = netlink_kernel_create(NETLINK_TEST, nl_data_ready);
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
#endif


#include <net/sock.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_TEST 17


struct sock *nl_sock = NULL;

static void netlink_test_recv_msg(struct sk_buff *skb)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int msg_size;
    char *msg;
    int pid;
    int res;

    nlh = (struct nlmsghdr *)skb->data;
    msg = (char *)nlmsg_data(nlh);
    msg_size = strlen(msg);

    printk(KERN_INFO "netlink_test: Received %s\n", msg);
    pid = nlh->nlmsg_pid; /* pid of sending process */

    // create reply
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
      printk(KERN_ERR "netlink_test: Failed to allocate new skb\n");
      return;
    }

    // put received message into reply
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 1; /* in multicast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = netlink_broadcast(nl_sock, skb_out, 0, 1, GFP_KERNEL);
    if (res < 0)
      printk(KERN_INFO "netlink_test: Error while sending skb to user\n");
}

static int __init netlink_test_init(void)
{
  printk(KERN_INFO "netlink_test: Init module\n");

  struct netlink_kernel_cfg cfg = {
    .input = netlink_test_recv_msg,
  };

  nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
  if (!nl_sock) {
    printk(KERN_ALERT "netlink_test: Error creating socket.\n");
    return -10;
  }

  return 0;
}

static void __exit netlink_test_exit(void)
{
  printk(KERN_INFO "netlink_test: Exit module\n");

  netlink_kernel_release(nl_sock);
}

module_init(netlink_test_init);
module_exit(netlink_test_exit);

MODULE_LICENSE("GPL");
