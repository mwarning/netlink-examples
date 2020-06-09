#include <net/sock.h>
#include <net/netns/generic.h>
#include <net/net_namespace.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/pid_namespace.h>

#define NETLINK_TEST 17

/*
 * a different netlink socket
 * for every network namespace
 */
struct ns_data {
  struct sock *sk;
};

/*
 * network namespace index,
 * set once on module load
 */
static unsigned int net_id;

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

    // pid of the sending (user space) process
    pid = nlh->nlmsg_pid;

    // get namespace of the sending process
    struct net *net = get_net_ns_by_pid(pid);

    printk(KERN_INFO "netlink_test: Received from pid %d, namespace %p, net_id: %d: %s\n",
           pid, net, net_id, msg);

    // get our data for this network namespace
    struct ns_data *data = net_generic(net, net_id);
    if (data == NULL || data->sk == NULL) {
      printk(KERN_ERR "netlink_test: data or socket is NULL\n");
      return;
    }

    // create reply
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
      printk(KERN_ERR "netlink_test: Failed to allocate new skb\n");
      return;
    }

    // put message into response
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    printk(KERN_INFO "netlink_test: Send %s\n", msg);

    res = nlmsg_unicast(data->sk, skb_out, pid);
    if (res < 0)
      printk(KERN_INFO "netlink_test: Error while sending skb to user\n");
}

/*
 * Called for every existing and added network namespaces
 */
static int __net_init ns_netlink_test_init(struct net *net)
{
  struct netlink_kernel_cfg cfg = {
    .input = netlink_test_recv_msg,
    .flags = NL_CFG_F_NONROOT_RECV,
  };

  // create netlink socket
  struct sock *nl_sock = netlink_kernel_create(net, NETLINK_TEST, &cfg);
  if (!nl_sock) {
    printk(KERN_ALERT "netlink_test: Error creating socket.\n");
    return -ENOMEM;
  }

  // create data item in network namespace (net) under the id (net_id) 
  struct ns_data *data = net_generic(net, net_id);
  data->sk = nl_sock;

  return 0;
}

static void __net_exit ns_netlink_test_exit(struct net *net)
{
  // called when the network namespace is removed
  struct ns_data *data = net_generic(net, net_id);

  // close socket
  netlink_kernel_release(data->sk);
}

// callback to make the module network namespace aware
static struct pernet_operations net_ops __net_initdata = {
  .init = ns_netlink_test_init,
  .exit = ns_netlink_test_exit,
  .id = &net_id,
  .size = sizeof(struct ns_data),
};

static int __init netlink_test_init(void)
{
  printk(KERN_INFO "netlink_test: Init module\n");

  register_pernet_subsys(&net_ops);

  return 0;
}

static void __exit netlink_test_exit(void)
{
  printk(KERN_INFO "netlink_test: Exit module\n");

  unregister_pernet_subsys(&net_ops);
}

module_init(netlink_test_init);
module_exit(netlink_test_exit);

MODULE_LICENSE("GPL");
