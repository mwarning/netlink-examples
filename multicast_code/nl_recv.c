#include <sys/socket.h>
#include <linux/netlink.h>

#define MAX_PAYLOAD 1024  /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;

void main() {
  sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);

  memset(&src_addr, 0, sizeof(local_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();  /* self pid */
  /* interested in group 1<<0 */
  src_addr.nl_groups = 1;
  bind(sock_fd, (struct sockaddr*)&src_addr,
      sizeof(src_addr));

  memset(&dest_addr, 0, sizeof(dest_addr));

  nlh = (struct nlmsghdr *)malloc(
                          NLMSG_SPACE(MAX_PAYLOAD));
  memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

  iov.iov_base = (void *)nlh;
  iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
  msg.msg_name = (void *)&dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  printf("Waiting for message from kernel\n");

  /* Read message from kernel */
  recvmsg(fd, &msg, 0);
  printf("Received message payload: %s\n",
        NLMSG_DATA(nlh));
  close(sock_fd);
}
