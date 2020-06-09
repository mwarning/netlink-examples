#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/netlink.h>

#define MAX_PAYLOAD 1024  /* maximum payload size */
#define NETLINK_TEST 17


int main(int argc, char **argv)
{
  struct sockaddr_nl src_addr;
  struct sockaddr_nl dest_addr;
  struct nlmsghdr *nlh;
  struct msghdr msg;
  struct iovec iov;
  int sock_fd;
  int rc;

  if (argc != 2) {
    printf("usage: %s <message>\n", argv[0]);
    return 1;
  }

  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
  if (sock_fd < 0) {
    printf("socket: %s\n", strerror(errno));
    return 1;
  }

  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();  /* self pid */
  src_addr.nl_groups = 0;  /* not in mcast groups */
  bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.nl_family = AF_NETLINK;
  dest_addr.nl_pid = 0;   /* For Linux Kernel */
  dest_addr.nl_groups = 0; /* unicast */

  nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));

  /* Fill the netlink message header */
  nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
  nlh->nlmsg_pid = getpid();  /* self pid */
  nlh->nlmsg_flags = 0;

  /* Fill in the netlink message payload */
  strcpy(NLMSG_DATA(nlh), argv[1]);

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (void *)nlh;
  iov.iov_len = nlh->nlmsg_len;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void *)&dest_addr;
  msg.msg_namelen = sizeof(dest_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  printf("Send to kernel: %s\n", argv[1]);

  rc = sendmsg(sock_fd, &msg, 0);
  if (rc < 0) {
    printf("sendmsg(): %s\n", strerror(errno));
    close(sock_fd);
    return 1;
  }

  /* Read message from kernel */
  memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

  rc = recvmsg(sock_fd, &msg, 0);
  if (rc < 0) {
    printf("sendmsg(): %s\n", strerror(errno));
    close(sock_fd);
    return 1;
  }

  printf("Received from kernel: %s\n", NLMSG_DATA(nlh));

  /* Close Netlink Socket */
  close(sock_fd);

  return 0;
}
