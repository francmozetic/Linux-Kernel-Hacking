/**
 * @file					multicast1.c
 * @author				Aleksander Mozetic
 * @date				15 March 2019
 * @version			1.2.2.0
 * @copyright		2019 IndigoSoft
 * @brief				A userspace application for testing Linux kernelspace connector.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>    /* getpid */

#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

struct sockaddr_nl src_addr;
struct nlmsghdr *nlh = NULL;
struct msghdr msg;
struct iovec iov;
char buffer[32768];
int sock;

int main(void) {
	sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 10;
	bind(sock, (struct sockaddr *)&src_addr, sizeof(src_addr));

	/*
	 * So, if you wish to use a netlink socket with a group number other than 1,
	 * the userspace application must subscribe to that group first. It can be
	 * achieved by the following code:
	 */
	int on = src_addr.nl_groups;
	setsockopt(sock, 270, 1, &on, sizeof(on));    // Where 270 is SOL_NETLINK, and 1 is a NETLINK_ADD_MEMBERSHIP socket option.

	iov.iov_base = (void *)buffer;
	iov.iov_len = sizeof(buffer);
	msg.msg_name = &src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Waiting for messages from kernel.\n");

	while (1)
	{
		recvmsg(sock, &msg, 0);
		printf("Received message payload: %s\n", (char *)NLMSG_DATA((struct nlmsghdr *)&buffer));



	}
	close(	sock);
	return EXIT_SUCCESS;
}
