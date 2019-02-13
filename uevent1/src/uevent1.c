/**
 * @file: uevent1.c
 * @author: Aleksander Mozetic
 * @date: 10 February 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: A userspace application for monitoring kernelspace uevents.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>    /* getpid */

#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/filter.h>

#include <linux/cn_proc.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

int sock;
int ret;

void install_filter(int sock)
{
	// return amount of bytes of the packet
	struct sock_filter filter[] = {
			/* 1. return all if type != NLMSG_DONE */
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
					__builtin_offsetof(struct nlmsghdr, nlmsg_type)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(NLMSG_DONE), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),

			/* 2. return all if cn_msg::id::idx != CN_IDX_PROC */
			// load 32bit id from absolute address given in argument
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					// skip nlmsghdr
					NLMSG_LENGTH(0)
					// add offset to: cn_msg::id::idx
					+ __builtin_offsetof(struct cn_msg, id)
					+ __builtin_offsetof(struct cb_id, idx)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(CN_IDX_PROC), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),

			/* 3. return all if cn_msg::id::val != CN_VAL_PROC */
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					NLMSG_LENGTH(0)
					+ __builtin_offsetof(struct cn_msg, id)
					+ __builtin_offsetof(struct cb_id, val)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(CN_VAL_PROC), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),

			/* 4. if proc_event type is not PROC_EVENT_EXEC, throw away packet? */
        	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        			NLMSG_LENGTH(0)
					+ __builtin_offsetof(struct cn_msg, data)
					+ __builtin_offsetof(struct proc_event, what)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(PROC_EVENT_EXEC), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0x0),    /* message is dropped */

			/* 5. check message comes from the kernel */
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
					__builtin_offsetof(struct nlmsghdr, nlmsg_pid)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0x0),    /* message is dropped */
	};

	struct sock_fprog fprog;
	memset(&fprog, 0, sizeof(fprog));
	fprog.filter = filter;
	fprog.len = sizeof(filter) / sizeof(*filter);
	setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
}

static int subscription_message(int pidfd)
{
	char buffer[32768];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	enum proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
	struct cn_msg cn_msg = {
		.id = {
			.idx = CN_IDX_PROC,
			.val = CN_VAL_PROC,
		},
		.seq = 0,
		.ack = 0,
		.len = sizeof(op),
	};

	struct iovec iov[3] = {
		[0] = {
			.iov_base = buffer,
			.iov_len = NLMSG_LENGTH(0),
		},
		[1] = {
			.iov_base = &cn_msg,
			.iov_len = sizeof(cn_msg),
		},
		[2] = {
			.iov_base = &op,
			.iov_len = sizeof(op),
		}
	};

	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = 0;

	return 0;
}

int main(void)
{
	sock = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
	struct sockaddr_nl src_addr;
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = -1;

	ret = bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
	if (ret) {
		printf("Failed to bind netlink socket.");
		close(sock);
		return 1;
	}

	install_filter(sock);

	/*
	 * Send subscription message. Userspace sends this enum to register
	 * with the kernel that it is listening for events on the connector.
	 */
	struct cn_msg cn_msg;
	enum proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
	cn_msg.id.idx = CN_IDX_PROC;
	cn_msg.id.val = CN_VAL_PROC;
	cn_msg.seq = 0;
	cn_msg.ack = 0;
	cn_msg.len = sizeof(op);

	char buffer[32768];
	struct nlmsghdr *nlh = (struct nlmsghdr *)&buffer;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = getpid();

	struct iovec iov[3];
	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = nlh;
	iov[0].iov_len = NLMSG_LENGTH(0);
	iov[1].iov_base = &cn_msg;
	iov[1].iov_len = sizeof(cn_msg);
	iov[2].iov_base = &op;
	iov[2].iov_len = sizeof(op);

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov[0];
	msg.msg_iovlen = 1;
	sendmsg(sock, &msg, 0);

	printf("Waiting for netlink messages from the kernel.\n");

	while (1)
	{
		int r = recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
		if (r == -1)
			continue;
		if (r < 0) {
			continue;
		}
		printf("Received message payload: %s\n", buffer);



	}
	close(	sock);
	return EXIT_SUCCESS;
}
