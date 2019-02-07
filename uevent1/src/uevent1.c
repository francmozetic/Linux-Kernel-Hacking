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
#include <linux/cn_proc.h>
#include <linux/filter.h>

#include <arpa/inet.h>

struct sockaddr_nl src_addr;
struct msghdr msg;
struct iovec iov;
char buffer[32768];
int sock;
int ret;

void filter(int sock)
{
	// return amount of bytes of the packet
	// context: | struct nlmsghdr | struct cn_msg | struct proc_event ... |
	struct sock_filter f[] = {
			// 1. return all if type != NLMSG_DONE
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
					__builtin_offsetof(struct nlmsghdr, nlmsg_type)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(NLMSG_DONE), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),

			// 2. return all if cn_msg::id::idx != CN_IDX_PROC
			// load 32bit id from absolute address given in argument
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					// skip nlmsghdr
					NLMSG_LENGTH(0)
					// add offset to: cn_msg::id::idx
					+ __builtin_offsetof(struct cn_msg, id)
					+ __builtin_offsetof(struct cb_id, idx)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(CN_IDX_PROC), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),

			// 3. return all if cn_msg::id::val != CN_VAL_PROC
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					NLMSG_LENGTH(0) + __builtin_offsetof(struct cn_msg, id)
					+ __builtin_offsetof(struct cb_id, val)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(CN_VAL_PROC), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),

			// packet contains 1 netlink msg from proc_cn

			// 4. if proc_event type is not PROC_EVENT_EXEC, throw away packet
        	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        			NLMSG_LENGTH(0) + __builtin_offsetof(struct cn_msg, data)
					+ __builtin_offsetof(struct proc_event, what)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(PROC_EVENT_EXEC), 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
	};

	struct sock_fprog fprog;
	fprog.filter = f;
	fprog.len = sizeof f / sizeof f[0];
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof fprog) == -1)
		perror("setsockopt");
}

int main(void) {
	sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
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

	printf("Waiting for netlink messages from kernel.\n");

	while (1)
	{
		int r = recv(sock, buffer, sizeof(msg), MSG_DONTWAIT);
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
