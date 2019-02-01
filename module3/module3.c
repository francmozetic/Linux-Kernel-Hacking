/**
 * @file: apalis_controller.c
 * @author: Aleksander Mozetic
 * @date: 15 March 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: A kernel module for testing Linux kernelspace connector.
*/

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/timer.h>

#include <connector.h>

MODULE_LICENSE("GPL");

static struct cb_id cn_test_id = { CN_NETLINK_USERS, 0x456 };
static char cn_test_name[] = "cn_test";
static struct sock *nls;
static struct timer_list cn_test_timer;

static void cn_test_callback(struct cn_msg *msg, struct netlink_skb_parms *nsp)
{
	pr_info("%s: %lu: idx=%x, val=%x, seq=%u, ack=%u, len=%d: %s.\n",
			__func__, jiffies, msg->id.idx, msg->id.val, msg->seq, msg->ack, msg->len,
			msg->len ? (char *)msg->data : "");
}

static u32 cn_test_timer_counter;

static void cn_test_timer_func(unsigned long __data)
{
	struct cn_msg *m;
	char data[32];
	//char *msg;

	pr_debug("%s: timer fired with data %lu\n", __func__, __data);

	m = kzalloc(sizeof(*m) + sizeof(data), GFP_ATOMIC);
	if (m)
	{
		memcpy(&m->id, &cn_test_id, sizeof(m->id));
		m->seq = cn_test_timer_counter;
		m->len = sizeof(data);
		m->len = scnprintf(data, sizeof(data), "%s: c = %u", __func__, cn_test_timer_counter) + 1;
		memcpy(m + 1, data, m->len);

		//msg = "Hello from kernel ...";
		//__msg_netlink_send(msg, 0, 10, GFP_ATOMIC);

		__cn_netlink_send(m, 0, 10, GFP_ATOMIC);
		pr_info("%s: message sent\n", __func__);
		kfree(m);
	}

	cn_test_timer_counter++;
	if (cn_test_timer_counter < 5)
		mod_timer(&cn_test_timer, jiffies + msecs_to_jiffies(1000));
}

static int cn_test_init(void)
{
	int err;

	err = __cn_add_callback(&cn_test_id, cn_test_name, cn_test_callback);
	if (err)
		goto error;
	cn_test_id.val++;
	err = __cn_add_callback(&cn_test_id, cn_test_name, cn_test_callback);
	if (err) {
		__cn_del_callback(&cn_test_id);
		goto error;
	}

	setup_timer(&cn_test_timer, cn_test_timer_func, 0);
	mod_timer(&cn_test_timer, jiffies + msecs_to_jiffies(1000));

	pr_info("initialized with id={%u.%u}\n", cn_test_id.idx, cn_test_id.val);

	return 0;

error:
	if (nls && nls->sk_socket)
		sock_release(nls->sk_socket);

	return err;
}

static void cn_test_fini(void)
{
	del_timer_sync(&cn_test_timer);
	__cn_del_callback(&cn_test_id);
	cn_test_id.val--;
	__cn_del_callback(&cn_test_id);
	if (nls && nls->sk_socket)
		sock_release(nls->sk_socket);
}

/*************************************************************************************************/
#define NETLINK_USER 31

struct sock *nl_sock = NULL;

static void netlink_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	char *payload;
	int pid, len, res;

	char *msg;
	struct sk_buff *skb_out;
	int size;

	nlh = (struct nlmsghdr *)skb->data;
	payload = (char *)NLMSG_DATA(nlh);
	printk(KERN_INFO "Received netlink message payload: %s\n", payload);
	pid = nlh->nlmsg_pid;							/* pid of sending process */
	printk(KERN_INFO "Pid of sending process: %d\n", pid);
	len = nlh->nlmsg_len;
	printk(KERN_INFO "Length of payload: %d\n", len);

	msg = "Hello from kernel ...";
	size = strlen(msg);

	skb_out = nlmsg_new(size, 0);
	if (!skb_out) {
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh = nlmsg_put(
			skb_out,					// @skb: socket buffer to store message in
			0,								// @portid: netlink PORTID of requesting application
			0,								// @seq: sequence number of message
			NLMSG_DONE,		// @type: message type
			size,							// @size: length of message payload
			0								// @flags: message flags
			);

	strncpy(NLMSG_DATA(nlh), msg, size);

	/* destination unicast */
	NETLINK_CB(skb_out).dst_group = 0;
	res = nlmsg_unicast(nl_sock, skb_out, pid);
}

/**
 * @brief The loadable kernel module initialization function
 * The static keyword restricts the visibility of the function to within this C file.
 * @return returns 0 if successful
 */
static int apalis_init(void)
{
	int result = 0;
	printk(KERN_INFO "Loadable kernel module: netlink_kernel_create() ...\n");
	struct netlink_kernel_cfg cfg = {
			.input = netlink_recv_msg,
	};

	nl_sock = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sock) {
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}

	return result;
}

/**
 * @brief The loadable kernel module cleanup function
 * The static keyword restricts the visibility of the function to within this C file.
 */
static void apalis_exit(void)
{
	netlink_kernel_release(nl_sock);
	printk(KERN_INFO "Loadable kernel module: netlink_kernel_release() ...\n");
}

/**
 * @brief A module must use the module_init() and module_exit() macros from linux/init.h, which
 * identify the initialization function at insertion time and the cleanup function.
 */

/*************************************************************************************************/
module_init(cn_test_init);
module_exit(cn_test_fini);
