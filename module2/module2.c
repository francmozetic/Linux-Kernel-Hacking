/**
 * @file: 	apalis_connector.c
 * @author: Aleksander Mozetic
 * @date: 10 March 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: A kernel module for monitoring Linux kernelspace connector.
*/

#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include <linux/list.h>
#include <linux/workqueue.h>

#include <net/sock.h>
#include <uapi/linux/connector.h>

#include <connector.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Evgeniy Polyakov <zbr@ioremap.net>");
MODULE_DESCRIPTION("Generic userspace to kernelspace connector.");

#define NETLINK_USER 31

static struct cn_dev cdev;

static int cn_already_initialized;

static struct cn_callback_entry *
cn_queue_alloc_callback_entry(struct cn_queue_dev *dev, const char *name, struct cb_id *id,
		void (*callback)(struct cn_msg *, struct netlink_skb_parms *))
{
	struct cn_callback_entry *cbq;

	cbq = kzalloc(sizeof(*cbq), GFP_KERNEL);
	if (!cbq) {
		pr_err("Failed to create new callback queue.\n");
		return NULL;
	}

	atomic_set(&cbq->refcnt, 1);

	atomic_inc(&dev->refcnt);
	cbq->pdev = dev;

	snprintf(cbq->id.name, sizeof(cbq->id.name), "%s", name);
	memcpy(&cbq->id.id, id, sizeof(struct cb_id));
	cbq->callback = callback;
	return cbq;
}

void cn_queue_release_callback(struct cn_callback_entry *cbq)
{
	if (!atomic_dec_and_test(&cbq->refcnt))
		return;

	atomic_dec(&cbq->pdev->refcnt);
	kfree(cbq);
}

int cn_cb_equal(struct cb_id *i1, struct cb_id *i2)
{
	return ((i1->idx == i2->idx) && (i1->val == i2->val));
}

int cn_queue_add_callback(struct cn_queue_dev *dev, const char *name, struct cb_id *id,
		void (*callback)(struct cn_msg *, struct netlink_skb_parms *))
{
	struct cn_callback_entry *cbq, *__cbq;
	int found = 0;

	cbq = cn_queue_alloc_callback_entry(dev, name, id, callback);
	if (!cbq)
		return -ENOMEM;

	spin_lock_bh(&dev->queue_lock);
	list_for_each_entry(__cbq, &dev->queue_list, callback_entry) {
		if (cn_cb_equal(&__cbq->id.id, id)) {
			found = 1;
			break;
		}
	}
	if (!found)
		list_add_tail(&cbq->callback_entry, &dev->queue_list);
	spin_unlock_bh(&dev->queue_lock);

	if (found) {
		cn_queue_release_callback(cbq);
		return -EINVAL;
	}

	cbq->seq = 0;
	cbq->group = cbq->id.id.idx;

	return 0;
}

void cn_queue_del_callback(struct cn_queue_dev *dev, struct cb_id *id)
{
	struct cn_callback_entry *cbq, *n;
	int found = 0;

	spin_lock_bh(&dev->queue_lock);
	list_for_each_entry_safe(cbq, n, &dev->queue_list, callback_entry) {
		if (cn_cb_equal(&cbq->id.id, id)) {
			list_del(&cbq->callback_entry);
			found = 1;
			break;
		}
	}
	spin_unlock_bh(&dev->queue_lock);

	if (found)
		cn_queue_release_callback(cbq);
}

struct cn_queue_dev *cn_queue_alloc_dev(const char *name, struct sock *nls)
{
	struct cn_queue_dev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	snprintf(dev->name, sizeof(dev->name), "%s", name);
	atomic_set(&dev->refcnt, 0);
	INIT_LIST_HEAD(&dev->queue_list);
	spin_lock_init(&dev->queue_lock);

	dev->nls = nls;

	return dev;
}

void cn_queue_free_dev(struct cn_queue_dev *dev)
{
	struct cn_callback_entry *cbq, *n;

	spin_lock_bh(&dev->queue_lock);
	list_for_each_entry_safe(cbq, n, &dev->queue_list, callback_entry)
		list_del(&cbq->callback_entry);
	spin_unlock_bh(&dev->queue_lock);

	while (atomic_read(&dev->refcnt)) {
		pr_info("Waiting for %s to become free: refcnt=%d.\n", dev->name, atomic_read(&dev->refcnt));
		msleep(1000);
	}

	kfree(dev);
	dev = NULL;
}

/*
* The message is sent to, the portid if given, the group if given, both if both,
* or if both are zero then the group is looked up and sent there.
*/
int __cn_netlink_send_mult(struct cn_msg *msg, u16 len, u32 portid, u32 __group, gfp_t gfp_mask)
{
	struct cn_callback_entry *__cbq;
	unsigned int size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct cn_msg *data;
	struct cn_dev *dev = &cdev;
	u32 group = 0;
	int found = 0;

	if (portid || __group) {
		group = __group;
		pr_info("%s: group: %d\n", __func__, group);    // ok
	}
	else {
		spin_lock_bh(&dev->cbdev->queue_lock);
		list_for_each_entry(__cbq, &dev->cbdev->queue_list, callback_entry) {
			if (cn_cb_equal(&__cbq->id.id, &msg->id)) {
				found = 1;
				group = __cbq->group;
				break;
			}
		}
		spin_unlock_bh(&dev->cbdev->queue_lock);

		if (!found)
			return -ENODEV;
	}
	pr_info("%s: out of group selection: %d\n", __func__, group);    // ok

	if (!portid && !netlink_has_listeners(dev->nls, group))
		return -ESRCH;
	pr_info("%s: out of netlink_has_listeners()\n", __func__);    // ok

	size = sizeof(*msg) + len;

	skb = nlmsg_new(size, gfp_mask);
	if (!skb)
		return -ENOMEM;

	nlh = nlmsg_put(skb, 0, msg->seq, NLMSG_DONE, size, 0);
	if (!nlh) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	data = nlmsg_data(nlh);
	memcpy(data, msg, size);

	NETLINK_CB(skb).dst_group = group;

	if (group)
	{
		pr_info("%s: netlink_broadcast with data %s\n", __func__, (char *)msg->data);
		return netlink_broadcast(dev->nls, skb, portid, group, gfp_mask);    // ok
	}
	pr_info("%s: netlink_unicast with data %s\n", __func__, (char *)msg->data);
	return netlink_unicast(dev->nls, skb, portid, gfp_mask);
}
EXPORT_SYMBOL_GPL(__cn_netlink_send_mult);

/* same as cn_netlink_send_mult except msg->len is used for len */
int __cn_netlink_send(struct cn_msg *msg, u32 portid, u32 __group, gfp_t gfp_mask)
{
	return __cn_netlink_send_mult(msg, msg->len, portid, __group, gfp_mask);
}
EXPORT_SYMBOL_GPL(__cn_netlink_send);

int __msg_netlink_send(char *msg, u32 portid, u32 group, gfp_t gfp_mask)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;
	struct cn_dev *dev = &cdev;
	int size;

	size = strlen(msg);

	skb = nlmsg_new(size, 0);
	if (!skb)
		return -ENOMEM;

	nlh = nlmsg_put(
			skb,							// @skb: socket buffer to store message in
			0,								// @portid: netlink PORTID of requesting application
			0,								// @seq: sequence number of message
			NLMSG_DONE,		// @type: message type
			size,							// @size: length of message payload
			0								// @flags: message flags
			);

	strncpy(nlmsg_data(nlh), msg, size);

	NETLINK_CB(skb).dst_group = group;

	if (group)
	{
		pr_info("%s: netlink_broadcast with data %s\n", __func__, msg);
		return netlink_broadcast(dev->nls, skb, portid, group, gfp_mask);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(__msg_netlink_send);

/*
 * Callback add routing - adds callback with given ID and name.
 * If there is registered callback with the same ID it will not be added.
 */
int __cn_add_callback(struct cb_id *id, const char *name, void (*callback)(struct cn_msg *, struct netlink_skb_parms *))
{
	int err;
	struct cn_dev *dev = &cdev;

	if (!cn_already_initialized)
		return -EAGAIN;

	err = cn_queue_add_callback(dev->cbdev, name, id, callback);
	if (err)
		return err;

	return 0;
}
EXPORT_SYMBOL_GPL(__cn_add_callback);

/*
 * Callback remove routing - removes callback with given ID.
 * If there is no registered callback with given ID nothing happens.
 */
void __cn_del_callback(struct cb_id *id)
{
	struct cn_dev *dev = &cdev;

	cn_queue_del_callback(dev->cbdev, id);
}
EXPORT_SYMBOL_GPL(__cn_del_callback);

/*
 * Callback helper - queues work and setup destructor for given data.
 */
static int cn_call_callback(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct cn_callback_entry *i, *cbq = NULL;
	struct cn_dev *dev = &cdev;
	struct cn_msg *msg = nlmsg_data(nlmsg_hdr(skb));
	struct netlink_skb_parms *nsp = &NETLINK_CB(skb);
	int err = -ENODEV;

	/* verify msg->len is within skb */
	nlh = nlmsg_hdr(skb);
	if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct cn_msg) + msg->len)
		return -EINVAL;

	pr_info("%s: callback helper function: len = %d\n", __func__, msg->len);
	pr_info("%s: callback helper function: idx = %x, val = %x\n", __func__, msg->id.idx, msg->id.val);
	spin_lock_bh(&dev->cbdev->queue_lock);
	list_for_each_entry(i, &dev->cbdev->queue_list, callback_entry) {
		if (cn_cb_equal(&i->id.id, &msg->id)) {
			atomic_inc(&i->refcnt);
			cbq = i;
			break;
		}
	}
	spin_unlock_bh(&dev->cbdev->queue_lock);

	if (cbq != NULL) {
		cbq->callback(msg, nsp);
		kfree_skb(skb);
		cn_queue_release_callback(cbq);
		err = 0;
	}

	return err;
}

/*
 * Main netlink receiving function.
 */
static void cn_rx_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int len, err;

	if (skb->len >= NLMSG_HDRLEN) {
		nlh = nlmsg_hdr(skb);
		len = nlmsg_len(nlh);

		if (len < (int)sizeof(struct cn_msg) || skb->len < nlh->nlmsg_len || len > CONNECTOR_MAX_MSG_SIZE)
			return;

		pr_info("%s: main netlink receiving function: len = %d\n", __func__, len);
		err = cn_call_callback(skb_get(skb));
		if (err < 0)
			kfree_skb(skb);
	}
}

static struct cn_dev cdev = {
	.input   = cn_rx_skb,
};

/*
 * 2.6.14 netlink code only allows to select a group which is less or equal to
 * the maximum group number, which is used at netlink_kernel_create() time.
 * In case of connector it is CN_NETLINK_USERS + 0xf, so if you want to use
 * group number 12345, you must increment CN_NETLINK_USERS to that number.
 */
static int cn_init(void)
{
	struct cn_dev *dev = &cdev;
	struct netlink_kernel_cfg cfg = {
		.groups = CN_NETLINK_USERS + 0xf,    // the maximum group number (default: 11 + 15)
		.input 	= dev->input,
	};

	dev->nls = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);    // create the netlink socket (NETLINK_CONNECTOR returns -EIO)
	if (!dev->nls)
		return -EIO;

	dev->cbdev = cn_queue_alloc_dev("cqueue", dev->nls);
	if (!dev->cbdev) {
		netlink_kernel_release(dev->nls);
		return -EINVAL;
	}

	cn_already_initialized = 1;



	return 0;
}

static void cn_fini(void)
{
	struct cn_dev *dev = &cdev;

	cn_already_initialized = 0;

	cn_queue_free_dev(dev->cbdev);
	netlink_kernel_release(dev->nls);
}

/*************************************************************************************************/
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
	payload = (char *)nlmsg_data(nlh);
	printk(KERN_INFO "Received netlink message payload: %s\n", payload);
	pid = nlh->nlmsg_pid;							/* pid of sending process */
	printk(KERN_INFO "Pid of sending process: %d\n", pid);
	len = nlh->nlmsg_len;
	printk(KERN_INFO "Length of payload: %d\n", len);

	msg = "Hello from kernel!";
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

	strncpy(nlmsg_data(nlh), msg, size);

	NETLINK_CB(skb_out).dst_group = 0;				/* destination unicast */
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
module_init(cn_init);
module_exit(cn_fini);
