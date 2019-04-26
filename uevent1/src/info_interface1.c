/**
 * @file: info_interface1.c
 * @author: Aleksander Mozetic
 * @date: 30 April 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: Getting information about an interface.
 *
 * Resources:
 * https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git
 * https://stackoverflow.com/questions/18062268/using-nl80211-h-to-scan-access-points
 */

#include <errno.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "info_wifi.h"

static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

static char *channel_type_name(enum nl80211_channel_type channel_type)
{
	switch (channel_type) {
	case NL80211_CHAN_NO_HT:
		return "NO HT";
	case NL80211_CHAN_HT20:
		return "HT20";
	case NL80211_CHAN_HT40MINUS:
		return "HT40-";
	case NL80211_CHAN_HT40PLUS:
		return "HT40+";
	default:
		return "unknown";
	}
}

char *channel_width_name(enum nl80211_chan_width width)
{
	switch (width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		return "20 MHz (no HT)";
	case NL80211_CHAN_WIDTH_20:
		return "20 MHz";
	case NL80211_CHAN_WIDTH_40:
		return "40 MHz";
	case NL80211_CHAN_WIDTH_80:
		return "80 MHz";
	case NL80211_CHAN_WIDTH_80P80:
		return "80+80 MHz";
	case NL80211_CHAN_WIDTH_160:
		return "160 MHz";
	case NL80211_CHAN_WIDTH_5:
		return "5 MHz";
	case NL80211_CHAN_WIDTH_10:
		return "10 MHz";
	default:
		return "unknown";
	}
}

static int print_iface_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	unsigned int *wiphy = arg;
	const char *indent = "";

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (wiphy && tb_msg[NL80211_ATTR_WIPHY]) {
		unsigned int thiswiphy = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
		indent = "\t";
		if (*wiphy != thiswiphy)
			printf("phy#%d\n", thiswiphy);
		*wiphy = thiswiphy;
	}

	if (tb_msg[NL80211_ATTR_IFNAME])
		printf("%sInterface %s\n", indent, nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
	else
		printf("%sUnnamed/non-netdev interface\n", indent);
	if (tb_msg[NL80211_ATTR_IFINDEX])
		printf("%s\tifindex %d\n", indent, nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]));
	if (tb_msg[NL80211_ATTR_WDEV])
		printf("%s\twdev 0x%llx\n", indent,
		       (unsigned long long)nla_get_u64(tb_msg[NL80211_ATTR_WDEV]));
	if (tb_msg[NL80211_ATTR_MAC]) {
		char mac_addr[20];
		mac_addr_n2a(mac_addr, nla_data(tb_msg[NL80211_ATTR_MAC]));
		printf("%s\taddr %s\n", indent, mac_addr);
	}
	if (tb_msg[NL80211_ATTR_SSID]) {
		printf("%s\tssid ", indent);
		print_ssid_escaped(nla_len(tb_msg[NL80211_ATTR_SSID]), nla_data(tb_msg[NL80211_ATTR_SSID]));
		printf("\n");
	}
	if (tb_msg[NL80211_ATTR_IFTYPE])
		printf("%s\ttype %s\n", indent, iftype_name(nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE])));
	if (!wiphy && tb_msg[NL80211_ATTR_WIPHY])
		printf("%s\twiphy %d\n", indent, nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]));
	if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
		uint32_t freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);

		printf("%s\tchannel %d (%d MHz)", indent, ieee80211_frequency_to_channel(freq), freq);

		if (tb_msg[NL80211_ATTR_CHANNEL_WIDTH]) {
			printf(", width: %s",
				channel_width_name(nla_get_u32(tb_msg[NL80211_ATTR_CHANNEL_WIDTH])));
			if (tb_msg[NL80211_ATTR_CENTER_FREQ1])
				printf(", center1: %d MHz",
					nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ1]));
			if (tb_msg[NL80211_ATTR_CENTER_FREQ2])
				printf(", center2: %d MHz",
					nla_get_u32(tb_msg[NL80211_ATTR_CENTER_FREQ2]));
		} else if (tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
			enum nl80211_channel_type channel_type;

			channel_type = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]);
			printf(" %s", channel_type_name(channel_type));
		}

		printf("\n");
	}

	if (tb_msg[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) {
		uint32_t txp = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]);

		printf("%s\ttxpower %d.%.2d dBm\n", indent, txp / 100, txp % 100);
	}

	return NL_SKIP;
}

int get_interface_info(struct nl_sock *socket, int if_index, int driver_id) {
	// Gets information about an interface.
	struct nl_msg *msg;
	struct nl_cb *cb;
	int err, ret;

	register_handler(print_iface_handler, NULL);

	// Allocate the messages and callback handler.
    msg = nlmsg_alloc();
    if (!msg) {
        printf("Failed to allocate netlink message.\n");
        return -ENOMEM;
    }
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        printf("Failed to allocate netlink callback.\n");
        nlmsg_free(msg);
        return -ENOMEM;
    }

    // Setup the messages and callback handler.
    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);    // Setup which command to run
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);    // Add message attribute, which interface to use
    ret = nl_send_auto(socket, msg);    // Send the message
    printf("NL80211_CMD_GET_INTERFACE sent %d bytes to the kernel.\n", ret);



    // Cleanup
    nlmsg_free(msg);
    nl_cb_put(cb);
    return 0;
}
