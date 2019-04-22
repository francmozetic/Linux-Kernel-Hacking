/**
 * @file: info_station1.c
 * @author: Aleksander Mozetic
 * @date: 15 April 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: Getting information about a station.
 *
 * Resources:
 * https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git
 * https://stackoverflow.com/questions/18062268/using-nl80211-h-to-scan-access-points
 */

#include <stdio.h>
#include <errno.h>

#include <net/if.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "info_wifi.h"

#define BIT(x) (1ULL<<(x))

struct info_results {
    int done;
    int aborted;
};

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
	// Callback for errors.
    printf("error_handler() called.\n");
    int *ret = arg;
    *ret = err->error;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
    // Callback for NL_CB_FINISH.
    int *ret = arg;
    *ret = 0;
    return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
	// Callback for NL_CB_ACK.
	int *ret = arg;
    *ret = 0;
    return NL_STOP;
}

static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

int valid_handler(struct nl_msg *msg, void *arg)
{
	if (registered_handler)
		return registered_handler(msg, registered_handler_data);

	return NL_OK;
}

static void parse_bss_param(struct nlattr *bss_param_attr)
{
	struct nlattr *bss_param_info[NL80211_STA_BSS_PARAM_MAX + 1], *info;
	static struct nla_policy bss_policy[NL80211_STA_BSS_PARAM_MAX + 1] = {
		[NL80211_STA_BSS_PARAM_CTS_PROT] = { .type = NLA_FLAG },
		[NL80211_STA_BSS_PARAM_SHORT_PREAMBLE] = { .type = NLA_FLAG },
		[NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME] = { .type = NLA_FLAG },
		[NL80211_STA_BSS_PARAM_DTIM_PERIOD] = { .type = NLA_U8 },
		[NL80211_STA_BSS_PARAM_BEACON_INTERVAL] = { .type = NLA_U16 },
	};

	if (nla_parse_nested(bss_param_info, NL80211_STA_BSS_PARAM_MAX,
			     bss_param_attr, bss_policy)) {
		printf("failed to parse nested bss param attributes!");
	}

	info = bss_param_info[NL80211_STA_BSS_PARAM_DTIM_PERIOD];
	if (info)
		printf("\n\tDTIM period:\t%u", nla_get_u8(info));
	info = bss_param_info[NL80211_STA_BSS_PARAM_BEACON_INTERVAL];
	if (info)
		printf("\n\tbeacon interval:%u", nla_get_u16(info));
	info = bss_param_info[NL80211_STA_BSS_PARAM_CTS_PROT];
	if (info) {
		printf("\n\tCTS protection:");
		if (nla_get_u16(info))
			printf("\tyes");
		else
			printf("\tno");
	}
	info = bss_param_info[NL80211_STA_BSS_PARAM_SHORT_PREAMBLE];
	if (info) {
		printf("\n\tshort preamble:");
		if (nla_get_u16(info))
			printf("\tyes");
		else
			printf("\tno");
	}
	info = bss_param_info[NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME];
	if (info) {
		printf("\n\tshort slot time:");
		if (nla_get_u16(info))
			printf("yes");
		else
			printf("no");
	}
}

void parse_bitrate(struct nlattr *bitrate_attr, char *buf, int buflen)
{
	int rate = 0;
	char *pos = buf;
	struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
	static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
		[NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
		[NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
		[NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
		[NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
		[NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
	};

	if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, bitrate_attr, rate_policy)) {
		snprintf(buf, buflen, "failed to parse nested rate attributes!");
		return;
	}

	if (rinfo[NL80211_RATE_INFO_BITRATE32])
		rate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
	else if (rinfo[NL80211_RATE_INFO_BITRATE])
		rate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
	if (rate > 0)
		pos += snprintf(pos, buflen - (pos - buf), "%d.%d MBit/s", rate / 10, rate % 10);
	else
		pos += snprintf(pos, buflen - (pos - buf), "(unknown)");

	if (rinfo[NL80211_RATE_INFO_MCS])
		pos += snprintf(pos, buflen - (pos - buf),
				" MCS %d", nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]));
	if (rinfo[NL80211_RATE_INFO_VHT_MCS])
		pos += snprintf(pos, buflen - (pos - buf),
				" VHT-MCS %d", nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_MCS]));
	if (rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
		pos += snprintf(pos, buflen - (pos - buf), " 40MHz");
	if (rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
		pos += snprintf(pos, buflen - (pos - buf), " 80MHz");
	if (rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
		pos += snprintf(pos, buflen - (pos - buf), " 80P80MHz");
	if (rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
		pos += snprintf(pos, buflen - (pos - buf), " 160MHz");
	if (rinfo[NL80211_RATE_INFO_SHORT_GI])
		pos += snprintf(pos, buflen - (pos - buf), " short GI");
	if (rinfo[NL80211_RATE_INFO_VHT_NSS])
		pos += snprintf(pos, buflen - (pos - buf), " VHT-NSS %d", nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]));
}

static char *get_chain_signal(struct nlattr *attr_list)
{
	struct nlattr *attr;
	static char buf[64];
	char *cur = buf;
	int i = 0, rem;
	const char *prefix;

	if (!attr_list)
		return "";

	nla_for_each_nested(attr, attr_list, rem) {
		if (i++ > 0)
			prefix = ", ";
		else
			prefix = "[";

		cur += snprintf(cur, sizeof(buf) - (cur - buf), "%s%d", prefix,
				(int8_t) nla_get_u8(attr));
	}

	if (i)
		snprintf(cur, sizeof(buf) - (cur - buf), "] ");

	return buf;
}

static int print_sta_handler(struct nl_msg *msg, void *arg)
{
	/**
	 * enum nl80211_sta_info - station information
	 *
	 * These attribute types are used with %NL80211_ATTR_STA_INFO
	 * when getting information about a station.
	 *
	 * @__NL80211_STA_INFO_INVALID: attribute number 0 is reserved
	 * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
	 * @NL80211_STA_INFO_RX_BYTES: total received bytes (u32, from this station)
	 * @NL80211_STA_INFO_TX_BYTES: total transmitted bytes (u32, to this station)
	 * @NL80211_STA_INFO_RX_BYTES64: total received bytes (u64, from this station)
	 * @NL80211_STA_INFO_TX_BYTES64: total transmitted bytes (u64, to this station)
	 * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
	 * @NL80211_STA_INFO_TX_BITRATE: current unicast tx rate, nested attribute
	 * 	containing info as possible, see &enum nl80211_rate_info
	 * @NL80211_STA_INFO_RX_PACKETS: total received packet (u32, from this station)
	 * @NL80211_STA_INFO_TX_PACKETS: total transmitted packets (u32, to this
	 *	station)
	 * @NL80211_STA_INFO_TX_RETRIES: total retries (u32, to this station)
	 * @NL80211_STA_INFO_TX_FAILED: total failed packets (u32, to this station)
	 * @NL80211_STA_INFO_SIGNAL_AVG: signal strength average (u8, dBm)
	 * @NL80211_STA_INFO_LLID: the station's mesh LLID
	 * @NL80211_STA_INFO_PLID: the station's mesh PLID
	 * @NL80211_STA_INFO_PLINK_STATE: peer link state for the station
	 *	(see %enum nl80211_plink_state)
	 * @NL80211_STA_INFO_RX_BITRATE: last unicast data frame rx rate, nested
	 *	attribute, like NL80211_STA_INFO_TX_BITRATE.
	 * @NL80211_STA_INFO_BSS_PARAM: current station's view of BSS, nested attribute
	 *     containing info as possible, see &enum nl80211_sta_bss_param
	 * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
	 * @NL80211_STA_INFO_STA_FLAGS: Contains a struct nl80211_sta_flag_update.
	 * @NL80211_STA_INFO_BEACON_LOSS: count of times beacon loss was detected (u32)
	 * @NL80211_STA_INFO_T_OFFSET: timing offset with respect to this STA (s64)
	 * @NL80211_STA_INFO_LOCAL_PM: local mesh STA link-specific power mode
	 * @NL80211_STA_INFO_PEER_PM: peer mesh STA link-specific power mode
	 * @NL80211_STA_INFO_NONPEER_PM: neighbor mesh STA power save mode towards
	 *	non-peer STA
	 * @NL80211_STA_INFO_CHAIN_SIGNAL: per-chain signal strength of last PPDU
	 *	Contains a nested array of signal strength attributes (u8, dBm)
	 * @NL80211_STA_INFO_CHAIN_SIGNAL_AVG: per-chain signal strength average
	 *	Same format as NL80211_STA_INFO_CHAIN_SIGNAL.
	 * @NL80211_STA_EXPECTED_THROUGHPUT: expected throughput considering also the
	 *	802.11 header (u32, kbps)
	 * @__NL80211_STA_INFO_AFTER_LAST: internal
	 * @NL80211_STA_INFO_MAX: highest possible station info attribute
	 */
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	char mac_addr[20], dev[20];
	struct nl80211_sta_flag_update *sta_flags;
	static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_BYTES64] = { .type = NLA_U64 },
		[NL80211_STA_INFO_TX_BYTES64] = { .type = NLA_U64 },
		[NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
		[NL80211_STA_INFO_BEACON_RX] = { .type = NLA_U64 },
		[NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
		[NL80211_STA_INFO_T_OFFSET] = { .type = NLA_U64 },
		[NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
		[NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
		[NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
		[NL80211_STA_INFO_TX_RETRIES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
		[NL80211_STA_INFO_BEACON_LOSS] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_DROP_MISC] = { .type = NLA_U64 },
		[NL80211_STA_INFO_STA_FLAGS] = 	{ .minlen = sizeof(struct nl80211_sta_flag_update) },
		[NL80211_STA_INFO_LOCAL_PM] = { .type = NLA_U32 },
		[NL80211_STA_INFO_PEER_PM] = { .type = NLA_U32 },
		[NL80211_STA_INFO_NONPEER_PM] = { .type = NLA_U32 },
		[NL80211_STA_INFO_CHAIN_SIGNAL] = { .type = NLA_NESTED },
		[NL80211_STA_INFO_CHAIN_SIGNAL_AVG] = { .type = NLA_NESTED },
		[NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED },
		[NL80211_STA_INFO_BSS_PARAM] = { .type = NLA_NESTED },
		[NL80211_STA_INFO_RX_DURATION] = { .type = NLA_U64 },
	};

	char *chain;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy)) {
		fprintf(stderr, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	mac_addr_n2a(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
	printf("Station %s (on %s)", mac_addr, dev);

	if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
		printf("\n\tinactive time:\t%u ms",
			nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]));
	if (sinfo[NL80211_STA_INFO_RX_BYTES64])
		printf("\n\trx bytes:\t%llu",
		       (unsigned long long)nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]));
	else if (sinfo[NL80211_STA_INFO_RX_BYTES])
		printf("\n\trx bytes:\t%u",
		       nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]));
	if (sinfo[NL80211_STA_INFO_RX_PACKETS])
		printf("\n\trx packets:\t%u",
			nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]));
	if (sinfo[NL80211_STA_INFO_TX_BYTES64])
		printf("\n\ttx bytes:\t%llu",
		       (unsigned long long)nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]));
	else if (sinfo[NL80211_STA_INFO_TX_BYTES])
		printf("\n\ttx bytes:\t%u",
		       nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]));
	if (sinfo[NL80211_STA_INFO_TX_PACKETS])
		printf("\n\ttx packets:\t%u",
			nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]));
	if (sinfo[NL80211_STA_INFO_TX_RETRIES])
		printf("\n\ttx retries:\t%u",
			nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]));
	if (sinfo[NL80211_STA_INFO_TX_FAILED])
		printf("\n\ttx failed:\t%u",
			nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]));
	if (sinfo[NL80211_STA_INFO_BEACON_LOSS])
		printf("\n\tbeacon loss:\t%u",
		       nla_get_u32(sinfo[NL80211_STA_INFO_BEACON_LOSS]));
	if (sinfo[NL80211_STA_INFO_BEACON_RX])
		printf("\n\tbeacon rx:\t%llu",
		       (unsigned long long)nla_get_u64(sinfo[NL80211_STA_INFO_BEACON_RX]));
	if (sinfo[NL80211_STA_INFO_RX_DROP_MISC])
		printf("\n\trx drop misc:\t%llu",
		       (unsigned long long)nla_get_u64(sinfo[NL80211_STA_INFO_RX_DROP_MISC]));

	chain = get_chain_signal(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL_AVG]);
	if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
		printf("\n\tsignal avg:\t%d %sdBm",
				(int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]), chain);

	chain = get_chain_signal(sinfo[NL80211_STA_INFO_CHAIN_SIGNAL_AVG]);
	if (sinfo[NL80211_STA_INFO_SIGNAL_AVG])
		printf("\n\tsignal avg:\t%d %sdBm",
			(int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]), chain);

	if (sinfo[NL80211_STA_INFO_BEACON_SIGNAL_AVG])
		printf("\n\tbeacon signal avg:\t%d dBm",
		       (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_BEACON_SIGNAL_AVG]));
	if (sinfo[NL80211_STA_INFO_T_OFFSET])
		printf("\n\tToffset:\t%llu us",
		       (unsigned long long)nla_get_u64(sinfo[NL80211_STA_INFO_T_OFFSET]));

	if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
		char buf[100];

		parse_bitrate(sinfo[NL80211_STA_INFO_TX_BITRATE], buf, sizeof(buf));
		printf("\n\ttx bitrate:\t%s", buf);
	}

	if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
		char buf[100];

		parse_bitrate(sinfo[NL80211_STA_INFO_RX_BITRATE], buf, sizeof(buf));
		printf("\n\trx bitrate:\t%s", buf);
	}

	if (sinfo[NL80211_STA_INFO_STA_FLAGS]) {
		sta_flags = (struct nl80211_sta_flag_update *)nla_data(sinfo[NL80211_STA_INFO_STA_FLAGS]);

		if (sta_flags->mask & BIT(NL80211_STA_FLAG_AUTHORIZED)) {
			printf("\n\tauthorized:\t");
			if (sta_flags->set & BIT(NL80211_STA_FLAG_AUTHORIZED))
				printf("yes");
			else
				printf("no");
		}

		if (sta_flags->mask & BIT(NL80211_STA_FLAG_AUTHENTICATED)) {
			printf("\n\tauthenticated:\t");
			if (sta_flags->set & BIT(NL80211_STA_FLAG_AUTHENTICATED))
				printf("yes");
			else
				printf("no");
		}

		if (sta_flags->mask & BIT(NL80211_STA_FLAG_ASSOCIATED)) {
			printf("\n\tassociated:\t");
			if (sta_flags->set & BIT(NL80211_STA_FLAG_ASSOCIATED))
				printf("yes");
			else
				printf("no");
		}

		if (sinfo[NL80211_STA_INFO_BSS_PARAM])
			parse_bss_param(sinfo[NL80211_STA_INFO_BSS_PARAM]);
		if (sinfo[NL80211_STA_INFO_CONNECTED_TIME]) {
			printf("\n\tconnected time:\t%u seconds", nla_get_u32(sinfo[NL80211_STA_INFO_CONNECTED_TIME]));
		}



	}

	printf("\n");
	return NL_SKIP;
}

int get_station_info(struct nl_sock *socket, int if_index, int driver_id) {
	// Gets information about a station.
	struct nl_msg *msg;
	struct nl_cb *cb;
	int err, ret;

	register_handler(print_sta_handler, NULL);

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
    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);    // Setup which command to run
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);    // Add message attribute, which interface to use
    ret = nl_send_auto(socket, msg);    // Send the message
    printf("NL80211_CMD_GET_STATION sent %d bytes to the kernel.\n", ret);

    err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);    // Add the callback

    while (err > 0) ret = nl_recvmsgs(socket, cb);
    if (err < 0) {
    	printf("Error: err has a value of %d.\n", err);
    }
    if (ret < 0) {
    	printf("Error: nl_recvmsgs() returned %d (%s).\n", ret, nl_geterror(-ret));
    	return ret;
    }
    printf("Getting info is done.\n");

    // Cleanup
    nlmsg_free(msg);
    nl_cb_put(cb);
    return 0;
}

// To ne gre (print_sta_handler() is not called)
int get_station_infoo(struct nl_sock *socket, int if_index, int driver_id) {
	// Gets information about a station.

    // Allocate the messages and callback handler.
	struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        printf("Failed to allocate netlink message.\n");
        return -ENOMEM;
    }

    // Setup the messages and callback handler.
    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);    // Setup which command to run
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);    // Add message attribute, which interface to use
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, print_sta_handler, NULL);    // Add the callback
    int ret = nl_send_auto(socket, msg);    // Send the message
    printf("NL80211_CMD_GET_STATION sent %d bytes to the kernel.\n", ret);
    ret = nl_recvmsgs_default(socket);    // Retrieve the kernel's answer (print_sta_handler() prints station info to stdout)
    printf("Getting information is done.\n");
    nlmsg_free(msg);

    if (ret < 0) {
    	printf("Error: nl_recvmsgs_default() returned %d (%s).\n", ret, nl_geterror(-ret));
    	return ret;
    }

    return 0;
}
