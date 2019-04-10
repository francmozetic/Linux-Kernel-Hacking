/**
 * @file: info_station1.c
 * @author: Aleksander Mozetic
 * @date: 28 February 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: A userspace application for wireless interface scanning.
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

void mac_addr_n2a(char *mac_addr, const unsigned char *arg)
{
	int i, l;

	l = 0;
	for (i = 0; i < 6; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}

static int print_sta_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	char mac_addr[20], state_name[10], dev[20];
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

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

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



	printf("\n");
	return NL_SKIP;
}
