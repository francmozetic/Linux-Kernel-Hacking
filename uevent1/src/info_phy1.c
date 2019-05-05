/**
 * @file: info_phy1.c
 * @author: Aleksander Mozetic
 * @date: 30 April 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: Getting scan information for all SSIDs detected.
 *
 * Resources:
 * https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git
 * https://stackoverflow.com/questions/18062268/using-nl80211-h-to-scan-access-points
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include <net/if.h>

#include <linux/netlink.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "info_wifi.h"

static int print_phy_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IR] = { .type = NLA_FLAG },
		[__NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
	};

	struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
	static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
		[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
	};

	struct nlattr *nl_band;
	struct nlattr *nl_freq;
	struct nlattr *nl_rate;
	struct nlattr *nl_mode;
	struct nlattr *nl_cmd;
	struct nlattr *nl_if, *nl_ftype;
	int rem_band, rem_freq, rem_rate, rem_mode, rem_cmd, rem_ftype, rem_if;
	int open;
	/*
	 * static variables only work here, other applications need to use the
	 * callback pointer and store them there so they can be multithreaded
	 * and/or have multiple netlink sockets, etc.
	 */
	static int64_t phy_id = -1;
	static int last_band = -1;
	static bool band_had_freq = false;
	bool print_name = true;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY]) {
		if (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]) == phy_id)
			print_name = false;
		else
			last_band = -1;
		phy_id = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
	}
	if (print_name && tb_msg[NL80211_ATTR_WIPHY_NAME])
		printf("Wiphy %s\n", nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));

	/* needed for split dump */
	if (tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
		nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
			if (last_band != nl_band->nla_type) {
				printf("\tBand %d:\n", nl_band->nla_type + 1);
				band_had_freq = false;
			}
			last_band = nl_band->nla_type;

			nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band),
				  nla_len(nl_band), NULL);

			if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
				__u16 cap = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
				print_ht_capability(cap);
			}
			if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]) {
				__u8 exponent = nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]);
				print_ampdu_length(exponent);
			}
			if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]) {
				__u8 spacing = nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]);
				print_ampdu_spacing(spacing);
			}
			if (tb_band[NL80211_BAND_ATTR_HT_MCS_SET] &&
			    nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) == 16)
				print_ht_mcs(nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]));
			if (tb_band[NL80211_BAND_ATTR_VHT_CAPA] &&
			    tb_band[NL80211_BAND_ATTR_VHT_MCS_SET])
				print_vht_info(nla_get_u32(tb_band[NL80211_BAND_ATTR_VHT_CAPA]),
					       nla_data(tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]));

			if (tb_band[NL80211_BAND_ATTR_FREQS]) {
				if (!band_had_freq) {
					printf("\t\tFrequencies:\n");
					band_had_freq = true;
				}
				nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
					uint32_t freq;
					nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq),
						  nla_len(nl_freq), freq_policy);
					if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
						continue;
					freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
					printf("\t\t\t* %d MHz [%d]", freq, ieee80211_frequency_to_channel(freq));

					if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] &&
					    !tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
						printf(" (%.1f dBm)", 0.01 * nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]));

					open = 0;
					if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
						print_flag("disabled", &open);
						goto next;
					}

					/* If both flags are set assume an new kernel */
					if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR] && tb_freq[__NL80211_FREQUENCY_ATTR_NO_IBSS]) {
						print_flag("no IR", &open);
					} else if (tb_freq[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN]) {
						print_flag("passive scan", &open);
					} else if (tb_freq[__NL80211_FREQUENCY_ATTR_NO_IBSS]){
						print_flag("no ibss", &open);
					}

					if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
						print_flag("radar detection", &open);
next:
					if (open)
						printf(")");
					printf("\n");
				}
			}

			if (tb_band[NL80211_BAND_ATTR_RATES]) {
			printf("\t\tBitrates (non-HT):\n");
			nla_for_each_nested(nl_rate, tb_band[NL80211_BAND_ATTR_RATES], rem_rate) {
				nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate),
					  nla_len(nl_rate), rate_policy);
				if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
					continue;
				printf("\t\t\t* %2.1f Mbps", 0.1 * nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]));
				open = 0;
				if (tb_rate[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE])
					print_flag("short preamble supported", &open);
				if (open)
					printf(")");
				printf("\n");
			}
			}
		}
	}

	if (tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]) {
		unsigned int frag;

		frag = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FRAG_THRESHOLD]);
		if (frag != (unsigned int)-1)
			printf("\tFragmentation threshold: %d\n", frag);
	}

	if (tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD]) {
		unsigned int rts;

		rts = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_RTS_THRESHOLD]);
		if (rts != (unsigned int)-1)
			printf("\tRTS threshold: %d\n", rts);
	}

	if (tb_msg[NL80211_ATTR_FEATURE_FLAGS]) {
		unsigned int features = nla_get_u32(tb_msg[NL80211_ATTR_FEATURE_FLAGS]);

		if (features & NL80211_FEATURE_SK_TX_STATUS)
			printf("\tDevice supports TX status socket option.\n");
		if (features & NL80211_FEATURE_HT_IBSS)
			printf("\tDevice supports HT-IBSS.\n");
		if (features & NL80211_FEATURE_INACTIVITY_TIMER)
			printf("\tDevice has client inactivity timer.\n");
		if (features & NL80211_FEATURE_CELL_BASE_REG_HINTS)
			printf("\tDevice accepts cell base station regulatory hints.\n");
		if (features & NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL)
			printf("\tP2P Device uses a channel (of the concurrent ones)\n");
		if (features & NL80211_FEATURE_SAE)
			printf("\tDevice supports SAE with AUTHENTICATE command\n");
		if (features & NL80211_FEATURE_LOW_PRIORITY_SCAN)
			printf("\tDevice supports low priority scan.\n");
		if (features & NL80211_FEATURE_SCAN_FLUSH)
			printf("\tDevice supports scan flush.\n");
		if (features & NL80211_FEATURE_AP_SCAN)
			printf("\tDevice supports AP scan.\n");
		if (features & NL80211_FEATURE_VIF_TXPOWER)
			printf("\tDevice supports per-vif TX power setting\n");
		if (features & NL80211_FEATURE_NEED_OBSS_SCAN)
			printf("\tUserspace should do OBSS scan and generate 20/40 coex reports\n");
		if (features & NL80211_FEATURE_P2P_GO_CTWIN)
			printf("\tP2P GO supports CT window setting\n");
		if (features & NL80211_FEATURE_P2P_GO_OPPPS)
			printf("\tP2P GO supports opportunistic powersave setting\n");
		if (features & NL80211_FEATURE_FULL_AP_CLIENT_STATE)
			printf("\tDriver supports full state transitions for AP/GO clients\n");
		if (features & NL80211_FEATURE_USERSPACE_MPM)
			printf("\tDriver supports a userspace MPM\n");
		if (features & NL80211_FEATURE_ACTIVE_MONITOR)
			printf("\tDevice supports active monitor (which will ACK incoming frames)\n");
		if (features & NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE)
			printf("\tDriver/device bandwidth changes during BSS lifetime (AP/GO mode)\n");
		if (features & NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES)
			printf("\tDevice adds DS IE to probe requests\n");
		if (features & NL80211_FEATURE_WFA_TPC_IE_IN_PROBES)
			printf("\tDevice adds WFA TPC Report IE to probe requests\n");
		if (features & NL80211_FEATURE_QUIET)
			printf("\tDevice supports quiet requests from AP\n");
		if (features & NL80211_FEATURE_TX_POWER_INSERTION)
			printf("\tDevice can update TPC Report IE\n");
		if (features & NL80211_FEATURE_ACKTO_ESTIMATION)
			printf("\tDevice supports ACK timeout estimation.\n");
		if (features & NL80211_FEATURE_STATIC_SMPS)
			printf("\tDevice supports static SMPS\n");
		if (features & NL80211_FEATURE_DYNAMIC_SMPS)
			printf("\tDevice supports dynamic SMPS\n");
		if (features & NL80211_FEATURE_SUPPORTS_WMM_ADMISSION)
			printf("\tDevice supports WMM-AC admission (TSPECs)\n");
		if (features & NL80211_FEATURE_MAC_ON_CREATE)
			printf("\tDevice supports configuring vdev MAC-addr on create.\n");
		if (features & NL80211_FEATURE_TDLS_CHANNEL_SWITCH)
			printf("\tDevice supports TDLS channel switching\n");
		if (features & NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR)
			printf("\tDevice supports randomizing MAC-addr in scans.\n");
		if (features & NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR)
			printf("\tDevice supports randomizing MAC-addr in sched scans.\n");
		if (features & NL80211_FEATURE_ND_RANDOM_MAC_ADDR)
			printf("\tDevice supports randomizing MAC-addr in net-detect scans.\n");
	}



	return NL_SKIP;
}
