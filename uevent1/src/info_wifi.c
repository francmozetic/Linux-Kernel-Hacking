/**
 * @file: info_wifi.c
 * @author: Aleksander Mozetic
 * @date: 28 February 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: A userspace application for wireless interface scanning.
 *
 * Resources:
 * https://wireless.wiki.kernel.org/
 * https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>    /* isprint */
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include <sys/uio.h>
#include <net/if.h>

#include <linux/netlink.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "info_wifi.h"

#define NETLINK_EXT_ACK			11

int *time_numbers()
{
  const struct tm *tm_ptr;
  time_t now;
  int *value;

  now = time(0);
  tm_ptr = localtime(&now);

  value = (int *)malloc(6 * sizeof(int));

  value[0] = 1900 + tm_ptr->tm_year;
  value[1] = 1 + tm_ptr->tm_mon;
  value[2] = tm_ptr->tm_mday;
  value[3] = tm_ptr->tm_hour;
  value[4] = tm_ptr->tm_min;
  value[5] = tm_ptr->tm_sec;

  return value;
}

void mac_addr_n2a(char *mac_addr, unsigned char *arg) {
    // From http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c.
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

static const char *ifmodes[NL80211_IFTYPE_MAX + 1] = {
	"unspecified",
	"IBSS",
	"managed",
	"AP",
	"AP/VLAN",
	"WDS",
	"monitor",
	"mesh point",
	"P2P-client",
	"P2P-GO",
	"P2P-device",
	"outside context of a BSS",
	"NAN",
};

static char modebuf[100];

const char *iftype_name(enum nl80211_iftype iftype)
{
	if (iftype <= NL80211_IFTYPE_MAX && ifmodes[iftype])
		return ifmodes[iftype];
	sprintf(modebuf, "Unknown mode (%d)", iftype);
	return modebuf;
}

static const char *commands[NL80211_CMD_MAX + 1] = {
/*
 * sed 's%^\tNL80211_CMD_%%;t n;d;:n s%^\([^=]*\),.*%\t[NL80211_CMD_\1] = \"\L\1\",%;t;d' nl80211.h | grep -v "reserved"
 */
	[NL80211_CMD_UNSPEC] = "unspec",
	[NL80211_CMD_GET_WIPHY] = "get_wiphy",
	[NL80211_CMD_SET_WIPHY] = "set_wiphy",
	[NL80211_CMD_NEW_WIPHY] = "new_wiphy",
	[NL80211_CMD_DEL_WIPHY] = "del_wiphy",
	[NL80211_CMD_GET_INTERFACE] = "get_interface",
	[NL80211_CMD_SET_INTERFACE] = "set_interface",
	[NL80211_CMD_NEW_INTERFACE] = "new_interface",
	[NL80211_CMD_DEL_INTERFACE] = "del_interface",
	[NL80211_CMD_GET_KEY] = "get_key",
	[NL80211_CMD_SET_KEY] = "set_key",
	[NL80211_CMD_NEW_KEY] = "new_key",
	[NL80211_CMD_DEL_KEY] = "del_key",
	[NL80211_CMD_GET_BEACON] = "get_beacon",
	[NL80211_CMD_SET_BEACON] = "set_beacon",
	[NL80211_CMD_START_AP] = "start_ap",
	[NL80211_CMD_STOP_AP] = "stop_ap",
	[NL80211_CMD_GET_STATION] = "get_station",
	[NL80211_CMD_SET_STATION] = "set_station",
	[NL80211_CMD_NEW_STATION] = "new_station",
	[NL80211_CMD_DEL_STATION] = "del_station",
	[NL80211_CMD_GET_MPATH] = "get_mpath",
	[NL80211_CMD_SET_MPATH] = "set_mpath",
	[NL80211_CMD_NEW_MPATH] = "new_mpath",
	[NL80211_CMD_DEL_MPATH] = "del_mpath",
	[NL80211_CMD_SET_BSS] = "set_bss",
	[NL80211_CMD_SET_REG] = "set_reg",
	[NL80211_CMD_REQ_SET_REG] = "req_set_reg",
	[NL80211_CMD_GET_MESH_CONFIG] = "get_mesh_config",
	[NL80211_CMD_SET_MESH_CONFIG] = "set_mesh_config",
	[NL80211_CMD_GET_REG] = "get_reg",
	[NL80211_CMD_GET_SCAN] = "get_scan",
	[NL80211_CMD_TRIGGER_SCAN] = "trigger_scan",
	[NL80211_CMD_NEW_SCAN_RESULTS] = "new_scan_results",
	[NL80211_CMD_SCAN_ABORTED] = "scan_aborted",
	[NL80211_CMD_REG_CHANGE] = "reg_change",
	[NL80211_CMD_AUTHENTICATE] = "authenticate",
	[NL80211_CMD_ASSOCIATE] = "associate",
	[NL80211_CMD_DEAUTHENTICATE] = "deauthenticate",
	[NL80211_CMD_DISASSOCIATE] = "disassociate",
	[NL80211_CMD_MICHAEL_MIC_FAILURE] = "michael_mic_failure",
	[NL80211_CMD_REG_BEACON_HINT] = "reg_beacon_hint",
	[NL80211_CMD_JOIN_IBSS] = "join_ibss",
	[NL80211_CMD_LEAVE_IBSS] = "leave_ibss",
	[NL80211_CMD_TESTMODE] = "testmode",
	[NL80211_CMD_CONNECT] = "connect",
	[NL80211_CMD_ROAM] = "roam",
	[NL80211_CMD_DISCONNECT] = "disconnect",
	[NL80211_CMD_SET_WIPHY_NETNS] = "set_wiphy_netns",
	[NL80211_CMD_GET_SURVEY] = "get_survey",
	[NL80211_CMD_NEW_SURVEY_RESULTS] = "new_survey_results",
	[NL80211_CMD_SET_PMKSA] = "set_pmksa",
	[NL80211_CMD_DEL_PMKSA] = "del_pmksa",
	[NL80211_CMD_FLUSH_PMKSA] = "flush_pmksa",
	[NL80211_CMD_REMAIN_ON_CHANNEL] = "remain_on_channel",
	[NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL] = "cancel_remain_on_channel",
	[NL80211_CMD_SET_TX_BITRATE_MASK] = "set_tx_bitrate_mask",
	[NL80211_CMD_REGISTER_FRAME] = "register_frame",
	[NL80211_CMD_FRAME] = "frame",
	[NL80211_CMD_FRAME_TX_STATUS] = "frame_tx_status",
	[NL80211_CMD_SET_POWER_SAVE] = "set_power_save",
	[NL80211_CMD_GET_POWER_SAVE] = "get_power_save",
	[NL80211_CMD_SET_CQM] = "set_cqm",
	[NL80211_CMD_NOTIFY_CQM] = "notify_cqm",
	[NL80211_CMD_SET_CHANNEL] = "set_channel",
	[NL80211_CMD_SET_WDS_PEER] = "set_wds_peer",
	[NL80211_CMD_FRAME_WAIT_CANCEL] = "frame_wait_cancel",
	[NL80211_CMD_JOIN_MESH] = "join_mesh",
	[NL80211_CMD_LEAVE_MESH] = "leave_mesh",
	[NL80211_CMD_UNPROT_DEAUTHENTICATE] = "unprot_deauthenticate",
	[NL80211_CMD_UNPROT_DISASSOCIATE] = "unprot_disassociate",
	[NL80211_CMD_NEW_PEER_CANDIDATE] = "new_peer_candidate",
	[NL80211_CMD_GET_WOWLAN] = "get_wowlan",
	[NL80211_CMD_SET_WOWLAN] = "set_wowlan",
	[NL80211_CMD_START_SCHED_SCAN] = "start_sched_scan",
	[NL80211_CMD_STOP_SCHED_SCAN] = "stop_sched_scan",
	[NL80211_CMD_SCHED_SCAN_RESULTS] = "sched_scan_results",
	[NL80211_CMD_SCHED_SCAN_STOPPED] = "sched_scan_stopped",
	[NL80211_CMD_SET_REKEY_OFFLOAD] = "set_rekey_offload",
	[NL80211_CMD_PMKSA_CANDIDATE] = "pmksa_candidate",
	[NL80211_CMD_TDLS_OPER] = "tdls_oper",
	[NL80211_CMD_TDLS_MGMT] = "tdls_mgmt",
	[NL80211_CMD_UNEXPECTED_FRAME] = "unexpected_frame",
	[NL80211_CMD_PROBE_CLIENT] = "probe_client",
	[NL80211_CMD_REGISTER_BEACONS] = "register_beacons",
	[NL80211_CMD_UNEXPECTED_4ADDR_FRAME] = "unexpected_4addr_frame",
	[NL80211_CMD_SET_NOACK_MAP] = "set_noack_map",
	[NL80211_CMD_CH_SWITCH_NOTIFY] = "ch_switch_notify",
	[NL80211_CMD_START_P2P_DEVICE] = "start_p2p_device",
	[NL80211_CMD_STOP_P2P_DEVICE] = "stop_p2p_device",
	[NL80211_CMD_CONN_FAILED] = "conn_failed",
	[NL80211_CMD_SET_MCAST_RATE] = "set_mcast_rate",
	[NL80211_CMD_SET_MAC_ACL] = "set_mac_acl",
	[NL80211_CMD_RADAR_DETECT] = "radar_detect",
	[NL80211_CMD_GET_PROTOCOL_FEATURES] = "get_protocol_features",
	[NL80211_CMD_UPDATE_FT_IES] = "update_ft_ies",
	[NL80211_CMD_FT_EVENT] = "ft_event",
	[NL80211_CMD_CRIT_PROTOCOL_START] = "crit_protocol_start",
	[NL80211_CMD_CRIT_PROTOCOL_STOP] = "crit_protocol_stop",
	[NL80211_CMD_GET_COALESCE] = "get_coalesce",
	[NL80211_CMD_SET_COALESCE] = "set_coalesce",
	[NL80211_CMD_CHANNEL_SWITCH] = "channel_switch",
	[NL80211_CMD_VENDOR] = "vendor",
	[NL80211_CMD_SET_QOS_MAP] = "set_qos_map",
	[NL80211_CMD_ADD_TX_TS] = "add_tx_ts",
	[NL80211_CMD_DEL_TX_TS] = "del_tx_ts",
	[NL80211_CMD_GET_MPP] = "get_mpp",
	[NL80211_CMD_JOIN_OCB] = "join_ocb",
	[NL80211_CMD_LEAVE_OCB] = "leave_ocb",
	[NL80211_CMD_CH_SWITCH_STARTED_NOTIFY] = "ch_switch_started_notify",
	[NL80211_CMD_TDLS_CHANNEL_SWITCH] = "tdls_channel_switch",
	[NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH] = "tdls_cancel_channel_switch",
	[NL80211_CMD_WIPHY_REG_CHANGE] = "wiphy_reg_change",
	[NL80211_CMD_ABORT_SCAN] = "abort_scan",
	[NL80211_CMD_START_NAN] = "start_nan",
	[NL80211_CMD_STOP_NAN] = "stop_nan",
	[NL80211_CMD_ADD_NAN_FUNCTION] = "add_nan_function",
	[NL80211_CMD_DEL_NAN_FUNCTION] = "del_nan_function",
	[NL80211_CMD_CHANGE_NAN_CONFIG] = "change_nan_config",
	[NL80211_CMD_NAN_MATCH] = "nan_match",
	[NL80211_CMD_SET_MULTICAST_TO_UNICAST] = "set_multicast_to_unicast",
	[NL80211_CMD_UPDATE_CONNECT_PARAMS] = "update_connect_params",
};

static char cmdbuf[100];

const char *command_name(enum nl80211_commands cmd)
{
	if (cmd <= NL80211_CMD_MAX && commands[cmd])
		return commands[cmd];
	sprintf(cmdbuf, "Unknown command (%d)", cmd);
	return cmdbuf;
}

int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
	if (chan <= 0)
		return 0; /* not supported */
	switch (band) {
	case NL80211_BAND_2GHZ:
		if (chan == 14)
			return 2484;
		else if (chan < 14)
			return 2407 + chan * 5;
		break;
	case NL80211_BAND_5GHZ:
		if (chan >= 182 && chan <= 196)
			return 4000 + chan * 5;
		else
			return 5000 + chan * 5;
		break;
	case NL80211_BAND_60GHZ:
		if (chan < 5)
			return 56160 + chan * 2160;
		break;
	default:
		;
	}
	return 0; /* not supported */
}

int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}
//________________________________________________________________________________________________________________

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

struct print_event_args {
	struct timeval ts; /* internal */
	bool have_ts; /* must be set false */
	bool frame, time, reltime;
};

struct wait_event {
	int n_cmds, n_prints;
	const __u32 *cmds;
	const __u32 *prints;
	__u32 cmd;
	struct print_event_args *pargs;
};

static int nl80211_print(struct nl_msg* msg, void* arg) {
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	char macbuf[6*3];
	__u16 status;

	printf("event command: %d\n", gnlh->cmd);

	switch(gnlh->cmd) {
	case NL80211_CMD_NEW_STATION:
		mac_addr_n2a(macbuf, nla_data(tb[NL80211_ATTR_MAC]));
		printf("new station %s\n", macbuf);
		break;
	case NL80211_CMD_DEL_STATION:
		mac_addr_n2a(macbuf, nla_data(tb[NL80211_ATTR_MAC]));
		printf("del station %s\n", macbuf);
		break;
	case NL80211_CMD_JOIN_IBSS:
		mac_addr_n2a(macbuf, nla_data(tb[NL80211_ATTR_MAC]));
		printf("IBSS %s joined\n", macbuf);
		break;
	case NL80211_CMD_AUTHENTICATE:
		printf("auth");
		if (tb[NL80211_ATTR_FRAME])
			printf(": print frame");
		else if (tb[NL80211_ATTR_TIMED_OUT])
			printf(": timed out");
		else
			printf(": unknown event");
		printf("\n");
		break;
	case NL80211_CMD_ASSOCIATE:
		printf("assoc");
		if (tb[NL80211_ATTR_FRAME])
			printf(": print frame");
		else if (tb[NL80211_ATTR_TIMED_OUT])
			printf(": timed out");
		else
			printf(": unknown event");
		printf("\n");
		break;
	case NL80211_CMD_DEAUTHENTICATE:
		printf("deauth");
		printf(": print frame");
		printf("\n");
		break;
	case NL80211_CMD_DISASSOCIATE:
		printf("disassoc");
		printf(": print frame");
		printf("\n");
		break;
	case NL80211_CMD_CONNECT:
		status = 0;
		if (tb[NL80211_ATTR_TIMED_OUT])
			printf("timed out");
		else if (!tb[NL80211_ATTR_STATUS_CODE])
			printf("unknown connect status");
		else if (nla_get_u16(tb[NL80211_ATTR_STATUS_CODE]) == 0)
			printf("connected");
		else {
			status = nla_get_u16(tb[NL80211_ATTR_STATUS_CODE]);
			printf("failed to connect");
		}
		if (tb[NL80211_ATTR_MAC]) {
			mac_addr_n2a(macbuf, nla_data(tb[NL80211_ATTR_MAC]));
			printf(" to %s", macbuf);
		}
		if (status)
			printf(", status: %d: %s", status, get_status_str(status));
		printf("\n");
		break;
	case NL80211_CMD_ROAM:
		printf("roamed");
		if (tb[NL80211_ATTR_MAC]) {
			mac_addr_n2a(macbuf, nla_data(tb[NL80211_ATTR_MAC]));
			printf(" to %s", macbuf);
		}
		printf("\n");
		break;
	case NL80211_CMD_DISCONNECT:
		printf("disconnected");
		if (tb[NL80211_ATTR_DISCONNECTED_BY_AP])
			printf(" (by AP)");
		else
			printf(" (local request)");
		if (tb[NL80211_ATTR_REASON_CODE])
			printf(" reason: %d: %s", nla_get_u16(tb[NL80211_ATTR_REASON_CODE]),
				get_reason_str(nla_get_u16(tb[NL80211_ATTR_REASON_CODE])));
		printf("\n");
		break;

    default:
    	printf("default multicast event: %d\n", gnlh->cmd);
        return NL_SKIP;
    }

	return 0;
}

static int nl80211_wait(struct nl_msg *msg, void *arg)
{
	struct wait_event *wait = arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int i;

	if (wait->pargs) {
		for (i = 0; i < wait->n_prints; i++) {
			if (gnlh->cmd == wait->prints[i])
				nl80211_print(msg, wait->pargs);
		}
	}

	for (i = 0; i < wait->n_cmds; i++) {
		if (gnlh->cmd == wait->cmds[i])
			wait->cmd = gnlh->cmd;
	}

	return NL_SKIP;
}

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	/* The buffer size used when reading from the netlink socket and thus limiting the
	 * maximum size of a netlink message that can be read defaults to the size of a memory page.
	 */
	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	err = 1;
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK, NETLINK_EXT_ACK, &err, sizeof(err));

	/* This method resolves the generic netlink family name ("nl80211") to the
	 * corresponding numeric family identifier. The userspace application must
	 * send its subsequent messages to the kernel, specifying this id.
	 */
	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	nl_socket_free(state->nl_sock);
}

static int nl80211_listen_events(struct nl80211_state *state, struct print_event_args *args)
{
	int mcid, ret;

	/* Configuration multicast group
	 * Joins the specified groups using the modern socket option which is
	 * available since kernel version 2.6.14. It allows joining an almost arbitary
	 * number of groups without limitation.
	 */
	mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "config");
	if (mcid >= 0) {
		ret = nl_socket_add_membership(state->nl_sock, mcid);
		if (ret)
			return ret;
	}

	/* Scan multicast group */
	mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "scan");
	if (mcid >= 0) {
		ret = nl_socket_add_membership(state->nl_sock, mcid);
		if (ret)
			return ret;
	}

	/* Regulatory multicast group */
	mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "regulatory");
	if (mcid >= 0) {
		ret = nl_socket_add_membership(state->nl_sock, mcid);
		if (ret)
			return ret;
	}

	/* MLME multicast group */
	mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "mlme");
	if (mcid >= 0) {
		ret = nl_socket_add_membership(state->nl_sock, mcid);
		if (ret)
			return ret;
	}

	const __u32 *waits = NULL;
	const int n_waits = 0;
	const __u32 *prints = NULL;
	const int n_prints = 0;

	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct wait_event wait_ev;

	if (n_waits && waits) {
			wait_ev.cmds = waits;
			wait_ev.n_cmds = n_waits;
			wait_ev.prints = prints;
			wait_ev.n_prints = n_prints;
			//register_handler(nl80211_wait, &wait_ev);
		}
	else {
		//register_handler(nl80211_print, args);
	}

	wait_ev.cmd = 0;

	while (!wait_ev.cmd)
		nl_recvmsgs(state->nl_sock, cb);

	nl_cb_put(cb);

	return wait_ev.cmd;
}
//________________________________________________________________________________________________________________

int main(void)
{
	// Use this wireless interface for scanning.
	int if_index = if_nametoindex("wlp1s0");
	// Open socket to kernel.
	// Allocate new netlink socket in memory.
	struct nl_sock *socket = nl_socket_alloc();
	if (!socket) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	// Create file descriptor and bind socket.
	if (genl_connect(socket)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		nl_socket_free(socket);
		return -ENOLINK;
	}

	nl_socket_set_buffer_size(socket, 8192, 8192);

	// Resolve Generic Netlink family name to numeric identifier (driver_id in this case).
	int driver_id = genl_ctrl_resolve(socket, "nl80211");
	if (driver_id < 0) {
		fprintf(stderr, "Failed to resolve nl80211 to numeric identifier.\n");
		nl_socket_free(socket);
		return -ENOENT;
	}

	// Issue NL80211_CMD_GET_WIPHY to the kernel and wait for it to finish.
	int err = get_wiphy_info(socket, if_index, driver_id);
    if (err != 0) {
    	printf("get_wiphy_info() failed with %d.\n", err);
    	return err;
    }

	/* Issue NL80211_CMD_GET_INTERFACE to the kernel and wait for it to finish.
	int err = get_interface_info(socket, if_index, driver_id);
    if (err != 0) {
    	printf("get_interface_info() failed with %d.\n", err);
    	return err;
    } */

	/* Issue NL80211_CMD_GET_STATION to the kernel and wait for it to finish.
	err = get_station_info(socket, if_index, driver_id);
    if (err != 0) {
    	printf("get_station_info() failed with %d.\n", err);
    	return err;
    } */

	/* Issue NL80211_CMD_TRIGGER_SCAN to the kernel and wait for it to finish.
	int err = do_scan_trigger(socket, if_index, driver_id);
    if (err != 0) {
    	printf("do_scan_trigger() failed with %d.\n", err);
    	return err;
    }

	// Issue NL80211_CMD_GET_SCAN to the kernel and wait for it to finish.
	err = get_scan_info(socket, if_index, driver_id);
    if (err != 0) {
    	printf("get_scan_info() failed with %d.\n", err);
    	return err;
    } */

    return 0;
}
