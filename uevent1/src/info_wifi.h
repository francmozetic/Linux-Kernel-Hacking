/*
 * @file: info_wifi.h
 * @author: Aleksander Mozetic
 * @created on: 7 May 2019
 * @version: 1.2.2.0
 * @copyright: 2019 IndigoSoft
 * @brief: Getting information about a station.
 */

#ifndef INFO_WIFI_H_
#define INFO_WIFI_H_

void mac_addr_n2a(char *mac_addr, unsigned char *arg);
const char *iftype_name(enum nl80211_iftype iftype);
int ieee80211_channel_to_frequency(int chan, enum nl80211_band band);
int ieee80211_frequency_to_channel(int freq);

void print_ssid_escaped(const uint8_t len, const uint8_t *data);

int get_station_info(struct nl_sock *socket, int if_index, int driver_id);
int get_interface_info(struct nl_sock *socket, int if_index, int driver_id);

#endif /* INFO_WIFI_H_ */
