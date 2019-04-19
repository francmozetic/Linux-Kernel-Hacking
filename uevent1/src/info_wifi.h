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
int get_station_info(struct nl_sock *socket, int if_index, int driver_id);

#endif /* INFO_WIFI_H_ */
