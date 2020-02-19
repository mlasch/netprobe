/*
 * handle_packet.h
 *
 *  Created on: 05.05.2016
 *      Author: marc
 */

#ifndef HANDLE_PACKET_H_
#define HANDLE_PACKET_H_

#include <curl/curl.h>
#include <pcap.h>

#include "main.h"

#ifdef DEBUG
	#define INSERT_DELAY 5
#else
	#define INSERT_DELAY 30
#endif

#define MAX_PARAM_LENGTH MAX_OPTION_LENGTH
#define MAX_PATH_LENGTH MAX_OPTION_LENGTH

bool check_local(struct in6_addr* addr);
void handle_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);

void* pcap_thread(void* arg);
void* inserter_thread(void* arg);
#endif /* HANDLE_PACKET_H_ */
