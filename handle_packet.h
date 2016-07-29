/*
 * handle_packet.h
 *
 *  Created on: 05.05.2016
 *      Author: marc
 */

#ifndef HANDLE_PACKET_H_
#define HANDLE_PACKET_H_

#include <pcap.h>

extern pthread_mutex_t collect_mutex;

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);
void* pcap_thread(void* arg);
void* inserter_thread(void* arg);
#endif /* HANDLE_PACKET_H_ */
