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

#define DEV_NAME_LEN 10
#define PATH_LEN 80
#define TOKEN_LEN 80

typedef struct {
	char dev[DEV_NAME_LEN];
} pcap_arg_t;

typedef struct {
	CURL* curl_handle;
	char path[PATH_LEN];
	char token[80];
	char db[80];
} inserter_arg_t;

extern pthread_mutex_t collect_mutex;

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);
void* pcap_thread(void* arg);
void* inserter_thread(void* arg);
#endif /* HANDLE_PACKET_H_ */
