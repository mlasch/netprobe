/*
 * main.h
 *
 *  Created on: 08.08.2016
 *      Author: marc
 */

#ifndef MAIN_H_
#define MAIN_H_

#include "handle_packet.h"

#define NETPROBE_VERSION "0.1"

#define MAX_OPTION_LENGTH 255

typedef struct {
	char* dev;
} pcap_arg_t;

typedef struct {
	CURL* curl_handle;
	char* url;
	char* path;
} inserter_arg_t;


#endif /* MAIN_H_ */
