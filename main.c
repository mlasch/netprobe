/*
 * main.c
 *
 *  Created on: 04.05.2016
 *      Author: marc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>

#include "handle_packet.h"
#include "flow.h"

struct flow* insert_ptr = NULL;
struct flow* collect_ptr = NULL;

pthread_mutex_t collect_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char* argv[]) {

	pthread_t pcap_id, inserter_id;
	int ret;
	pcap_arg_t pcap_arg;
	inserter_arg_t inserter_arg;

	if (argc >= 5) {
		strcpy(pcap_arg.dev, argv[1]);
		strcpy(inserter_arg.path, argv[2]);
		strcpy(inserter_arg.token, argv[3]);
		strcpy(inserter_arg.db, argv[4]);
	} else {
		fprintf(stderr, "Not enough arguments!\n");
	}

	inserter_arg.curl_handle = curl_easy_init();


	ret = pthread_create(&pcap_id, NULL, &pcap_thread, &pcap_arg);

	if (ret != 0) {
		fprintf(stderr, "Failed to create pcap_thread\n");
	}

	ret = pthread_create(&inserter_id, NULL, &inserter_thread, &inserter_arg);

	if (ret != 0) {
		fprintf(stderr, "Failed to create inserter\n");
	}

	pthread_join(pcap_id, NULL);
	pthread_join(inserter_id, NULL);

	return EXIT_SUCCESS;
}
