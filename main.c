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

#include "handle_packet.h"
#include "flow.h"

#define DEV_NAME_LEN 10

struct pcap_arg_t {
	char dev[DEV_NAME_LEN];
};

struct flow* insert_ptr = NULL;
struct flow* collect_ptr = NULL;

pthread_mutex_t collect_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char* argv[]) {
	pthread_t pcap_id, inserter_id;
	int ret;
	struct pcap_arg_t pcap_arg;

	if (argc >= 2) {
		strcpy(pcap_arg.dev, argv[1]);
	} else {
		fprintf(stderr, "Not enough arguments!\n");
	}


	ret = pthread_create(&pcap_id, NULL, &pcap_thread, &pcap_arg);

	if (ret != 0) {
		fprintf(stderr, "Failed to create pcap_thread\n");
	}

	ret = pthread_create(&inserter_id, NULL, &inserter_thread, NULL);

	if (ret != 0) {
		fprintf(stderr, "Failed to create inserter\n");
	}

	pthread_join(pcap_id, NULL);
	pthread_join(inserter_id, NULL);

	return EXIT_SUCCESS;
}
