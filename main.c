/*
 * main.c
 *
 *  Created on: 04.05.2016
 *      Author: marc
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <pthread.h>

#include "flow.h"
#include "globals.h"
#include "handle_packet.h"
#include "main.h"

void print_usage() {
    printf("netprobe %s ( https://github.com/mlasch/netprobe )\n"
           "Usage:\n"
           "\t-i, --interface\t\tNetwork interface\n"
           "\t-u, --url\t\tURL containing server, port, database and token\n"
           "\t-p, --path\t\tPath\n"
           "\t    --nop\t\tNo actual insert (no operation)\n"
           "\t    --verbose\n"
           "\t    --version\t\tPrint program version\n",
           NETPROBE_VERSION);
}

int main(int argc, char *argv[]) {
    bool interface = 1, url = 1, path = 1;
    pcap_arg_t pcap_arg;
    inserter_arg_t inserter_arg;

    static struct option long_options[] = {/* flags */
                                           {"verbose", no_argument, &verbose_flag, 1},
                                           {"nop", no_argument, &nop_flag, 1},
                                           /* arguments */
                                           {"interface", required_argument, NULL, 'i'},
                                           {"url", required_argument, NULL, 'u'},
                                           {"path", required_argument, NULL, 'p'},
                                           {"version", required_argument, NULL, 'v'},
                                           {NULL, 0, NULL, 0}};

    for (int option_index = 0, c = 0; c != -1; c = getopt_long(argc, argv, "i:u:p:v", long_options, &option_index)) {

        switch (c) {
        case 'i':
            pcap_arg.dev = optarg;
            interface = 0;
            break;
        case 'u':
            inserter_arg.url = optarg;
            url = 0;
            break;
        case 'p':
            inserter_arg.path = optarg;
            path = 0;
            break;
        case 'v':
            printf("netprobe %s\n", NETPROBE_VERSION);
            exit(EXIT_SUCCESS);
        case 0:
            /* first loop run */
            break;
        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    }

    if (interface || url || path) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    pthread_t pcap_id, inserter_id;
    int ret;

    inserter_arg.curl_handle = curl_easy_init();

    ret = pthread_create(&pcap_id, NULL, &pcap_thread, &pcap_arg);

    if (ret != 0) {
        fprintf(stderr, "Failed to create pcap thread\n");
    }

    ret = pthread_create(&inserter_id, NULL, &inserter_thread, &inserter_arg);

    if (ret != 0) {
        fprintf(stderr, "Failed to create inserter thread\n");
    }

    printf("Started, waiting for threads to end\n");

    pthread_join(pcap_id, NULL);
    pthread_join(inserter_id, NULL);

    return EXIT_SUCCESS;
}
