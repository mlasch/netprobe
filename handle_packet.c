/*
 * handle_packet.c
 *
 *  Created on: 05.05.2016
 *      Author: marc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pcap.h>
#include <pthread.h>
#include <curl/curl.h>

#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "handle_packet.h"
#include "flow.h"

#define NUM_NETS 8


//TODO add link local and non routeable ipv6 addresses
const char* local_nets[NUM_NETS][2] = {
		{	/* 10.0.0.0/8 */
				"::ffff:10.0.0.0",
				"::ffff:255.0.0.0"
		},
		{	/* 224.0.0.0/24 Administratively Scoped Block (RFC 5771) */
				"::ffff:224.0.0.0",
				"::ffff:255.0.0.0"
		},
		{	/* 239.0.0.0/8 Administratively Scoped Block (RFC 5771) */
				"::ffff:239.0.0.0",
				"::ffff:255.0.0.0"
		},
		{
				"2a01:0170:1089:0002::",
				"ffff:ffff:ffff:ffff::"
		},
		{	/* fe80::/10 Link-Scoped Unicast (RFC 5156) */
				"fe80::",
				"ffc0::"
		},
		{	/* ff01::/16 Pre-Defined Multicast Addresses interface-local (RFC 4291) */
				"ff01::",
				"ffff::"
		},
		{	/* ff02::/16 Pre-Defined Multicast Addresses link-local (RFC 4291) */
				"ff02::",
				"ffff::"
		},
		{	/* ff05::/16 Pre-Defined Multicast Addresses site-local(RFC 4291) */
				"ff05::",
				"ffff::"
		}
};

static bool check_local(struct in6_addr* addr) {
	struct in6_addr temp;
	bool is_local = false;

	for(int i=0;i<NUM_NETS;i++) {
		struct in6_addr network, prefix;

		inet_pton(AF_INET6, local_nets[i][0], &network);
		inet_pton(AF_INET6, local_nets[i][1], &prefix);

		/* addr logical and netmask */
		for(int j=0;j<4;j++) {
			temp.__in6_u.__u6_addr32[j] = addr->__in6_u.__u6_addr32[j] &
					prefix.__in6_u.__u6_addr32[j];
		}

		if (memcmp(&temp, &network, sizeof(struct in6_addr)) == 0) {
			is_local = true;
			break;
		}
	}

	return is_local;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *pcap_header,
	    const u_char *packet_ptr) {

	struct ether_header *eth_header = (struct ether_header*) packet_ptr;

	uint8_t* mac;
	traf_dir dir;
	uint32_t routeable_size = pcap_header->len - ETH_HLEN;
	uint16_t ethertype = ntohs(eth_header->ether_type);
	uint8_t proto;
	struct in6_addr src = {{ .__u6_addr32 = {0,0,0,0} }};
	struct in6_addr dst = {{ .__u6_addr32 = {0,0,0,0} }};
	struct in6_addr ip_addr = {{ .__u6_addr32 = {0,0,0,0} }};

	if (ethertype == ETH_P_IP) {
		/* received packet is IPv4 */

		struct iphdr *ip4_header = (struct iphdr*) (packet_ptr + ETH_HLEN);
		proto = ip4_header->protocol;

		/* ipv6 mapped v4 addresses (rfc4038) */
		src.__in6_u.__u6_addr32[2] = 0xffff0000;
		dst.__in6_u.__u6_addr32[2] = 0xffff0000;
		src.__in6_u.__u6_addr32[3] = ip4_header->saddr;
		dst.__in6_u.__u6_addr32[3] = ip4_header->daddr;

	} else if (ethertype == ETH_P_IPV6) {
		/* received packet is IPv6 */

		struct ip6_hdr* ip6_header = (struct ip6_hdr*) (packet_ptr + ETH_HLEN);
		proto = ip6_header->ip6_nxt;

		src = ip6_header->ip6_src;
		dst = ip6_header->ip6_dst;

	} else {
		//printf("Non IP packet received!\n");
		return;
	}

	bool local_src = check_local(&src);
	bool local_dst = check_local(&dst);

	if (!local_src && local_dst) {
		/* source addr is non local */
		dir = IN;
		mac = eth_header->ether_dhost;
		ip_addr = dst;

	} else if (!local_dst && local_src) {
		/* dest addr is non local */
		dir = OUT;
		mac = eth_header->ether_shost;
		ip_addr = src;

	} else {
		/* local traffic or fault */
		return;
	}

	pthread_mutex_lock(&collect_mutex);
	add_dataset_to_flow(&collect_ptr,
						dir,
						mac,
						&ip_addr,
						proto,
						routeable_size);
	pthread_mutex_unlock(&collect_mutex);
}

void* pcap_thread(void* arg) {
	char* filter;
	char* dev = (char*) ((pcap_arg_t*)arg)->dev;

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fexp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		pthread_exit((void *)NULL);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet device\n", dev);
		pthread_exit((void *)NULL);
	}

	filter = "";

	if (pcap_compile(handle, &fexp, filter, 0, net)) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		pthread_exit((void *)NULL);
	}

	if (pcap_setfilter(handle, &fexp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		pthread_exit((void *)NULL);
	}

	pcap_loop(handle, -1, handle_packet, NULL);

	pcap_freecode(&fexp);
	pcap_close(handle);

	pthread_exit((void *)NULL);
}

void* inserter_thread(void* arg) {
	char* path = (char*) ((inserter_arg_t*)arg)->path;
	char* token = (char*) ((inserter_arg_t*)arg)->token;
	char* db = (char*) ((inserter_arg_t*)arg)->db;
	CURL* curl_handle = (CURL*) ((inserter_arg_t*)arg)->curl_handle;
	char post_buff[80];
	char url[100];

	sprintf(url, "https://www.localnet.cc/guard/write/%s?db=%s", token, db);
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);

	while(1) {
		sleep(30);

		pthread_mutex_lock(&collect_mutex);
		insert_ptr = collect_ptr;
		collect_ptr = NULL;
		pthread_mutex_unlock(&collect_mutex);

		printf("---------\n");

		struct flow* iter = insert_ptr;

		while (iter) {
			char data[200];
			data[0] = '\0';
			strcat(data, path);
			flow_to_post(iter, post_buff);
			strcat(data, post_buff);

			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);
			CURLcode curl_code = curl_easy_perform(curl_handle);

			if (curl_code) {
				printf("CURL error code: %d\n", curl_code);
			}

			print_flow(iter);
			iter = iter->next_flow;
		}
		free_flows(insert_ptr);
	}

	pthread_exit((void *)NULL);
}