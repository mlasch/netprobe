/*
 * handle_packet.c
 *
 *  Created on: 05.05.2016
 *      Author: marc
 */

#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>

#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "handle_packet.h"
#include "flow.h"

void handle_packet(u_char *args, const struct pcap_pkthdr *pcap_header,
	    const u_char *packet_ptr) {

	struct ether_header *eth_header = (struct ether_header*) packet_ptr;

	uint32_t routeable_size = pcap_header->len - ETH_HLEN;
	uint16_t ethertype = ntohs(eth_header->ether_type);
	uint8_t next_header;
	struct in6_addr src = {{ .__u6_addr32 = {0,0,0,0} }};
	struct in6_addr dst = {{ .__u6_addr32 = {0,0,0,0} }};

	if (ethertype == ETH_P_IP) {
		/* received packet is IPv4 */

		struct iphdr *ip4_header = (struct iphdr*) (packet_ptr + ETH_HLEN);
		next_header = ip4_header->protocol;

		src.__in6_u.__u6_addr32[3] = ip4_header->saddr;
		dst.__in6_u.__u6_addr32[3] = ip4_header->daddr;

	} else if (ethertype == ETH_P_IPV6) {
		/* received packet is IPv6 */

		struct ip6_hdr* ip6_header = (struct ip6_hdr*) (packet_ptr + ETH_HLEN);
		next_header = ip6_header->ip6_nxt;

		src = ip6_header->ip6_src;
		dst = ip6_header->ip6_dst;

	} else {
		//printf("Non IP packet received!\n");
		return;
	}

	pthread_mutex_lock(&collect_mutex);
	add_dataset_to_flow(&collect_ptr,
						eth_header->ether_shost,
						ethertype,
						&src,
						&dst,
						next_header,
						routeable_size);
	pthread_mutex_unlock(&collect_mutex);
}

void* pcap_thread(void* arg) {
	char *dev = "wlan2", *filter;
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
		return 2;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet device\n", dev);
		return 2;
	}

	filter = "";

	if (pcap_compile(handle, &fexp, filter, 0, net)) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		return 2;
	}

	if (pcap_setfilter(handle, &fexp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		return(2);
	}

	pcap_loop(handle, -1, handle_packet, NULL);

	pcap_freecode(&fexp);
	pcap_close(handle);

	return NULL;
}

void* inserter_thread(void* arg) {
	while(1) {
		pthread_mutex_lock(&collect_mutex);
		insert_ptr = collect_ptr;
		collect_ptr = NULL;
		pthread_mutex_unlock(&collect_mutex);

		print_flows(insert_ptr);
		printf("---------\n");

		sleep(10);
	}

	return NULL;
}
