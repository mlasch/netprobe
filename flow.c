/*
 * flow.c
 *
 *  Created on: 23.07.2016
 *      Author: marc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "flow.h"

void add_dataset_to_flow(struct flow **ptr, uint8_t mac[6], uint16_t ethertype, struct in6_addr* ip_src,
		struct in6_addr* ip_dst, uint8_t next_header, uint32_t size) {

	struct pkt_meta meta;
	struct flow* last;
	struct flow* iter = *ptr;

	meta.ethertype = ethertype;
	memcpy(&meta.mac, mac, sizeof(uint8_t)*6);
	memcpy(&meta.ip_src, ip_src, sizeof(struct in6_addr));
	memcpy(&meta.ip_dst, ip_dst, sizeof(struct in6_addr));
	meta.next_header = next_header;

	while (iter != NULL) {
		size_t s = sizeof(struct pkt_meta);
		uint32_t diff = memcmp(&iter->meta, &meta, s);

		if (diff == 0) {
			/* increase counters */
			iter->size += size;

			iter->packets += 1;
			return;
		}
		last = iter;
		iter = iter->next_flow;
	}

	struct flow* new_ptr = malloc(sizeof(struct flow));
	new_ptr->meta = meta;
	new_ptr->size = size;
	new_ptr->packets = 1;


	if (*ptr == NULL) {
		/* add new flow as first entry to list */
		*ptr = new_ptr;
	} else {
		/* add new flow to list */
		last->next_flow = new_ptr;
	}
}

void print_flows(struct flow *f_ptr) {
	struct flow *ptr = f_ptr;
	char buf[INET6_ADDRSTRLEN];

	while(ptr != NULL) {
		printf("mac: %02x:%02x:%02x:%02x:%02x:%02x, ", f_ptr->meta.mac[0], f_ptr->meta.mac[1], f_ptr->meta.mac[2],
				f_ptr->meta.mac[3], f_ptr->meta.mac[4], f_ptr->meta.mac[5]);

		inet_ntop(AF_INET6, &ptr->meta.ip_src, buf, INET6_ADDRSTRLEN);
		printf("%s -> ",  buf);
		inet_ntop(AF_INET6, &ptr->meta.ip_dst, buf, INET6_ADDRSTRLEN);
		printf("%s, ",  buf);

		printf("l3=0x%x, l4=0x%x %dbytes, %dpkts\n", ptr->meta.ethertype, ptr->meta.next_header, ptr->size, ptr->packets);
		ptr = ptr->next_flow;
	}
}

