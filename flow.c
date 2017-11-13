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
#include <stdbool.h>

#include "flow.h"
#include <netinet/in.h>

static char* proto_to_str(uint8_t proto, char* buf) {
	switch(proto) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			strcpy(buf, "ICMP");
			break;

		case IPPROTO_TCP:
			strcpy(buf, "TCP");
			break;

		case IPPROTO_UDP:
			strcpy(buf, "UDP");
			break;

		case IPPROTO_IPV6:
			strcpy(buf, "IPV6_HEADER");
			break;

		default:
			strcpy(buf, "OTHER");
	}

	return buf;
}

static char* dir_to_str(traf_dir dir, char* buf) {
	if (dir == IN) {
		strcpy(buf, "in");
	} else {
		strcpy(buf, "out");
	}

	return buf;
}

static bool metacmp(struct pkt_meta* a, struct pkt_meta* b) {

	for (int i=0;i<6;i++) {
		if (a->mac[i] != b->mac[i]) return false;
	}

	if (memcmp(&a->ip_addr,&b->ip_addr,sizeof(struct in6_addr)) != 0) return false;
	if (a->dir != b->dir) return false;
	if (a->proto != b->proto) return false;

	return true;
}

void add_dataset_to_flow(struct flow **ptr, traf_dir dir, uint8_t mac[6], struct in6_addr* ip_addr, uint8_t proto, uint32_t size) {

	struct pkt_meta meta;
	struct flow* last = NULL;
	struct flow* iter = *ptr;

	meta.dir = dir;
	memcpy(&meta.mac, mac, sizeof(uint8_t)*6);
	meta.ip_addr = *ip_addr;
	meta.proto = proto;

	while (iter != NULL) {
		if (metacmp(&(iter->meta), &meta)) {
			/* increase counters */
			iter->size += size;

			iter->packets += 1;
			return;
		}
		last = iter;
		iter = iter->next_flow;
	}

	struct flow* new_ptr = malloc(sizeof(struct flow));

	memcpy(&new_ptr->meta,&meta,sizeof(struct pkt_meta));

	new_ptr->size = size;
	new_ptr->packets = 1;
	new_ptr->next_flow = NULL;


	if (*ptr == NULL) {
		/* add new flow as first entry to list */
		*ptr = new_ptr;
	} else {
		/* add new flow to list */
		last->next_flow = new_ptr;
	}
}

void print_flow(struct flow *ptr) {
	char buf[INET6_ADDRSTRLEN];
	printf("FLOW: ");
	printf("mac=%02x:%02x:%02x:%02x:%02x:%02x, ", ptr->meta.mac[0], ptr->meta.mac[1], ptr->meta.mac[2],
			ptr->meta.mac[3], ptr->meta.mac[4], ptr->meta.mac[5]);

	inet_ntop(AF_INET6, &ptr->meta.ip_addr, buf, INET6_ADDRSTRLEN);
	printf("ip=%s, ",  buf);

	printf("dir=0x%x, proto=0x%x %dbytes, %dpkts\n", ptr->meta.dir, ptr->meta.proto, ptr->size, ptr->packets);
	ptr = ptr->next_flow;
}

void flow_to_post(struct flow *f_ptr, char* buf) {
	struct flow *ptr = f_ptr;
	char dir_buf[4];
	char proto_buf[20];
	char ip_buf[INET6_ADDRSTRLEN];

	sprintf(buf, ",mac=%02x:%02x:%02x:%02x:%02x:%02x,dir=%s,ip=%s,proto=%s bytes=%d,packets=%d",
			ptr->meta.mac[0],
			ptr->meta.mac[1],
			ptr->meta.mac[2],
			ptr->meta.mac[3],
			ptr->meta.mac[4],
			ptr->meta.mac[5],
			dir_to_str(ptr->meta.dir, dir_buf),
			inet_ntop(AF_INET6, &ptr->meta.ip_addr, ip_buf, INET6_ADDRSTRLEN),
			proto_to_str(ptr->meta.proto, proto_buf),
			ptr->size,
			ptr->packets);
}

void free_flows(struct flow* ptr) {
	struct flow* nxt_ptr = NULL;

	while(ptr) {
		nxt_ptr = ptr->next_flow;
		free(ptr);
		ptr = nxt_ptr;
	}
}
