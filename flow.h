/*
 * flow.h
 *
 *  Created on: 23.07.2016
 *      Author: marc
 */

#ifndef FLOW_H_
#define FLOW_H_

#include <stdint.h>
#include <linux/if_ether.h>
#include <netinet/ip6.h>

struct pkt_meta {
	uint8_t	mac[ETH_ALEN];
	uint16_t ethertype;
	struct in6_addr ip_src;
	struct in6_addr ip_dst;
	uint8_t next_header;
};

struct flow {
	struct pkt_meta meta;

	/* actual data */
	uint32_t size;
	uint32_t packets;

	struct flow *next_flow;
};

extern struct flow* insert_ptr;
extern struct flow* collect_ptr;

void add_dataset_to_flow(struct flow **ptr, uint8_t mac[6], uint16_t ethertype, struct in6_addr* ip_src,
		struct in6_addr* ip_dst, uint8_t next_header, uint32_t size);
void print_flows(struct flow *f_ptr);

#endif /* FLOW_H_ */
