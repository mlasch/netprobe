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

typedef enum {
	IN,
	OUT
} traf_dir;

struct pkt_meta {
	uint8_t	mac[ETH_ALEN];
	uint8_t proto;
	traf_dir dir;
	struct in6_addr ip_addr;
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

void add_dataset_to_flow(struct flow **ptr, traf_dir dir, uint8_t mac[6], struct in6_addr* ip_addr, uint8_t proto, uint32_t size);
void print_flow(struct flow *f_ptr);
void flow_to_post(struct flow *f_ptr, char* buf);
void free_flows(struct flow* ptr);

#endif /* FLOW_H_ */
