/*
 * handle_packet.c
 *
 *  Created on: 05.05.2016
 *      Author: marc
 */

#include <curl/curl.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "flow.h"
#include "globals.h"
#include "handle_packet.h"
#include "main.h"
#include "logging.h"

#define NUM_NETS 9

// TODO add link local and non routeable ipv6 addresses
const char *local_nets[NUM_NETS][2] = {{/* wan address */
                                        "::ffff:82.139.196.221", "::ffff:255.255.255.255"},
                                       {/* 10.0.0.0/8 */
                                        "::ffff:10.0.0.0", "::ffff:255.0.0.0"},
                                       {/* 224.0.0.0/24 Administratively Scoped Block (RFC 5771) */
                                        "::ffff:224.0.0.0", "::ffff:255.0.0.0"},
                                       {/* 239.0.0.0/8 Administratively Scoped Block (RFC 5771) */
                                        "::ffff:239.0.0.0", "::ffff:255.0.0.0"},
                                       {"2a01:0170:1089:0002::", "ffff:ffff:ffff:ffff::"},
                                       {/* fe80::/10 Link-Scoped Unicast (RFC 5156) */
                                        "fe80::", "ffc0::"},
                                       {/* ff01::/16 Pre-Defined Multicast Addresses interface-local (RFC 4291) */
                                        "ff01::", "ffff::"},
                                       {/* ff02::/16 Pre-Defined Multicast Addresses link-local (RFC 4291) */
                                        "ff02::", "ffff::"},
                                       {/* ff05::/16 Pre-Defined Multicast Addresses site-local(RFC 4291) */
                                        "ff05::", "ffff::"}};

bool check_local(struct in6_addr *addr) {
    struct in6_addr temp;

    char str[INET6_ADDRSTRLEN];

    for (int i = 0; i < NUM_NETS; i++) {
        struct in6_addr network, prefix;

        inet_pton(AF_INET6, local_nets[i][0], &network);
        inet_pton(AF_INET6, local_nets[i][1], &prefix);

        /* addr logical and netmask */
        for (int j = 0; j < 4; j++) {
            temp.__in6_u.__u6_addr32[j] = addr->__in6_u.__u6_addr32[j] & prefix.__in6_u.__u6_addr32[j];
        }

        if (memcmp(&temp, &network, sizeof(struct in6_addr)) == 0) {
            inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);

            return true;
        }
    }

    return false;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *pcap_header, const u_char *packet_ptr) {

    struct ether_header *eth_header = (struct ether_header *)packet_ptr;

    uint8_t *mac;
    traf_dir dir;
    uint32_t routeable_size = pcap_header->len - ETH_HLEN;
    uint16_t ethertype = ntohs(eth_header->ether_type);
    uint8_t proto;
    struct in6_addr src = {{.__u6_addr32 = {0, 0, 0, 0}}};
    struct in6_addr dst = {{.__u6_addr32 = {0, 0, 0, 0}}};
    struct in6_addr ip_addr = {{.__u6_addr32 = {0, 0, 0, 0}}};

    if (ethertype == ETH_P_IP) {
        /* received packet is IPv4 */

        struct iphdr *ip4_header = (struct iphdr *)(packet_ptr + ETH_HLEN);
        proto = ip4_header->protocol;

        /* ipv6 mapped v4 addresses (rfc4038) */
        src.__in6_u.__u6_addr32[2] = 0xffff0000;
        dst.__in6_u.__u6_addr32[2] = 0xffff0000;
        src.__in6_u.__u6_addr32[3] = ip4_header->saddr;
        dst.__in6_u.__u6_addr32[3] = ip4_header->daddr;

    } else if (ethertype == ETH_P_IPV6) {
        /* received packet is IPv6 */

        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet_ptr + ETH_HLEN);
        proto = ip6_header->ip6_nxt;

        src = ip6_header->ip6_src;
        dst = ip6_header->ip6_dst;

    } else {
        /* Non IP packet received -> will not be routed */
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
    add_dataset_to_flow(&collect_ptr, dir, mac, &ip_addr, proto, routeable_size);
    pthread_mutex_unlock(&collect_mutex);
}

void *pcap_thread(void *arg) {
    char *filter;
    char *dev = ((pcap_arg_t *)arg)->dev;

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fexp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        LOG_ERR("Can't get netmask for device %s", dev);
        net = 0;
        mask = 0;
    }

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);

    if (handle == NULL) {
        LOG_ERR("Couldn't open device %s: %s", dev, errbuf);
        pthread_exit((void *)NULL);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        LOG_ERR("%s is not an Ethernet device", dev);
        pthread_exit((void *)NULL);
    }

    filter = "";

    if (pcap_compile(handle, &fexp, filter, 0, net)) {
        LOG_ERR("Couldn't parse filter %s: %s", filter, pcap_geterr(handle));
        pthread_exit((void *)NULL);
    }

    if (pcap_setfilter(handle, &fexp) == -1) {
        LOG_ERR("Couldn't install filter %s: %s", filter, pcap_geterr(handle));
        pthread_exit((void *)NULL);
    }

    pcap_loop(handle, -1, handle_packet, NULL);

    pcap_freecode(&fexp);
    pcap_close(handle);

    pthread_exit((void *)NULL);
}

_Noreturn void *inserter_thread(void *arg) {
    CURL *curl_handle = (CURL *)((inserter_arg_t *)arg)->curl_handle;
    curl_easy_setopt(curl_handle, CURLOPT_URL, ((inserter_arg_t *)arg)->url);

    while (1) {
        sleep(INSERT_DELAY);

        pthread_mutex_lock(&collect_mutex);
        insert_ptr = collect_ptr;
        collect_ptr = NULL;
        pthread_mutex_unlock(&collect_mutex);

        if (verbose_flag) {
            printf("---------\n");
        }

        struct flow *iter = insert_ptr;

        while (iter) {
            char param[MAX_PARAM_LENGTH] = {0};
            char data[MAX_PARAM_LENGTH + MAX_PATH_LENGTH] = {0};

            strcat(data, ((inserter_arg_t *)arg)->measurement);
            flow_to_post(iter, param);
            strcat(data, param);

            curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);

            if (!nop_flag) {

                CURLcode curl_code = curl_easy_perform(curl_handle);

                if (curl_code) {
                    LOG_ERR("CURL error: %s\n", curl_easy_strerror(curl_code));
                } else {
                    LOG_INF("inserted");
                }
            }

            if (verbose_flag) {
                print_flow(iter);
            }

            iter = iter->next_flow;
        }

        free_flows(insert_ptr);
    }

    pthread_exit((void *)NULL);
}
