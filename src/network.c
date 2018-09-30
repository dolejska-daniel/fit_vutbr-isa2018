// network.c
// IPK-PROJ2, 07.04.2018
// ISA, 30.09.2018
// Author: Daniel Dolejska, FIT

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "network.h"
#include "macros.h"


unsigned short check_sum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}


struct ethhdr *get_eth_header( uint8_t *packet )
{
    return (struct ethhdr *) packet;
}

size_t get_eth_header_size()
{
    return sizeof(struct ethhdr);
}

void print_eth_header( const struct ethhdr *eh )
{
#ifdef DEBUG_PRINT_ENABLED
    fprintf(
            stderr,
            "ETH_HEADER: {\n\th_source\t%#x\n\th_dest\t\t%#x\n\th_proto\t\t%#x\n}\n",
            (uint32_t) eh->h_source,
            (uint32_t) eh->h_dest,
            eh->h_proto
    );
#endif
}

void eth_encaps( uint8_t *packet, uint16_t *packet_len, const uint8_t *mac )
{
    DEBUG_LOG("ETH-ENCAPS", "Creating ETH header...");
    struct ethhdr *eh = get_eth_header(packet);

    //  Source MAC address
    eh->h_source[0] = mac[0];
    eh->h_source[1] = mac[1];
    eh->h_source[2] = mac[2];
    eh->h_source[3] = mac[3];
    eh->h_source[4] = mac[4];
    eh->h_source[5] = mac[5];

    //  Destination MAC address (broadcast)
    eh->h_dest[0] = 0xFF;
    eh->h_dest[1] = 0xFF;
    eh->h_dest[2] = 0xFF;
    eh->h_dest[3] = 0xFF;
    eh->h_dest[4] = 0xFF;
    eh->h_dest[5] = 0xFF;

    //  Ethernet protocol
    eh->h_proto = htons(ETH_P_IP);

    *packet_len += get_eth_header_size();

    DEBUG_LOG("ETH-ENCAPS", "ETH header created...");
    DEBUG_PRINT("\tpacket_length (local): %hu (added %d)\n", (unsigned short) *packet_len, get_eth_header_size());
    print_eth_header(eh);
}

struct iphdr *get_ip_header( uint8_t *packet )
{
    return (struct iphdr *) (packet + get_eth_header_size());
}

size_t get_ip_header_size()
{
    return sizeof(struct iphdr);
}

void print_ip_header( const struct iphdr *iph )
{
#ifdef DEBUG_PRINT_ENABLED
    fprintf(
            stderr,
            "IP_HEADER: {\n\tihl\t%d\n\tversion\t%d\n\ttos\t%d\n\tid\t%#x\n\tttl\t%d\n\tprotocol\t%d\n\tsaddr\t%#x\n\tdaddr\t%#x\n\ttot_len\t%d\n\tcheck\t%#x\n}\n",
            iph->ihl,
            iph->version,
            iph->tos,
            iph->id,
            iph->ttl,
            iph->protocol,
            iph->saddr,
            iph->daddr,
            iph->tot_len,
            iph->check
    );
#endif
}

void ip_encaps( uint8_t *packet, uint16_t *packet_len )
{
    DEBUG_LOG("IP-ENCAPS", "Creating IP header...");
    struct iphdr *iph = get_ip_header(packet);

    //  IP header options
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 16; // Low delay
    iph->id       = htons(create_random_number(UINT16_MAX));
    iph->ttl      = 255; // time to live (hops)
    iph->protocol = 17; // UDP protocol

    //  Source address (none)
    iph->saddr = inet_addr("0.0.0.0");

    //  Destination address (broadcast)
    iph->daddr = inet_addr("255.255.255.255");

    *packet_len += get_ip_header_size();

    DEBUG_LOG("IP-ENCAPS", "IP header created...");
    DEBUG_PRINT("\tpacket_length (local): %hu (added %d)\n", (unsigned short) *packet_len, get_ip_header_size());
    print_ip_header(iph);
}

struct udphdr *get_udp_header( uint8_t *packet )
{
    return (struct udphdr *) (packet + get_ip_header_size() + get_eth_header_size());
}

size_t get_udp_header_size()
{
    return sizeof(struct udphdr);
}

void print_udp_header( const struct udphdr *udph )
{
#ifdef DEBUG_PRINT_ENABLED
    fprintf(
            stderr,
            "UDP_HEADER: {\n\tcheck\t%d\n\tsource\t%d\n\tdest\t%d\n\tlen\t%d\n}\n",
            udph->check,
            udph->source,
            udph->dest,
            udph->len
    );
#endif
}

void udp_encaps( uint8_t *packet, uint16_t *packet_len )
{
    DEBUG_LOG("UDP-ENCAPS", "Creating UDP header...");
    struct udphdr *udph = get_udp_header(packet);

    //  UDP header options
    udph->check = 0;

    //  Source port (DHCP client)
    udph->source = htons(68);

    //  Destination port (DHCP server)
    udph->dest = htons(67);

    *packet_len += get_udp_header_size();

    DEBUG_LOG("UDP-ENCAPS", "UDP header created...");
    DEBUG_PRINT("\tpacket_length (local): %hu (added %d)\n", (unsigned short) *packet_len, get_udp_header_size());
    print_udp_header(udph);
}

size_t get_header_sizes()
{
    return get_eth_header_size() + get_ip_header_size() + get_udp_header_size();
}
