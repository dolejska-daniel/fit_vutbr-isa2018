// network.c
// IPK-PROJ2, 07.04.2018
// ISA, 30.09.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>

#include "network.h"
#include "network_utils.h"
#include "macros.h"
#include "dns.h"


// ///////////////////////////////////////////////////////////////////////
//      PACKET DATA
// ///////////////////////////////////////////////////////////////////////

PacketDataPtr create_packet_data(uint8_t *data, uint16_t offset)
{
    DEBUG_LOG("PACKET-DATA-CREATE", "Creating packet data holder...");
    PacketDataPtr pdata = (PacketDataPtr) malloc(sizeof(PacketData));
    if (pdata == NULL)
    {
        perror("malloc");
        return NULL;
    }

    pdata->data   = data;
    pdata->offset = offset;

    return pdata;
}

void destroy_packet_data( PacketDataPtr pdata )
{
	DEBUG_LOG("PACKET-DATA-DESTROY", "Destroying packet data...");
    free(pdata);
}

uint8_t *get_packet_data( PacketDataPtr pdata )
{
    assert(pdata != NULL);
    return pdata->data + pdata->offset;
}

uint8_t *get_packet_data_custom( PacketDataPtr pdata, uint16_t offset )
{
    assert(pdata != NULL);
    return pdata->data + offset;
}


// ///////////////////////////////////////////////////////////////////////
//      TCP
// ///////////////////////////////////////////////////////////////////////

TCPPacketPtr parse_tcp_packet( uint8_t *packet_data )
{
    DEBUG_LOG("TCP-PACKET-PARSE", "Parsing TCP packet...");
    TCPPacketPtr packet = (TCPPacketPtr) malloc(sizeof(TCPPacket));
    if (packet == NULL)
    {
        perror("malloc");
        return NULL;
    }

    packet->eth_header = get_eth_header(packet_data);
    packet->ip_header  = get_ip_header(packet_data);
    packet->tcp_header = get_tcp_header(packet_data);
    packet->data       = create_packet_data(packet_data + get_header_sizes_tcp(packet), 0);
    if (packet->data == NULL)
    {
    	destroy_tcp_packet(packet);
    	return NULL;
    }

    //DEBUG_PRINT("\n\nPACKETDATA:\n%#x %#x %#x %#x %#x %#x %#x %#x\n",
    //            get_packet_data(packet->data)[0], get_packet_data(packet->data)[1], get_packet_data(packet->data)[2], get_packet_data(packet->data)[3],
    //            get_packet_data(packet->data)[4], get_packet_data(packet->data)[5], get_packet_data(packet->data)[6], get_packet_data(packet->data)[7]);

    return packet;
}

void destroy_tcp_packet( TCPPacketPtr packet )
{
    assert(packet != NULL);

    DEBUG_LOG("TCP-PACKET-DESTROY", "Destroying TCP packet...");
	destroy_packet_data(packet->data);
    free(packet);
}


// ///////////////////////////////////////////////////////////////////////
//      UDP
// ///////////////////////////////////////////////////////////////////////

UDPPacketPtr parse_udp_packet( uint8_t *packet_data )
{
    DEBUG_LOG("UDP-PACKET-PARSE", "Parsing UDP packet...");
    UDPPacketPtr packet = (UDPPacketPtr) malloc(sizeof(UDPPacket));
	if (packet == NULL)
	{
		perror("malloc");
        return NULL;
	}

    packet->eth_header = get_eth_header(packet_data);
    packet->ip_header  = get_ip_header(packet_data);
    packet->udp_header = get_udp_header(packet_data);
	packet->data       = create_packet_data(packet_data + get_header_sizes_udp(), 0);
	if (packet->data == NULL)
	{
		destroy_udp_packet(packet);
		return NULL;
	}

    return packet;
}

void destroy_udp_packet( UDPPacketPtr packet )
{
	assert(packet != NULL);

	DEBUG_LOG("UDP-PACKET-DESTROY", "Destroying UDP packet...");
	destroy_packet_data(packet->data);
    free(packet);
}


// ///////////////////////////////////////////////////////////////////////
//      ETH HEADERS
// ///////////////////////////////////////////////////////////////////////

struct ethhdr *get_eth_header( uint8_t *packet )
{
    //DEBUG_LOG("ETH-GET", "Getting ETH header...");
    struct ethhdr *header = (struct ethhdr *) packet;
    header->h_proto = ntohs(header->h_proto);

    return header;
}

uint16_t get_eth_header_size()
{
    return sizeof(struct ethhdr);
}

void print_eth_header( const UDPPacketPtr packet )
{
    print_eth_header_struct(packet->eth_header);
}

void print_eth_header_struct( const struct ethhdr *eh )
{
#ifdef DEBUG_PRINT_ENABLED
    fprintf(
            stderr, "ETH_HEADER (size: %u [+4 checksum]): {\n\th_source\t%02x:%02x:%02x:%02x:%02x:%02x\n\th_dest\t\t%02x:%02x:%02x:%02x:%02x:%02x\n\th_proto\t\t%#04x\n}\n",
            get_eth_header_size(),
            eh->h_source[0], eh->h_source[1], eh->h_source[2], eh->h_source[3], eh->h_source[4], eh->h_source[5],
            eh->h_dest[0], eh->h_dest[1], eh->h_dest[2], eh->h_dest[3], eh->h_dest[4], eh->h_dest[5],
            eh->h_proto
    );
#endif
}

void eth_encaps( uint8_t *packet, uint16_t *packet_len, const uint8_t *source_mac, const uint8_t *destination_mac )
{
    DEBUG_LOG("ETH-ENCAPS", "Creating ETH header...");
    struct ethhdr *eh = get_eth_header(packet);

    //  Source MAC address
    eh->h_source[0] = source_mac[0];
    eh->h_source[1] = source_mac[1];
    eh->h_source[2] = source_mac[2];
    eh->h_source[3] = source_mac[3];
    eh->h_source[4] = source_mac[4];
    eh->h_source[5] = source_mac[5];

    //  Destination MAC address (broadcast)
    eh->h_dest[0] = destination_mac[0];
    eh->h_dest[1] = destination_mac[1];
    eh->h_dest[2] = destination_mac[2];
    eh->h_dest[3] = destination_mac[3];
    eh->h_dest[4] = destination_mac[4];
    eh->h_dest[5] = destination_mac[5];

    //  Ethernet protocol
    eh->h_proto = htons(ETH_P_IP);

    *packet_len += get_eth_header_size();

    DEBUG_LOG("ETH-ENCAPS", "ETH header created...");
    DEBUG_PRINT("\tpacket_length (local): %hu (added %u)\n", (unsigned short) *packet_len, get_eth_header_size());
    print_eth_header_struct(eh);
}


// ///////////////////////////////////////////////////////////////////////
//      IP HEADERS
// ///////////////////////////////////////////////////////////////////////

struct iphdr *get_ip_header( uint8_t *packet )
{
    //DEBUG_LOG("IPH-GET", "Getting IP header...");
    struct iphdr *header = (struct iphdr *) (packet + get_eth_header_size());
    header->tot_len = ntohs(header->tot_len);
    header->id      = ntohs(header->id);
    header->check   = ntohs(header->check);

    return header;
}

uint16_t get_ip_header_size()
{
    return sizeof(struct iphdr);
}

void print_ip_header( const UDPPacketPtr packet )
{
    print_ip_header_struct(packet->ip_header);
}

void print_ip_header_struct( const struct iphdr *iph )
{
#ifdef DEBUG_PRINT_ENABLED
    fprintf(
            stderr, "IP_HEADER (size: %u): {\n\tversion\t%d\n\tihl\t%d\n\ttos\t%d\n\tid\t%#x\n\tttl\t%d\n\tprotocol\t%d\n\tsaddr\t%#x, %hu.%hu.%hu.%hu\n\tdaddr\t%#x, %hu.%hu.%hu.%hu\n\ttot_len\t%d\n\tcheck\t%#x\n}\n",
            get_ip_header_size(),
            iph->version,
            iph->ihl,
            iph->tos,
            iph->id,
            iph->ttl,
            iph->protocol,
            iph->saddr,
            iph->saddr << 24 >> 24, iph->saddr << 16 >> 24, iph->saddr << 8 >> 24, iph->saddr << 0 >> 24,
            iph->daddr,
            iph->daddr << 24 >> 24, iph->daddr << 16 >> 24, iph->daddr << 8 >> 24, iph->daddr << 0 >> 24,
            iph->tot_len,
            iph->check
    );
#endif
}

void ip_encaps( uint8_t *packet, uint16_t *packet_len )
{
    DEBUG_LOG("IPH-ENCAPS", "Creating IP header...");
    struct iphdr *iph = get_ip_header(packet);

    //  IP header options
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 16; // Low delay
    //iph->id       = htons(create_random_number(UINT16_MAX));
    iph->ttl      = 255; // time to live (hops)
    iph->protocol = 17; // UDP protocol

    //  Source address (none)
    iph->saddr = inet_addr("0.0.0.0");

    //  Destination address (broadcast)
    iph->daddr = inet_addr("255.255.255.255");

    *packet_len += get_ip_header_size();

    DEBUG_LOG("IPH-ENCAPS", "IP header created...");
    DEBUG_PRINT("\tpacket_length (local): %hu (added %u)\n", (unsigned short) *packet_len, get_ip_header_size());
    print_ip_header_struct(iph);
}


// ///////////////////////////////////////////////////////////////////////
//      UDP HEADERS
// ///////////////////////////////////////////////////////////////////////

struct udphdr *get_udp_header( uint8_t *packet )
{
    //DEBUG_LOG("UDPH-GET", "Getting UDP header...");
    struct udphdr *header = (struct udphdr *) (packet + get_ip_header_size() + get_eth_header_size());
    header->check  = ntohs(header->check);
    header->source = ntohs(header->source);
    header->dest   = ntohs(header->dest);
    header->len    = ntohs(header->len);

    return header;
}

uint16_t get_udp_header_size()
{
    return sizeof(struct udphdr);
}

void print_udp_header( const UDPPacketPtr packet )
{
    print_udp_header_struct(packet->udp_header);
}

void print_udp_header_struct( const struct udphdr *udph )
{
#ifdef DEBUG_PRINT_ENABLED
    fprintf(
            stderr, "UDP_HEADER (size: %u): {\n\tsource\t%u\n\tdest\t%u\n\tlen\t%d\n\tcheck\t%#x\n}\n",
            get_udp_header_size(),
            udph->source,
            udph->dest,
            udph->len,
            udph->check
    );
#endif
}

void udp_encaps( uint8_t *packet, uint16_t *packet_len, uint16_t source_port, uint16_t destination_port )
{
    DEBUG_LOG("UDPH-ENCAPS", "Creating UDP header...");
    struct udphdr *udph = get_udp_header(packet);

    //  UDP header options
    udph->check = 0;

    //  Source port
    udph->source = htons(source_port);

    //  Destination port
    udph->dest = htons(destination_port);

    *packet_len += get_udp_header_size();

    DEBUG_LOG("UDPH-ENCAPS", "UDP header created...");
    DEBUG_PRINT("\tpacket_length (local): %hu (added %u)\n", (unsigned short) *packet_len, get_udp_header_size());
    print_udp_header_struct(udph);
}


// ///////////////////////////////////////////////////////////////////////
//      TCP HEADERS
// ///////////////////////////////////////////////////////////////////////

struct tcphdr *get_tcp_header( uint8_t *packet )
{
    //DEBUG_LOG("TCPH-GET", "Getting TCP header...");
    struct tcphdr *header = (struct tcphdr *) (packet + get_ip_header_size() + get_eth_header_size());
    header->check  = ntohs(header->check);
    header->source = ntohs(header->source);
    header->dest   = ntohs(header->dest);

    return header;
}

uint16_t get_tcp_header_size( TCPPacketPtr packet )
{
    return packet->tcp_header->doff * 4u;
}

void print_tcp_header( const TCPPacketPtr packet )
{
	print_tcp_header_struct(packet->tcp_header, get_tcp_header_size(packet));
}

void print_tcp_header_struct( const struct tcphdr *tcph, uint16_t size )
{
#ifdef DEBUG_PRINT_ENABLED
	fprintf(
		stderr, "TCP_HEADER (size: %u): {\n\tsource\t%u\n\tdest\t%u\n\tcheck\t%#x\n\tseq\t%u\n\tack\t%u\n\tack_seq\t%u\n\tflags\t%#x\n\tFIN\t%#x\n\tSYN\t%#x\n\tACK\t%#x\n}\n",
		size,
		tcph->source,
		tcph->dest,
		tcph->check,
        tcph->th_seq,
		tcph->th_ack,
		tcph->ack_seq,
		tcph->th_flags,
		tcph->fin,
		tcph->syn,
		tcph->ack
	);
#endif
}


// ///////////////////////////////////////////////////////////////////////
//      GENERAL
// ///////////////////////////////////////////////////////////////////////

unsigned short check_sum( unsigned short *buf, int nwords )
{
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

uint16_t get_header_sizes_udp()
{
	return (uint16_t)(get_eth_header_size() + get_ip_header_size() + get_udp_header_size());
}

uint16_t get_header_sizes_tcp( TCPPacketPtr packet )
{
	return (uint16_t)(get_eth_header_size() + get_ip_header_size() + get_tcp_header_size(packet));
}
