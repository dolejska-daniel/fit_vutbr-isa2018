// network_utils.c
// ISA, 08.10.2018
// Author: Daniel Dolejska, FIT

#ifndef _NETWORK_UTILS_H
#define _NETWORK_UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <memory.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "network.h"


// ///////////////////////////////////////////////////////////////////////
//      PROTOCOL PROCESSING
// ///////////////////////////////////////////////////////////////////////

/**
 * Ziska protokol na L3 vrstve (sitova). IPv4, IPv6, ARP, RIP, ...
 *
 * @param packet
 * @return uint16_t
 */
uint16_t get_packet_L3_protocol( const uint8_t *packet );

/**
 * Ziska protokol na L4 vrstve (transportni). TCP, UDP, ...
 *
 * @param packet
 * @return uint16_t
 */
uint16_t get_packet_L4_protocol( const uint8_t *packet );


// ///////////////////////////////////////////////////////////////////////
//      ADDRESS PROCESSING
// ///////////////////////////////////////////////////////////////////////

typedef struct sockaddr_in SocketAddress;
typedef struct sockaddr_in *SocketAddressPtr;

/**
 * Zpracuje textovy hostname a do predpripravene struktury ulozi jeho IP adresu,
 * adresa muze byt IPv4 i IPv6.
 *
 * @param target_hostname
 * @param address
 * @return exit status code
 */
int hostname_to_netaddress( const char *target_hostname, SocketAddressPtr address );

/**
 * Zpracuje poskytnutou IP adresu/hostname v textovem formatu, a ulozi jej
 * v patricnem formatu do predpripravene struktury (nebude alokovana).
 *
 * @see hostname_to_netaddress
 *
 * @param target_address
 * @param address
 * @return exit status code
 */
int straddress_to_netaddress( const char *target_address, SocketAddressPtr address );

#endif //_NETWORK_UTILS_H
