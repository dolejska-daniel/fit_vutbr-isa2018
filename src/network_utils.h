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


typedef struct sockaddr_in SocketAddress;
typedef struct sockaddr_in *SocketAddressPtr;


/**
 * Zpracuje textovy hostname a do predpripravene struktury ulozi jeho IP adresu,
 * adresa muze byt IPv4 i IPv6.
 *
 * @param address
 * @param target_hostname
 * @return exit status code
 */
int process_hostname( SocketAddressPtr address, char *target_hostname );

/**
 * Zpracuje poskytnutou IP adresu v textovem formatu (zpracuje i hostname),
 * a ulozi jej v patricnem formatu do predpripravene struktury.
 *
 * @param address
 * @param target_address
 * @return exit status code
 */
int process_address( SocketAddressPtr address, char *target_address );

#endif //_NETWORK_UTILS_H
