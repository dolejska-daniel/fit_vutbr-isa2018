// network_utils.c
// ISA, 08.10.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include "network_utils.h"
#include "macros.h"
#include "dns.h"


int process_hostname( SocketAddressPtr address, char *target_hostname )
{
	/************************************************************************
	 * Castecne prevzato z:
	 * https://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
	 ************************************************************************/
	struct hostent *he;
	struct in_addr **addr_list;

	if ((he = gethostbyname(target_hostname)) == NULL)
	{
		//  An error occured
		ERR("An error occured while translating server hostname.\n");
		herror("gethostbyname");
		return EXIT_FAILURE;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	for (int i = 0; addr_list[i] != NULL; i++)
	{
		//  Addres was found
		address->sin_addr = *addr_list[i];
		address->sin_family = he->h_addrtype;
		return EXIT_SUCCESS;
	}

	ERR("Failed to translate hostname to IP address.\n");
	return EXIT_FAILURE;
}

int process_address( SocketAddressPtr address, char *target_address )
{
	if (inet_pton(AF_INET, target_address, &address->sin_addr))
	{
		address->sin_family = AF_INET;
		address->sin_port = htons(DNS_PORT);
	}
	else if (inet_pton(AF_INET6, target_address, &address->sin_addr))
	{
		//  target_address is valid IPv6 address
		address->sin_family = AF_INET6;
		address->sin_port = htons(DNS_PORT);
	}
	else
	{
		//  target_address is neither valid IPv4 nor IPv6 address
		//  lets try using it as hostname
		return process_hostname(address, target_address);
	}

	return EXIT_SUCCESS;
}

uint16_t get_packet_L3_protocol( const uint8_t *packet )
{
	return ntohs(((struct ethhdr *) packet)->h_proto);
}

uint16_t get_packet_L4_protocol( const uint8_t *packet )
{
	return ((struct iphdr *) (packet + get_eth_header_size()))->protocol;
}