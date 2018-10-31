// network_utils.c
// ISA, 08.10.2018
// Author: Daniel Dolejska, FIT

#include <assert.h>
#include "network_utils.h"
#include "macros.h"
#include "dns.h"


// ///////////////////////////////////////////////////////////////////////
//      PROTOCOL PROCESSING
// ///////////////////////////////////////////////////////////////////////

uint16_t get_packet_L3_protocol( const uint8_t *packet )
{
	assert(packet != NULL);
	return ntohs(((struct ethhdr *) packet)->h_proto);
}

uint16_t get_packet_L4_protocol( const uint8_t *packet )
{
	assert(packet != NULL);
	return ((struct iphdr *) (packet + get_eth_header_size()))->protocol;
}


// ///////////////////////////////////////////////////////////////////////
//      ADDRESS PROCESSING
// ///////////////////////////////////////////////////////////////////////

int hostname_to_netaddress( const char *target_hostname, SocketAddressPtr address )
{
	assert(target_hostname != NULL);
	assert(address != NULL);

	/************************************************************************
	 * Castecne prevzato z:
	 * https://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
	 ************************************************************************/
	struct hostent *he;
	struct in_addr **addr_list;

	if ((he = gethostbyname(target_hostname)) == NULL)
	{
		//  An error occured
		ERR("An error occured while translating server hostname...\n");
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

	ERR("Failed to translate hostname to IP address...\n");
	return EXIT_FAILURE;
}

int straddress_to_netaddress( const char *target_address, SocketAddressPtr address )
{
	assert(target_address != NULL);
	assert(address != NULL);

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
		return hostname_to_netaddress(target_address, address);
	}

	return EXIT_SUCCESS;
}
