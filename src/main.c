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
#include <string.h>
#include <signal.h>

#include <arpa/inet.h>
#include <ctype.h>

#include "main.h"
#include "process.h"
#include "network.h"
#include "macros.h"
#include "ht.h"
#include "pcap.h"
#include "syslog.h"


tHTable *entry_table;
SyslogSenderPtr syslog;
uint8_t flags = 0b00000000;


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
	DEBUG_LOG("MAIN", "Processing options...");
	/* Spuštění aplikace
	dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]

	-r : zpracuje daný pcap soubor
	-i : naslouchá na daném síťovém rozhraní a zpracovává DNS provoz
	-s : hostname/ipv4/ipv6 adresa syslog serveru
	-t : doba výpočtu statistik, výchozí hodnota 60s
	 */
	char *filepath = NULL;
	char *interface = NULL;
	char *server = NULL;
	char *time = "60";
	uint32_t time_interval = 0;

	int c;
	while ((c = getopt(argc, argv, "r:i:s:t:")) != -1)
	{
		switch (c)
		{
			/** zpracuje daný pcap soubor */
			case 'r':
				if (IS_FLAG_ACTIVE(FLAG_INTERFACE))
				{
					//  Interface flag is already active, cannot use read flag
					ERR("Option -i is already active! You cannot use option -r and -i together.\n");
					exit(EXIT_FAILURE);
				}
				else if (IS_FLAG_ACTIVE(FLAG_READ))
				{
					ERR("Option -r is already active! You cannot use option -r and -s together.\n");
				}

				SET_FLAG_ACTIVE(FLAG_READ);
				filepath = optarg;

				break;

			/** naslouchá na daném síťovém rozhraní a zpracovává DNS provoz */
			case 'i':
				if (IS_FLAG_ACTIVE(FLAG_READ))
				{
					//  Read flag is already active, cannot use interface flag
					ERR("Option -r is already active! You cannot use option -r and -i together.\n");
					exit(EXIT_FAILURE);
				}

				SET_FLAG_ACTIVE(FLAG_INTERFACE);
				interface = optarg;
				break;

			/** hostname/ipv4/ipv6 adresa syslog serveru */
			case 's':
				SET_FLAG_ACTIVE(FLAG_SERVER);
				server = optarg;

				break;

			/** doba výpočtu statistik, výchozí hodnota 60s */
			case 't':
				SET_FLAG_ACTIVE(FLAG_TIME);
				time = optarg;

				break;

			case '?':
				if (optopt == 'r' || optopt == 'i' || optopt == 's' || optopt == 't')
					ERR("Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					ERR("Unknown option `-%c'.\n", optopt);
				else
					ERR("Unknown option character `\\x%x'.\n", optopt);
				exit(EXIT_FAILURE);
			default:
				ERR("Failed to process options.\n");
				exit(EXIT_FAILURE);
		}
	}

	if (flags == 0)
	{
		ERR("Usage: dns-export [-r <file.pcap>] | [-i <interface>] [-s <syslog-server>] [-t <interval_s>]\n");
		exit(EXIT_FAILURE);
	}
	else if (IS_FLAG_ACTIVE(FLAG_READ) == 0 && IS_FLAG_ACTIVE(FLAG_INTERFACE) == 0)
	{
		ERR("Either -r or -i option must be present.\n");
		exit(EXIT_FAILURE);
	}

	char *err;
	time_interval = (uint32_t) strtoul(time, &err, 10);
	if (strlen(err))
	{
		DEBUG_PRINT("time: '%s'\nerr: '%s'\n", time, err);
		ERR("Argument for option -t is invalid. Unsigned long is expected.\n");
		exit(EXIT_FAILURE);
	}

	DEBUG_PRINT("Using following arguments:\n\t-r: '%s'\n\t-i: '%s'\n\t-s: '%s'\n\t-t: %u\n",
			filepath, interface, server, time_interval);

	DEBUG_LOG("MAIN", "Starting application...");
	int status = EXIT_SUCCESS;

	entry_table = malloc(HTSIZE * sizeof(tHTItem));
	if (entry_table == NULL)
	{
		perror("malloc");
		ERR("Failed to allocate hash table, application is unable to continue and will now exit.\n");
		exit(EXIT_FAILURE);
	}
	htInit(entry_table);

	if (IS_FLAG_ACTIVE(FLAG_SERVER))
	{
		syslog = init_syslog_sender(server);
		if (syslog == NULL)
		{
			ERR("Failed to allocate and initialize syslog sender, application is unable to continue and will now exit.\n");
			exit(EXIT_FAILURE);
		}
	}

	//	Setup signal capture
	signal(SIGUSR1, signal_handler);

	if (IS_FLAG_ACTIVE(FLAG_INTERFACE))
	{
		//	Start listening on interface
		status = start_interface_listening(interface, time_interval);
	}
	else if (IS_FLAG_ACTIVE(FLAG_READ))
	{
		//  Start parsing file
		PcapFilePtr file = pcap_file_open(filepath);
		if (file == NULL)
		{
			ERR("Failed to open specified file, application is unable to continue and will now exit.\n");
			exit(EXIT_FAILURE);
		}

		status = start_file_processing(file, time_interval);
		pcap_file_close(file);
	}

	DEBUG_LOG("MAIN", "Cleaning up...");
	if (IS_FLAG_ACTIVE(FLAG_SERVER) && syslog != NULL)
		destroy_syslog_sender(syslog);

	htClearAll(entry_table);
	free(entry_table);

	DEBUG_LOG("MAIN", "Exiting program...");
	exit(status);
}

void signal_handler( int signal )
{
	if (signal == SIGUSR1)
	{
		fprintf(stdout, "RECEIVED SIGUSR1!!!!!\n");
		//	TODO: Print statistics to stdout
	}
}

void entry_sender( tKey key, tData data )
{
	send_syslog_message(syslog, key, data);
}

void entry_printer( tKey key, tData data )
{
	fprintf(stdout, "%s %d\n",
			key,
			data);
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
