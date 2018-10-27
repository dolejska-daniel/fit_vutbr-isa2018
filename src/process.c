// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <sys/time.h>

#include "process.h"
#include "main.h"
#include "network_utils.h"
#include "macros.h"
#include "ht.h"
#include "pcap.h"


long send_interval_current = 0;


/**
 *
 *
 * @param interface
 * @return exit status
 */
int start_interface_listening( char *interface )
{
	DEBUG_LOG("PROCESS", "Starting listening...");

	DEBUG_LOG("PROCESS", "Creating RAW socket...");
	int sock;
	//  Raw socket
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(0x0800))) == -1)
	{
		perror("socket");
		return EXIT_FAILURE;
	}

	DEBUG_LOG("PROCESS", "Getting interface ID...");
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface, strlen(interface) + 1);
	if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror("SIOCGIFINDEX");
		return EXIT_FAILURE;
	}

	DEBUG_LOG("PROCESS", "Setting socket options...");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) < 0)
	{
		perror("SO_BINDTODEVICE");
		close(sock);
		return EXIT_FAILURE;
	}

	int flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
	{
		perror("SO_REUSEADDR");
		close(sock);
		return EXIT_FAILURE;
	}

	struct timeval timeout;
	timeout.tv_sec = send_interval / 4;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
	{
		perror("SO_RCVTIMEO");
		close(sock);
		return EXIT_FAILURE;
	}

	struct timeval time_last, time_now;
	gettimeofday(&time_last, NULL);
	long send_interval_ms = send_interval * 1000;

	DEBUG_LOG("PROCESS", "Listening for transmissions...");

	while (1)
	{
		//  Initialize variables
		short recv_bits = 0;
		uint8_t recv_data[BUFFER_SIZE];

		//  Receive data
		recv_bits = (uint16_t) receive_data(sock, recv_data);
		gettimeofday(&time_now, NULL);

		//  Calculate time difference
		double ms_diff = (time_now.tv_sec - time_last.tv_sec) * 1000.0;
		ms_diff+= (time_now.tv_usec - time_last.tv_usec) / 1000.0;
		send_interval_current = (long) ms_diff / 1000;

		DEBUG_PRINT("ms_diff: %f\n", ms_diff);
		if (ms_diff > send_interval_ms)
		{
			send_statistics(1, 0);
			time_last = time_now;
			if (recv_bits == 0)
				continue;
		}

		if (recv_bits > 0)
		{
			//	Something has been received
			DEBUG_LOG("PROCESS", "Packet received...");
			process_traffic(recv_data);
		}
		else if (recv_bits < 0)
			break;
	}

	send_statistics(1, 0);
	return EXIT_SUCCESS;
}

int start_file_processing( PcapFilePtr file )
{
	if (file->packet_count == 0)
		return EXIT_SUCCESS;

	PcapPacketHeaderPtr header_last = &file->packets[0]->header;
	for (uint32_t i = 0; i < file->packet_count; i++)
	{
		PcapPacketPtr packet = file->packets[i];

		//  Calculate time difference
		double s_diff = (packet->header.ts_sec - header_last->ts_sec);
		send_interval_current = (long) s_diff;

		DEBUG_PRINT("s_diff: %f\n", s_diff);
		if (s_diff > send_interval && IS_FLAG_ACTIVE(FLAG_TIME))
		{
			send_statistics(1, 0);
			header_last = &packet->header;
		}

		if (process_traffic(packet->data) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}

	send_statistics(1, 0);
	return EXIT_SUCCESS;
}

short receive_data( int sock, uint8_t *data )
{
	short recv_bits = 0;
	memset(data, 0, BUFFER_SIZE);

	//  Receive offer
	recv_bits = (short) recvfrom(sock, data, BUFFER_SIZE, 0, NULL, NULL);
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	{
		//  Receive timeout
		DEBUG_LOG("PROCESS", "No waiting packets...");
		recv_bits = 0;
		errno = 0;
	}
	else if (errno == EINTR)
	{
		//  Process was interrupted
		DEBUG_LOG("PROCESS", "Recvfrom interrupted...");
		recv_bits = 0;
		errno = 0;
	}
	else if (recv_bits < 0 || errno != 0)
	{
		//  Different error
		perror("recvfrom");
	}

	return recv_bits;
}

int process_traffic( uint8_t *data )
{
	uint16_t L3_protocol = get_packet_L3_protocol(data);
	if (L3_protocol != IPv4 && L3_protocol != IPv6)
	{
		//  Ignore non IP protocols
		DEBUG_LOG("PROCESS", "Ignoring non-IP packet.");
		DEBUG_PRINT("\tL3_protocol: %#x (accepting %#x or %#x)\n", L3_protocol, IPv4, IPv6);
		return EXIT_SUCCESS;
	}

	uint16_t L4_protocol = get_packet_L4_protocol(data);
	if (L4_protocol == TCP)
	{
		//  Parse headers
		TCPPacketPtr packet = parse_tcp_packet(data);
		if (packet == NULL)
		{
			ERR("Failed to process packet, application is unable to continue and will now exit.\n");
			//	TODO: Rather return than continue;?
			return EXIT_FAILURE;
		}

		//  TODO: Create common packet from TCP packet

		/*
		if (packet->tcp_header->source == DNS_PORT)
		{
			DEBUG_LOG("PROCESS[TCP]", "Packet destination: DNS PORT...");

			//  Parse DNS part of the packet
			DNSPacketPtr dns = parse_dns_packet(packet);
			if (dns == NULL)
			{
				ERR("Failed to process DNS packet, application is unable to continue and will now exit.\n");
				//	TODO: Rather return than continue;?
				return EXIT_FAILURE;
			}

			print_dns_packet(dns);

			//	Log traffic somehow
			process_dns_traffic(dns);

			//	DNS packet is no longer needed
			destroy_dns_packet(dns);
		}

		//	UDP packet is no longer needed
		destroy_udp_packet(packet);
		 */

		return EXIT_SUCCESS;
	}
	else if (L4_protocol == UDP)
	{
		//  Parse headers
		UDPPacketPtr packet = parse_udp_packet(data);
		if (packet == NULL)
		{
			ERR("Failed to process packet, application is unable to continue and will now exit.\n");
			//	TODO: Rather return than continue;?
			return EXIT_FAILURE;
		}

		//  TODO: Create common packet from UDP packet

		if (packet->udp_header->source == DNS_PORT)
		{
			DEBUG_LOG("PROCESS[UDP]", "Packet destination: DNS PORT...");

			//  Parse DNS part of the packet
			DNSPacketPtr dns = parse_dns_packet(packet);
			if (dns == NULL)
			{
				ERR("Failed to process DNS packet, application is unable to continue and will now exit.\n");
				//	TODO: Rather return than continue;?
				return EXIT_FAILURE;
			}

			print_dns_packet(dns);

			//	Log traffic somehow
			process_dns_traffic(dns);

			//	DNS packet is no longer needed
			destroy_dns_packet(dns);
		}

		//	UDP packet is no longer needed
		destroy_udp_packet(packet);
	}
	else
	{
		//  Ignore non TCP or UDP packets
		DEBUG_PRINT("\tL4_protocol: %#x (ignoring)\n", L4_protocol);
		return EXIT_SUCCESS;
	}

	return EXIT_SUCCESS;
}

void process_dns_traffic( DNSPacketPtr dns )
{
	for (int i = 0; i < dns->answer_count; i++)
	{
		DNSResourceRecordPtr record = dns->answers[i];

		char *data; translate_dns_data(record, &data);
		char *type = translate_dns_type(dns->answers[i]->record_type);

		size_t entry_length = strlen(record->name) + 1 + strlen(type) + 1 + strlen(data); // +1s for whitespaces
		char *entry = malloc(entry_length + 1); // +1 for '\0'
		sprintf(entry, "%s %s %s", record->name, type, data);

		printf("\33[2K\r");
		fprintf(stdout, "%s +1", entry);
		fflush(stdout);

		//  Do not free created items, item key will be freed before cleaning the table
		if (htIncrease(entry_table, entry) != ITEM_STATUS_CREATED)
			//  Free entry for *UPDATED* item
			free(entry);

		//  Free translated DNS data
		free(data);
	}
}

void send_statistics( short clear_table, short force_print )
{
	//  Send stats
	DEBUG_LOG("PROCESS", "Sending statistics...");

	printf("\33[2K\r");
	if (IS_FLAG_ACTIVE(FLAG_SERVER) && force_print == 0)
	{
		htWalk(entry_table, &entry_sender);
		syslog_buffer_flush(syslog);
	}
	else
	{
		fprintf(stdout, "=== DNS Traffic Statistics (last %ld minute(s) %ld second(s)) ===\n", send_interval_current / 60, send_interval_current % 60);
		htWalk(entry_table, &entry_printer);
		fprintf(stdout, "\n");
	}

	if (clear_table == 1)
	{
		DEBUG_LOG("PROCESS", "Resetting table...");
		htClearAll(entry_table);
	}
}
