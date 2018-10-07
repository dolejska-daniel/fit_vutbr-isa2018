// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "main.h"
#include "macros.h"
#include "ht.h"
#include "process.h"
#include "pcap.h"




void send_statistics()
{
	//  Send stats
	DEBUG_LOG("PROCESS", "Sending statistics...");

	printf("\33[2K\r");
	fprintf(stdout, "CURRENT STATS:\n");
	htWalk(entry_table, &entry_processor);
	fprintf(stdout, "\n");

	DEBUG_LOG("PROCESS", "Resetting table...");
	htClearAll(entry_table);
}





/**
 *
 *
 * @param interface
 * @return exit status
 */
int start_interface_listening( char *interface, uint32_t send_interval )
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
	timeout.tv_sec = (long) send_interval / 4;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
	{
		perror("SO_RCVTIMEO");
		close(sock);
		return EXIT_FAILURE;
	}

	struct timeval time_last, time_now;
	gettimeofday(&time_last, NULL);
	send_interval*= 1000;

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

		DEBUG_PRINT("ms_diff: %f\n", ms_diff);
		if (ms_diff > send_interval)
		{
			send_statistics();
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

	return EXIT_SUCCESS;
}

int start_file_processing( PcapFilePtr file, uint32_t send_interval )
{
	if (file->packet_count == 0)
		return EXIT_SUCCESS;

	PcapPacketHeaderPtr header_last = &file->packets[0]->header;
	for (uint32_t i = 0; i < file->packet_count; i++)
	{
		PcapPacketPtr packet = file->packets[i];

		//  Calculate time difference
		double ms_diff = (packet->header.ts_sec - header_last->ts_sec) * 1000.0;
		ms_diff+= (packet->header.ts_usec - header_last->ts_usec) / 1000.0;

		DEBUG_PRINT("ms_diff: %f\n", ms_diff);
		if (ms_diff > send_interval)
		{
			send_statistics();
			header_last = &packet->header;
		}

		if (process_traffic(packet->data) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}

	send_statistics();
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
	//  Parse headers
	UDPPacketPtr packet = parse_udp_packet(data);
	if (packet == NULL)
	{
		ERR("Failed to process packet, application is unable to continue and will now exit.\n");
		//	TODO: Rather return than continue;?
		return EXIT_FAILURE;
	}

	if (packet->udp_header->source == DNS_PORT)
	{
		DEBUG_LOG("PROCESS", "Packet destination: DNS PORT...");
		DEBUG_PRINT("packet_size: %ld\n", recv_bits);

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