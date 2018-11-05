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
#include <assert.h>

#include "process.h"
#include "main.h"
#include "network_utils.h"
#include "macros.h"
#include "ht.h"
#include "pcap.h"


long seconds_since_start = 0;
long send_interval_current = 0;
uint8_t *tcp_buffer = 0;
uint8_t tcp_packet_ended = 0;
uint16_t tcp_buffer_offset = 0;
uint16_t tcp_dns_length = 0;
uint32_t tcp_packet_seq = 0;


// ///////////////////////////////////////////////////////////////////////
//      TCP PACKET BUFFER
// ///////////////////////////////////////////////////////////////////////

int create_tcp_buffer()
{
	tcp_buffer = malloc(TCP_BUFFER_SIZE);
	if (tcp_buffer == NULL)
	{
		ERR("Failed to allocate memory for TCP packet buffer...\n");
		perror("malloc");
		return EXIT_FAILURE;
	}
	memset(tcp_buffer, 0, TCP_BUFFER_SIZE);
	return EXIT_SUCCESS;
}

void destroy_tcp_buffer()
{
	assert(tcp_buffer != NULL);

	free(tcp_buffer);
	tcp_buffer = NULL;
}

void push_tcp_data( TCPPacketPtr packet )
{
	assert(packet != NULL);
	assert(tcp_buffer != NULL);

	DEBUG_LOG("PUSH-TCP-DATA", "Pushing TCP packet data...");
	if (tcp_packet_ended == 0 && tcp_packet_seq > 0 && packet->tcp_header->ack_seq != tcp_packet_seq)
	{
		DEBUG_ERR("PUSH-TCP-DATA", "Failed to push another TCP packet, last packet not popped!");
		return;
	}

	if (packet->tcp_header->syn != 0
		|| packet->tcp_header->source != DNS_PORT)
	{
		DEBUG_LOG("PUSH-TCP-DATA", "Ignoring packet, doesn't contain DNS data...");
		//  Packet doesn't contain any DNS data
		return;
	}

	//  Size of TCP payload
	uint16_t size = packet->ip_header->tot_len - get_ip_header_size() - get_tcp_header_size(packet);
	if (size == 0)
	{
		DEBUG_LOG("PUSH-TCP-DATA", "Ignoring packet, no data are present...");
		return;
	}

	if (tcp_dns_length == 0)
	{
		DEBUG_LOG("PUSH-TCP-DATA", "Setting DNS response length...");
		tcp_dns_length = ntohs(*((uint16_t *)get_packet_data(packet->data)));
		packet->data->offset+= 2;
		size-= 2;
		DEBUG_PRINT("\tsupposed_length: %u\n", tcp_dns_length);
	}

	DEBUG_LOG("PUSH-TCP-DATA", "Inserting packet data...");
	tcp_packet_seq = packet->tcp_header->ack_seq;
	DEBUG_PRINT("\tsize: %d\n\ttcp_packet_seq: %u\n\toffset: %u\n",
	            size, tcp_packet_seq, tcp_buffer_offset);

	//  Current buffer position
	uint8_t *buffer = tcp_buffer + tcp_buffer_offset;
	//  Copy data
	for (uint16_t i = 0; i < size; i++)
		buffer[i] = get_packet_data(packet->data)[i];

	//  Move in buffer
	tcp_buffer_offset+= size;
	if (tcp_buffer_offset >= tcp_dns_length)
	{
		DEBUG_LOG("PUSH-TCP-DATA", "Current length is equal or exceeds supposed length, ending packet...");
		DEBUG_PRINT("\tsupposed_length: %u\n\tactual_length: %u\n", tcp_dns_length, tcp_buffer_offset);
		tcp_packet_ended = 1;
	}
}

uint16_t pop_tcp_data( TCPPacketPtr packet )
{
	assert(packet != NULL);
	assert(tcp_buffer != NULL);

	DEBUG_LOG("POP-TCP-DATA", "Popping packet data...");
	if (tcp_packet_ended == 0)
	{
		DEBUG_LOG("POP-TCP-DATA", "Previous packet not ended yet...");
		return 0;
	}

	DEBUG_LOG("PUSH-TCP-DATA", "Popping will proceed...");
	packet->data->data = tcp_buffer;
	packet->data->offset = 0;

	uint16_t result = tcp_buffer_offset;
	tcp_packet_ended = 0;
	tcp_packet_seq = 0;
	tcp_buffer_offset = 0;
	tcp_dns_length = 0;
	return result;
}


// ///////////////////////////////////////////////////////////////////////
//      PACKET PROCESSING
// ///////////////////////////////////////////////////////////////////////

/**
 *
 *
 * @param interface
 * @return exit status
 */
int start_interface_listening( char *interface )
{
	assert(interface != NULL);

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

	if (create_tcp_buffer() != EXIT_SUCCESS)
	{
		close(sock);
		return EXIT_FAILURE;
	}

	DEBUG_LOG("PROCESS", "Listening for transmissions...");

	while (keep_running)
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
		seconds_since_start+= (long) ms_diff / 1000;

		DEBUG_PRINT("ms_diff: %f\n", ms_diff);
		if (ms_diff > send_interval_ms)
		{
			send_statistics(INTERVAL_TABLE, 1, 0);
			time_last = time_now;
			if (recv_bits == 0)
				continue;
		}

		if (recv_bits > 0)
		{
			//	Something has been received
			DEBUG_LOG("PROCESS", "Packet received...");
			if (process_traffic(recv_data) != EXIT_SUCCESS)
			{
				close(sock);
				destroy_tcp_buffer();
				return EXIT_FAILURE;
			}
		}
		else if (recv_bits < 0)
			break;
	}

	send_statistics(INTERVAL_TABLE, 1, 0);
	close(sock);
	destroy_tcp_buffer();
	return EXIT_SUCCESS;
}

int start_file_processing( PcapFilePtr file )
{
	assert(file != NULL);

	if (file->packet_count == 0)
		return EXIT_SUCCESS;

	if (create_tcp_buffer() != EXIT_SUCCESS)
		return EXIT_FAILURE;

	PcapPacketHeaderPtr header_last = &file->packets[0]->header;
	for (uint32_t i = 0; i < file->packet_count && keep_running; i++)
	{
		PcapPacketPtr packet = file->packets[i];

		//  Calculate time difference
		double s_diff = (packet->header.ts_sec - header_last->ts_sec);
		send_interval_current = (long) s_diff;
		seconds_since_start+= (long) s_diff;

		DEBUG_PRINT("s_diff: %f\n", s_diff);
		if (s_diff > send_interval && IS_FLAG_ACTIVE(FLAG_TIME))
		{
			send_statistics(INTERVAL_TABLE, 1, 0);
			header_last = &packet->header;
		}

		if (process_traffic(packet->data) != EXIT_SUCCESS)
		{
			destroy_tcp_buffer();
			return EXIT_FAILURE;
		}
	}

	send_statistics(INTERVAL_TABLE, 1, 0);
	destroy_tcp_buffer();
	return EXIT_SUCCESS;
}

short receive_data( int sock, uint8_t *data )
{
	assert(data != NULL);

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
	assert(data != NULL);

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
			//	TODO: Rather return than continue;?
			return EXIT_FAILURE;
		}

		print_tcp_header(packet);
		push_tcp_data(packet);
		uint16_t tcp_read = pop_tcp_data(packet);

		if (tcp_read > 0)
		{
			//  Parse DNS part of the packet
			DNSPacketPtr dns = parse_dns_packet(packet->data);
			if (dns == NULL)
			{
				destroy_tcp_packet(packet);
				return EXIT_FAILURE;
			}

			print_dns_packet(dns);

			//	Log traffic somehow
			process_dns_traffic(dns);

			//	DNS packet is no longer needed
			destroy_dns_packet(dns);
		}

		//	TCP packet is no longer needed
		destroy_tcp_packet(packet);

		return EXIT_SUCCESS;
	}
	else if (L4_protocol == UDP)
	{
		//  Parse headers
		UDPPacketPtr packet = parse_udp_packet(data);
		if (packet == NULL)
		{
			//	TODO: Rather return than continue;?
			return EXIT_FAILURE;
		}

		if (packet->udp_header->source == DNS_PORT)
		{
			DEBUG_LOG("PROCESS[UDP]", "Packet destination: DNS PORT...");

			//  Parse DNS part of the packet
			DNSPacketPtr dns = parse_dns_packet(packet->data);
			if (dns == NULL)
			{
				//	TODO: Rather return than continue;?
				destroy_dns_packet(dns);
				return EXIT_FAILURE;
			}

			print_dns_packet(dns);

			//	Log traffic somehow
			process_dns_traffic(dns);

			//	DNS packet is no longer needed
			destroy_dns_packet(dns);
		}
		else
		{
			DEBUG_LOG("PROCESS[UDP]", "Wrong packet source port...");
			DEBUG_PRINT("\tsrc: %d, dst: %d\n", packet->udp_header->source, packet->udp_header->dest);
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
		if (process_dns_resource_record(dns->answers[i]) != EXIT_SUCCESS)
		{
			//	TODO: Fail?
		}
	}

	for (int i = 0; i < dns->authority_count && DNS_PROCESS_AUTHORITIES; i++)
	{
		if (process_dns_resource_record(dns->authorities[i]) != EXIT_SUCCESS)
		{
			//	TODO: Fail?
		}
	}
}

int process_dns_resource_record( DNSResourceRecordPtr record )
{
	assert(entry_table != NULL);

	char *type = translate_dns_type(record->record_type);
	size_t entry_length = strlen(record->name) + 1 + strlen(type) + 1 + strlen(record->rdata); // +1s for whitespaces

	char *entry;
	char *entry_full;
	if (record->record_type == DNS_TYPE_A
	    || record->record_type == DNS_TYPE_AAAA
	    || record->record_type == DNS_TYPE_NS
	    || record->record_type == DNS_TYPE_CNAME
	    || record->record_type == DNS_TYPE_PTR)
	{
		entry = malloc(entry_length + 1); // +1 for '\0'
		if (entry == NULL)
		{
			ERR("Failed to allocate memory for resource record table key...\n");
			return EXIT_FAILURE;
		}
		sprintf(entry, "%s %s %s", record->name, type, record->rdata);

		entry_full = malloc(entry_length + 1); // +1 for '\0'
		if (entry_full == NULL)
		{
			ERR("Failed to allocate memory for resource record table key...\n");
			return EXIT_FAILURE;
		}
		sprintf(entry_full, "%s %s %s", record->name, type, record->rdata);
	}
	else
	{
		entry = malloc(entry_length + 3); // +1 for '\0', +2 for \"\"
		if (entry == NULL)
		{
			ERR("Failed to allocate memory for resource record table key...\n");
			return EXIT_FAILURE;
		}
		sprintf(entry, "%s %s \"%s\"", record->name, type, record->rdata);

		entry_full = malloc(entry_length + 3); // +1 for '\0', +2 for \"\"
		if (entry_full == NULL)
		{
			ERR("Failed to allocate memory for resource record table key...\n");
			return EXIT_FAILURE;
		}
		sprintf(entry_full, "%s %s \"%s\"", record->name, type, record->rdata);
	}

	/*
	printf("\33[2K\r");
	fprintf(stdout, "%s +1", entry);
	fflush(stdout);
	 */

	//  Do not free created items, item key will be freed before cleaning the table
	if (htIncrease(entry_table, entry) != ITEM_STATUS_CREATED)
		//  Free entry for *UPDATED* item
		free(entry);

	//  Do not free created items, item key will be freed before cleaning the table
	if (htIncrease(entry_table_full, entry_full) != ITEM_STATUS_CREATED)
		//  Free entry for *UPDATED* item
		free(entry_full);

	return EXIT_SUCCESS;
}

void send_statistics( tHTable *source_table, short clear_table, short force_print )
{
	assert(source_table != NULL);

	//  Send stats
	DEBUG_LOG("PROCESS", "Sending statistics...");

	//printf("\33[2K\r");
	if (IS_FLAG_ACTIVE(FLAG_SERVER) && force_print == 0)
	{
		htWalk(source_table, &entry_sender);
		syslog_buffer_flush(syslog);
	}
	else
	{
		if (source_table == FULL_TABLE)
		{
			fprintf(stdout, "=== DNS Traffic Statistics (last %ld minute(s) %ld second(s)) ===\n", seconds_since_start / 60, seconds_since_start % 60);
		}
		else
		{
			fprintf(stdout, "=== DNS Traffic Statistics (last %ld minute(s) %ld second(s)) ===\n", send_interval_current / 60, send_interval_current % 60);
		}

		htWalk(source_table, &entry_printer);
		fprintf(stdout, "\n");
	}

	if (clear_table == 1)
	{
		DEBUG_LOG("PROCESS", "Resetting table...");
		htClearAll(source_table);
	}
}
