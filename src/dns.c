// dns.c
// ISA, 03.10.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <arpa/inet.h>

#include "macros.h"
#include "network.h"
#include "dns.h"


void load_dns_string( char **destination, void *source, uint16_t *offset )
{
	assert(destination != NULL);
	assert(source != NULL);

	DEBUG_LOG("LOAD-DNS-STRING", "Loading string...");
	source+= 1; // +1 because of DNS string preface
	char *source_string = (char *) source;
	uint16_t length = strlen(source_string) + 1; // +1 because of '\0' char
	//	TODO: Zkusit načíst cyklem
	assert(length > 1);

	//	Allocate memory and move string
	DEBUG_LOG("LOAD-DNS-STRING", "Allocating memory...");
	char *dest = *destination = (char *) calloc(length, sizeof(char));
	if (dest == NULL)
	{
		perror("calloc");
		exit(EXIT_FAILURE);
	}

	DEBUG_LOG("LOAD-DNS-STRING", "Copying data...");
	memcpy(dest, (char *) source, length * sizeof(char));
	if (offset)
	{
		DEBUG_LOG("LOAD-DNS-STRING", "Setting offset...");
		*offset+= length * sizeof(char) + 1; // +1 because of '\0' char
	}

	//	Normalize string
	DEBUG_LOG("LOAD-DNS-STRING", "Normalizing...");
	int i = 0;
	do
	{
		assert(i < length);
		char c = dest[i++];

		if (c == '\0')
			break;

		if (isprint(c) == 0)
			dest[i - 1] = '.';
	}
	while (1);
	DEBUG_LOG("LOAD-DNS-STRING", "String loaded...");
}

uint16_t get_dns_string_length_recursive( UDPPacketPtr packet, uint16_t offset )
{
	DEBUG_LOG("GET-DNS-STRING-LEN", "Counting string length...");
	uint8_t data = 0;
	uint16_t length = 0;

	while (1)
	{
		DEBUG_LOG("GET-DNS-STRING-LEN", "Before get data...");
		DEBUG_PRINT("length: %d\n", length);
		data = get_udp_packet_data_custom(packet, offset)[length];
		if (data == DNS_RECURSION_MASK)
		{
			DEBUG_LOG("GET-DNS-STRING-LEN", "Is recursion...");
			data = get_udp_packet_data_custom(packet, offset)[length + 1];

			//	String is given by reference
			length+= get_dns_string_length_recursive(packet, get_dns_packet_head_size() + data);
		}
		else
		{
			DEBUG_LOG("GET-DNS-STRING-LEN", "Not recursion...");

			//	This might be the end of the string
			if (data == 0)
				break;

			//	String follows in given length
			length+= data + 1; // +1 to get to the next label length
		}
	}

	DEBUG_LOG("GET-DNS-STRING-LEN", "Returning...");
	DEBUG_PRINT("length: %d\n", length);
	return length;
}

void load_dns_string_recursive( char **destination, UDPPacketPtr packet, uint16_t *length_recursive )
{
	DEBUG_LOG("LOAD-DNS-STRING", "Counting string length...");
	uint8_t data = 0;
	uint16_t length = 0;

	while (1)
	{
		DEBUG_LOG("LOAD-DNS-STRING", "Before get data...");
		DEBUG_PRINT("length: %d\n", length);
		data = get_udp_packet_data_custom(packet, offset)[length];
		if (data == DNS_RECURSION_MASK)
		{
			DEBUG_LOG("LOAD-DNS-STRING", "Is recursion...");
			data = get_udp_packet_data_custom(packet, offset)[length + 1];

			//	String is given by reference
			length+= get_dns_string_length_recursive(packet, get_dns_packet_head_size() + data);
		}
		else
		{
			DEBUG_LOG("LOAD-DNS-STRING", "Not recursion...");

			//	This might be the end of the string
			if (data == 0)
				break;

			//	String follows in given length
			length+= data + 1; // +1 to get to the next label length
		}
	}

	DEBUG_LOG("LOAD-DNS-STRING", "Returning...");
	DEBUG_PRINT("length: %d\n", length);
	return length;
}

size_t get_dns_packet_head_size()
{
	return sizeof(DNSPacket) - sizeof(DNSQueryPtr *) - 3 * sizeof(DNSResourceRecordPtr *);
}

DNSPacketPtr parse_dns_packet( UDPPacketPtr udp_packet )
{
	DEBUG_LOG("DNS-PACKET-PARSE", "Parsing DNS packet...");
	DNSPacketPtr packet = (DNSPacketPtr) malloc(sizeof(DNSPacket));
	if (packet == NULL)
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	DNSPacketPtr data = (DNSPacketPtr) udp_packet->data;

	packet->transaction_id = ntohs(data->transaction_id);
	packet->flags          = ntohs(data->flags);

	packet->question_count   = ntohs(data->question_count);
	packet->answer_count     = ntohs(data->answer_count);
	packet->authority_count  = ntohs(data->authority_count);
	packet->additional_count = ntohs(data->additional_count);

	udp_packet->offset = get_dns_packet_head_size();
	if (packet->question_count > 0)
	{
		packet->questions = (DNSQueryPtr *) malloc(packet->question_count * sizeof(DNSQueryPtr));
		for (int i = 0; i < packet->question_count; i++)
			packet->questions[i] = parse_dns_packet_query(udp_packet);
	}

	if (packet->answer_count > 0)
	{
		packet->answers = (DNSResourceRecordPtr *) malloc(packet->answer_count * sizeof(DNSResourceRecordPtr));
		for (int i = 0; i < packet->answer_count; i++)
			packet->answers[i] = parse_dns_packet_resource_record(udp_packet);
	}

	if (packet->authority_count > 0)
	{
		packet->authorities = (DNSResourceRecordPtr *) malloc(packet->authority_count * sizeof(DNSResourceRecordPtr));
		for (int i = 0; i < packet->authority_count; i++)
			packet->authorities[i] = parse_dns_packet_resource_record(udp_packet);
	}

	if (packet->additional_count > 0)
	{
		packet->additionals = (DNSResourceRecordPtr *) malloc(packet->additional_count * sizeof(DNSResourceRecordPtr));
		for (int i = 0; i < packet->additional_count; i++)
			packet->additionals[i] = parse_dns_packet_resource_record(udp_packet);
	}

	return packet;
}

DNSQueryPtr parse_dns_packet_query( UDPPacketPtr udp_packet )
{
	DEBUG_LOG("DNS-QUERY-PARSE", "Parsing DNS query...");
	DNSQueryPtr query = (DNSQueryPtr) malloc(sizeof(DNSQuery));
	if (query == NULL)
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	load_dns_string_recursive(&query->name, udp_packet, NULL);
	//load_dns_string(&query->name, udp_packet->data + udp_packet->offset, &udp_packet->offset);

	memcpy(&query->record_type, udp_packet->data + udp_packet->offset, sizeof(uint16_t));
	query->record_type = ntohs(query->record_type);
	udp_packet->offset+= sizeof(uint16_t);

	memcpy(&query->record_class, udp_packet->data + udp_packet->offset, sizeof(uint16_t));
	query->record_class = ntohs(query->record_class);
	udp_packet->offset+= sizeof(uint16_t);

	return query;
}

DNSResourceRecordPtr parse_dns_packet_resource_record( UDPPacketPtr udp_packet )
{
	DEBUG_LOG("DNS-RECORD-PARSE", "Parsing DNS resource record...");
	DNSResourceRecordPtr record = (DNSResourceRecordPtr) malloc(sizeof(DNSResourceRecord));
	if (record == NULL)
	{
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	load_dns_string_recursive(&record->name, udp_packet, NULL);

	/*
	uint16_t name_offset;
	memcpy(&name_offset, udp_packet->data + udp_packet->offset, sizeof(uint16_t));
	name_offset = ntohs(name_offset);
	udp_packet->offset+= sizeof(uint16_t);
	name_offset^= 0b11 << 14; // DNS offset for Resource Record name
	load_dns_string(&record->name, udp_packet->data + name_offset * sizeof(uint8_t), NULL); // -1 because we ignore the initial DNS name string preface later
	 */
	DEBUG_PRINT("&record->name: %p\n", &record->name);
	DEBUG_PRINT("record->name: '%s'\n", record->name);

	memcpy(&record->record_type, udp_packet->data + udp_packet->offset, sizeof(uint16_t));
	record->record_type = ntohs(record->record_type);
	udp_packet->offset+= sizeof(uint16_t);

	memcpy(&record->record_class, udp_packet->data + udp_packet->offset, sizeof(uint16_t));
	record->record_class = ntohs(record->record_class);
	udp_packet->offset+= sizeof(uint16_t);

	memcpy(&record->ttl, udp_packet->data + udp_packet->offset, sizeof(uint32_t));
	record->ttl = ntohl(record->ttl);
	udp_packet->offset+= sizeof(uint32_t);

	memcpy(&record->rdata_length, udp_packet->data + udp_packet->offset, sizeof(uint16_t));
	record->rdata_length = ntohs(record->rdata_length);
	udp_packet->offset+= sizeof(uint16_t);

	DEBUG_LOG("DNS-RECORD-PARSE", "Before rdata...");
	DEBUG_PRINT("&record->name: %p\n", &record->name);
	DEBUG_PRINT("record->name: '%s'\n", record->name);
	DEBUG_PRINT("record->rdata_length: %d\n", record->rdata_length);

	record->rdata = (uint8_t *) calloc(record->rdata_length, sizeof(uint8_t));
	if (record->rdata == NULL)
	{
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	DEBUG_PRINT("&record->rdata: %p\n", &record->rdata);
	DEBUG_PRINT("record->rdata: %p\n", record->rdata);
	if (record->record_type == DNS_TYPE_PTR
		|| record->record_type == DNS_TYPE_CNAME)
	{
		DEBUG_LOG("DNS-RECORD-PARSE", "Loading rdata by load_dns_string...");
		load_dns_string((char **) &record->rdata, udp_packet->data + udp_packet->offset, &udp_packet->offset);
	}
	else
	{
		for (int i = 0; i < record->rdata_length; i++)
			record->rdata[i] = (udp_packet->data + udp_packet->offset)[i];
	}
	//memcpy(&record->rdata, udp_packet->data + udp_packet->offset, record->rdata_length * sizeof(uint8_t)); // 	FIXME: KOKOTINA ROZMRDÁVÁ STRINGY
	udp_packet->offset+= record->rdata_length * sizeof(uint8_t);

	DEBUG_LOG("DNS-RECORD-PARSE", "Before return...");
	DEBUG_PRINT("&record->rdata: %p\n", &record->rdata);
	DEBUG_PRINT("record->rdata: %p\n", record->rdata);
	DEBUG_PRINT("&record->name: %p\n", &record->name);
	DEBUG_PRINT("record->name: '%s'\n", record->name);

	return record;
}

void destroy_dns_packet( DNSPacketPtr packet )
{
	assert(packet != NULL);
	DEBUG_LOG("DNS-PACKET-DESTROY", "Destroying DNS packet...");

	if (packet->question_count > 0)
	{
		for (int i = 0; i < packet->question_count; i++)
			destroy_dns_packet_query(packet->questions[i]);
		free(packet->questions);
	}

	if (packet->answer_count > 0)
	{
		for (int i = 0; i < packet->answer_count; i++)
			destroy_dns_packet_resource_record(packet->answers[i]);
		free(packet->answers);
	}

	if (packet->authority_count > 0)
	{
		for (int i = 0; i < packet->authority_count; i++)
			destroy_dns_packet_resource_record(packet->authorities[i]);
		free(packet->authorities);
	}

	if (packet->additional_count > 0)
	{
		for (int i = 0; i < packet->additional_count; i++)
			destroy_dns_packet_resource_record(packet->additionals[i]);
		free(packet->additionals);
	}

	free(packet);
}

void destroy_dns_packet_query( DNSQueryPtr query )
{
	assert(query != NULL);
	DEBUG_LOG("DNS-QUERY-DESTROY", "Destroying DNS query...");

	free(query->name);
	free(query);
}

void destroy_dns_packet_resource_record( DNSResourceRecordPtr record )
{
	assert(record != NULL);
	DEBUG_LOG("DNS-RECORD-DESTROY", "Destroying DNS resource record...");

	free(record->name);
	free(record->rdata);
	free(record);
}

void print_dns_packet( DNSPacketPtr packet )
{
#ifdef DEBUG_PRINT_ENABLED
	fprintf(
			stderr,
			"DNS_PACKET: {\n\ttransaction_id\t%#x\n\tflags\t\t%#x\n\tQR\t\t%d\n\tOpcode\t\t%d\n\tAA\t\t%d\n\tTC\t\t%d\n\tED\t\t%d\n\tRA\t\t%d\n\treturn_code\t%d\n\tquestion_count\t\t%u\n\tanswer_count\t\t%u\n\tauthority_count\t\t%u\n\tadditional_count\t%u\n}\n",
			packet->transaction_id,
			packet->flags,
			GET_DNS_FLAG_VALUE1B(packet->flags, DNS_FLAG_QR),
			GET_DNS_FLAG_VALUE4B(packet->flags, DNS_FLAG_OPCODE),
			GET_DNS_FLAG_VALUE1B(packet->flags, DNS_FLAG_AA),
			GET_DNS_FLAG_VALUE1B(packet->flags, DNS_FLAG_TC),
			GET_DNS_FLAG_VALUE1B(packet->flags, DNS_FLAG_RD),
			GET_DNS_FLAG_VALUE1B(packet->flags, DNS_FLAG_RA),
			GET_DNS_FLAG_VALUE4B(packet->flags, DNS_FLAG_RCODE),
			packet->question_count,
			packet->answer_count,
			packet->authority_count,
			packet->additional_count
	);

	fprintf(stderr, "DNS_Questions:\n");
	for (int i = 0; i < packet->question_count; i++)
		print_dns_packet_query(packet->questions[i]);

	fprintf(stderr, "DNS_Answers:\n");
	for (int i = 0; i < packet->answer_count; i++)
		print_dns_packet_resource_record(packet->answers[i]);

	fprintf(stderr, "DNS_Authorities:\n");
	for (int i = 0; i < packet->authority_count; i++)
		print_dns_packet_resource_record(packet->authorities[i]);

	fprintf(stderr, "DNS_Additionals:\n");
	for (int i = 0; i < packet->additional_count; i++)
		print_dns_packet_resource_record(packet->additionals[i]);
#endif
}

void print_dns_packet_query( DNSQueryPtr query )
{
#ifdef DEBUG_PRINT_ENABLED
	fprintf(
			stderr, "DNS_PACKET_QUERY: {\n\tname\t%s\n\ttype\t%d (%s)\n\tclass\t%#x (%s)\n}\n",
			query->name,
			query->record_type, "-",
			query->record_class, "-"
	);
#endif
}

void print_dns_packet_resource_record( DNSResourceRecordPtr record )
{
#ifdef DEBUG_PRINT_ENABLED
	fprintf(
			stderr, "DNS_PACKET_RESOURCE_RECORD: {\n\tname\t%s\n\ttype\t%d (%s)\n\tclass\t%#x (%s)\n\tttl\t%d\n\trdata_length\t%d\n}\n",
			record->name,
			record->record_type, "-",
			record->record_class, "-",
			record->ttl,
			record->rdata_length
	);
	if (record->record_type == DNS_TYPE_A)
	{
		fprintf(
				stderr, "DNS_PACKET_RESOURCE_RECORD_DATA (IPv4): %hu.%hu.%hu.%hu\n",
				record->rdata[0],
				record->rdata[1],
				record->rdata[2],
				record->rdata[3]
		);
	}
	else if (record->record_type == DNS_TYPE_AAAA)
	{
		fprintf(
				stderr, "DNS_PACKET_RESOURCE_RECORD_DATA (IPv6): ?\n"
		);
	}
	else if (record->record_type == DNS_TYPE_CNAME || record->record_type == DNS_TYPE_PTR || record->record_type == DNS_TYPE_TXT)
	{
		fprintf(
				stderr, "DNS_PACKET_RESOURCE_RECORD_DATA (%s): '%s'\n",
				record->record_type == DNS_TYPE_CNAME ? "CNAME" : record->record_type == DNS_TYPE_PTR ? "PTR" : "TXT",
				record->rdata
		);
	}
#endif
}
