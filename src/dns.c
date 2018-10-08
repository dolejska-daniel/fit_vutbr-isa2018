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


char *translate_dns_type( uint16_t type ) {
	static DNSRecordType types[] = {
			//	List from: https://en.wikipedia.org/wiki/List_of_DNS_record_types#Resource_records
			{ 1,	"A" }, // Address record
			{ 28,	"AAAA" }, // IPv6 address record
			{ 18,	"AFSDB" }, // AFS database record
			{ 42,	"APL" }, // Address Prefix List
			{ 257,	"CAA" }, // Certification Authority Authorization
			{ 60,	"CDNSKEY" }, //
			{ 59,	"CDS" }, // Child DS
			{ 37,	"CERT" }, // Certificate record
			{ 5,	"CNAME" }, // Canonical name record
			{ 49,	"DHCID" }, // DHCP identifier
			{ 32769,"DLV" }, // DNSSEC Lookaside Validation record
			{ 39,	"DNAME" }, //
			{ 48,	"DNSKEY" }, // DNS Key record
			{ 43,	"DS" }, // Delegation signer
			{ 55,	"HIP" }, // Host Identity Protocol
			{ 45,	"IPSECKEY" }, // IPsec Key
			{ 25,	"KEY" }, // Key record
			{ 36,	"KX" }, // Key Exchanger record
			{ 29,	"LOC" }, // Location record
			{ 15,	"MX" }, // Mail exchange record
			{ 35,	"NAPTR" }, // Naming Authority Pointer
			{ 2,	"NS" }, // Name server record
			{ 47,	"NSEC" }, // Next Secure record
			{ 50,	"NSEC3" }, // Next Secure record version 3
			{ 51,	"NSEC3PARAM" }, // NSEC3 parameters
			{ 61,	"OPENPGPKEY" }, // OpenPGP public key record
			{ 12,	"PTR" }, // Pointer record
			{ 46,	"RRSIG" }, // DNSSEC signature
			{ 17,	"RP" }, // Responsible Person
			{ 24,	"SIG" }, // Signature
			{ 6,	"SOA" }, // Start of [a zone of] authority record
			{ 33,	"SRV" }, // Service locator
			{ 44,	"SSHFP" }, // SSH Public Key Fingerprint
			{ 32768,"TA" }, // DNSSEC Trust Authorities
			{ 249,	"TKEY" }, // Transaction Key record
			{ 52,	"TLSA" }, // TLSA certificate association
			{ 250,	"TSIG" }, // Transaction Signature
			{ 16,	"TXT" }, // Text record
			{ 256,	"URI" }, // Uniform Resource Identifier
			//	List from: https://en.wikipedia.org/wiki/List_of_DNS_record_types#Other_types_and_pseudo_resource_records
			{ 255,	"*" }, // All cached records
			{ 252,	"AXFR" }, // Authoritative Zone Transfer
			{ 251,	"IXFR" }, // Incremental Zone Transfer
			{ 41,	"OPT" } // Option
	};

	for (int i = 0; i < 42; i++)
		if (types[i].type == type)
			return types[i].string;

	return "|?|";
}

void translate_dns_data( DNSResourceRecordPtr record, char **data )
{
	uint16_t len;
	switch (record->record_type)
	{
		case DNS_TYPE_A:
			*data = malloc(16);
			sprintf(*data, "%hu.%hu.%hu.%hu",
					record->rdata[0],
					record->rdata[1],
					record->rdata[2],
					record->rdata[3]);
			break;
		case DNS_TYPE_AAAA:
			*data = malloc(6);
			sprintf(*data, "IPV6!");
			break;
		case DNS_TYPE_KX:
		case DNS_TYPE_MX:
			/*  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                  PREFERENCE                   | 16bits integer
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				/                   EXCHANGE                    / domain-name
				/                                               /
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ */
			*data = malloc(4);
			sprintf(*data, "MX!");
			break;
		case DNS_TYPE_TA:
		case DNS_TYPE_DLV:
		case DNS_TYPE_DS:
			/* The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
			   Algorithm field, a 1 octet Digest Type field, and a Digest field.

									1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
				0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |           Key Tag             |  Algorithm    |  Digest Type  |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   /                                                               /
			   /                            Digest                             /
			   /                                                               /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
			*data = malloc(4);
			sprintf(*data, "DS!");
			break;
		case DNS_TYPE_SOA:
			/*  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				/                     MNAME                     /
				/                                               /
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				/                     RNAME                     /
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                    SERIAL                     |
				|                                               |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                    REFRESH                    |
				|                                               |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                     RETRY                     |
				|                                               |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                    EXPIRE                     |
				|                                               |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                    MINIMUM                    |
				|                                               |
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

			MNAME           The <domain-name> of the name server that was the
							original or primary source of data for this zone.

			RNAME           A <domain-name> which specifies the mailbox of the
							person responsible for this zone.

			SERIAL          The unsigned 32 bit version number of the original copy
							of the zone.  Zone transfers preserve this value.  This
							value wraps and should be compared using sequence space
							arithmetic.

			REFRESH         A 32 bit time interval before the zone should be
							refreshed.

			RETRY           A 32 bit time interval that should elapse before a
							failed refresh should be retried.

			EXPIRE          A 32 bit time value that specifies the upper limit on
							the time interval that can elapse before the zone is no
							longer authoritative.

			MINIMUM         The unsigned 32 bit minimum TTL field that should be
							exported with any RR from this zone. */
			*data = malloc(5);
			sprintf(*data, "SOA!");
			break;
		case DNS_TYPE_NSEC:
			/* The RDATA of the NSEC RR is as shown below:

									1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
				0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   /                      Next Domain Name                         /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   /                       Type Bit Maps                           /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
			*data = malloc(6);
			sprintf(*data, "NSEC!");
			break;
		case DNS_TYPE_NSEC3:
			/* The RDATA of the NSEC3 RR is as shown below:

									1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
				0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |   Hash Alg.   |     Flags     |          Iterations           |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |  Salt Length  |                     Salt                      /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |  Hash Length  |             Next Hashed Owner Name            /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   /                         Type Bit Maps                         /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			   Hash Algorithm is a single octet.

			   Flags field is a single octet, the Opt-Out flag is the least
			   significant bit, as shown below:

				0 1 2 3 4 5 6 7
			   +-+-+-+-+-+-+-+-+
			   |             |O|
			   +-+-+-+-+-+-+-+-+ */
			*data = malloc(7);
			sprintf(*data, "NSEC3!");
			break;
		case DNS_TYPE_RRSIG:
			/* The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
			   1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
			   TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
			   Inception field, a 2 octet Key tag, the Signer's Name field, and the
			   Signature field.

									1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
				0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |        Type Covered           |  Algorithm    |     Labels    |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |                         Original TTL                          |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |                      Signature Expiration                     |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |                      Signature Inception                      |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |            Key Tag            |                               /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
			   /                                                               /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   /                                                               /
			   /                            Signature                          /
			   /                                                               /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
			*data = malloc(7);
			sprintf(*data, "RRSIG!");
			break;
		case DNS_TYPE_DNSKEY:
		case DNS_TYPE_KEY:
			/* The RDATA for a DNSKEY RR consists of a 2 octet Flags Field, a 1
			   octet Protocol Field, a 1 octet Algorithm Field, and the Public Key
			   Field.

									1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
				0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |              Flags            |    Protocol   |   Algorithm   |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   /                                                               /
			   /                            Public Key                         /
			   /                                                               /
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
			*data = malloc(8);
			sprintf(*data, "DNSKEY!");
			break;
		case DNS_TYPE_NS: // FIXME: NS load_dns_string might be necessary
		case DNS_TYPE_TXT:
		case DNS_TYPE_SPF:
		default:
			if (record->rdata_length)
			{
				len = strlen((char *) record->rdata) + 1; // +1 because of '\0'
				*data = malloc(len);
				for(int i = 0; i < len; i++)
					(*data)[i] = record->rdata[i];

				//memcpy(data, record->rdata, len);
			}
			else
			{
				*data = malloc(4);
				(*data)[0] = '|';
				(*data)[1] = '?';
				(*data)[2] = '|';
				(*data)[3] = '\0';
			}
	}
}

void load_dns_string( char **destination, UDPPacketPtr packet, uint16_t *offset_ptr, uint16_t size, uint16_t *length_ptr )
{
	assert(destination != NULL);
	assert(*destination != NULL);
	assert(packet != NULL);
	assert(packet->data != NULL);
	assert(offset_ptr != NULL);
	assert(length_ptr != NULL);

    DEBUG_LOG("LOAD-DNS-STRING", "Loading string...");
	uint8_t data = 0;
	uint16_t length = *length_ptr;
	uint16_t offset = *offset_ptr;

	while (1)
	{
		data = *get_udp_packet_data_custom(packet, offset);
		offset+= sizeof(uint8_t);

		if (data == DNS_RECURSION_MASK)
		{
			//	Byte indicates string reference
			DEBUG_LOG("LOAD-DNS-STRING", "Is recursion...");

			//	Load label reference
			data = *get_udp_packet_data_custom(packet, offset);
			offset+= sizeof(uint8_t);

			uint16_t recursion_offset = data;
			load_dns_string(destination, packet, &recursion_offset, size, &length);
			break;
		}
		else
		{
			//	In this case, value of data indicates length of next label
			while (length + data + 1 > size) // +1 because '.' or '\0'
			{
				DEBUG_PRINT("%d bytes wont fit in %d, increasing to %d\n", length + data + 1, size, size * 2);
				//	Make sure, that there is enough space for the string
				*destination = realloc(*destination, size * 2);
				if (*destination == NULL)
                {
				    DEBUG_ERR("LOAD-DNS-STRING", "Failed to realloc string...");
				    perror("realloc");
				    return;
                }
				size*= 2;
			}

			//	Exit loop on label end
			if (data == '\0')
			{
				(*destination)[length] = data;
				break;
			}

			//	Separate labels by '.'
			if (length != 0)
				(*destination)[length++] = '.';

			//	Copy label to allocated string
			uint8_t c = 0;
			uint16_t label_len = 0;
			while (label_len < data)
			{
				//	Load data
				c = *get_udp_packet_data_custom(packet, offset);
				offset+= sizeof(uint8_t);

				//	Save data
				(*destination)[length + label_len] = c;

				label_len++;
			}
			length+= label_len;
		}
	}

	*length_ptr = length;
	*offset_ptr = offset;
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

	udp_packet->offset = get_dns_packet_head_size() - 4; // TODO: Kde se berou 4 bajty navíc??
	DEBUG_PRINT("offset location pre queryparse: %s\n", get_udp_packet_data_custom(udp_packet, udp_packet->offset));
	if (packet->question_count > 0)
	{
		packet->questions = malloc(packet->question_count * sizeof(DNSQueryPtr));
		for (int i = 0; i < packet->question_count; i++)
			packet->questions[i] = parse_dns_packet_query(udp_packet);
	}

	if (packet->answer_count > 0)
	{
		packet->answers = malloc(packet->answer_count * sizeof(DNSResourceRecordPtr));
		for (int i = 0; i < packet->answer_count; i++)
			packet->answers[i] = parse_dns_packet_resource_record(udp_packet);
	}

	if (packet->authority_count > 0 && DNS_PROCESS_AUTHORITIES)
	{
		packet->authorities = malloc(packet->authority_count * sizeof(DNSResourceRecordPtr));
		for (int i = 0; i < packet->authority_count; i++)
			packet->authorities[i] = parse_dns_packet_resource_record(udp_packet);
	}

	if (packet->additional_count > 0 && DNS_PROCESS_AUTHORITIES && DNS_PROCESS_ADDITIONALS)
	{
		packet->additionals = malloc(packet->additional_count * sizeof(DNSResourceRecordPtr));
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

	uint16_t name_length = 0;
	query->name = calloc(32, sizeof(char));
	load_dns_string(&query->name, udp_packet, &udp_packet->offset, 32, &name_length);

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

	uint16_t name_length = 0;
	record->name = calloc(32, sizeof(char));
	load_dns_string(&record->name, udp_packet, &udp_packet->offset, 32, &name_length);

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

	record->rdata = calloc(record->rdata_length, sizeof(uint8_t));
	if (record->rdata == NULL)
	{
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	if (record->record_type == DNS_TYPE_PTR
		|| record->record_type == DNS_TYPE_CNAME)
	{
		DEBUG_LOG("DNS-RECORD-PARSE", "Loading rdata by load_dns_string...");
		name_length = 0;
		load_dns_string((char **) &record->rdata, udp_packet, &udp_packet->offset, record->rdata_length, &name_length);
        DEBUG_PRINT("current contents: ");
        for (int i = 0; i < record->rdata_length; i++)
            DEBUG_PRINT("%#02x ", record->rdata[i]);
        DEBUG_PRINT("\n");
	}
	else
	{
		for (int i = 0; i < record->rdata_length; i++)
			record->rdata[i] = (udp_packet->data + udp_packet->offset)[i];
        udp_packet->offset+= record->rdata_length * sizeof(uint8_t);
	}

	DEBUG_LOG("DNS-RECORD-PARSE", "Returning...");
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

	if (packet->authority_count > 0 && DNS_PROCESS_AUTHORITIES)
	{
		for (int i = 0; i < packet->authority_count; i++)
			destroy_dns_packet_resource_record(packet->authorities[i]);
		free(packet->authorities);
	}

	if (packet->additional_count > 0 && DNS_PROCESS_AUTHORITIES && DNS_PROCESS_ADDITIONALS)
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

	if (DNS_PROCESS_AUTHORITIES)
	{
		fprintf(stderr, "DNS_Authorities:\n");
		for (int i = 0; i < packet->authority_count; i++)
			print_dns_packet_resource_record(packet->authorities[i]);

		if (DNS_PROCESS_ADDITIONALS)
		{
			fprintf(stderr, "DNS_Additionals:\n");
			for (int i = 0; i < packet->additional_count; i++)
				print_dns_packet_resource_record(packet->additionals[i]);
		}
	}
#endif
}

void print_dns_packet_query( DNSQueryPtr query )
{
#ifdef DEBUG_PRINT_ENABLED
	fprintf(
			stderr, "DNS_PACKET_QUERY: {\n\tname\t%s\n\ttype\t%d (%s)\n\tclass\t%#x (%s)\n}\n",
			query->name,
			query->record_type, translate_dns_type(query->record_type),
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
			record->record_type, translate_dns_type(record->record_type),
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
