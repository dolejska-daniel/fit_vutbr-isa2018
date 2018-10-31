// dns.c
// ISA, 03.10.2018
// Author: Daniel Dolejska, FIT

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <arpa/inet.h>

#include "macros.h"
#include "network.h"
#include "dns.h"
#include "base64.h"


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

	return "*?*";
}

int load_resource_record_data( PacketDataPtr pdata, DNSResourceRecordPtr record )
{
	DEBUG_LOG("DNS-RECORD-PARSE", "Loading rdata...");
	uint16_t len;
	switch (record->record_type)
	{
		case DNS_TYPE_A:
			{
				record->rdata = malloc(INET_ADDRSTRLEN);
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for A resource record data...");
					perror("malloc");
					return EXIT_FAILURE;
				}

				inet_ntop(AF_INET, get_packet_data(pdata), record->rdata, INET_ADDRSTRLEN);
			}
			break;
		case DNS_TYPE_AAAA:
			{
				record->rdata = malloc(INET6_ADDRSTRLEN);
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for AAAA resource record data...");
					perror("malloc");
					return EXIT_FAILURE;
				}

				inet_ntop(AF_INET6, get_packet_data(pdata), record->rdata, INET6_ADDRSTRLEN);
			}
			break;
		case DNS_TYPE_NS:
		case DNS_TYPE_PTR:
		case DNS_TYPE_CNAME:
			{
				record->rdata = malloc(32 * sizeof(char));
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for NS/PTR/CNAME resource record data...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				uint16_t domain_name_length = 0;
				uint16_t offset = pdata->offset;
				load_domain_name(&record->rdata, pdata, &offset, 32, &domain_name_length);
			}
			break;
		case DNS_TYPE_SRV:
			{
				/*  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
					|                   PRIORITY                    | 16bits integer
				    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
					|                    WEIGHT                     | 16bits integer
				    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
					|                     PORT                      | 16bits integer
					+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
					/                    TARGET                     / domain-name
					/                                               /
					+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ */

				uint16_t offset = pdata->offset;
				uint16_t priority = ntohs(*((uint16_t*) get_packet_data(pdata))); offset+= sizeof(uint16_t);
				uint16_t weight   = ntohs(*((uint16_t*) get_packet_data(pdata))); offset+= sizeof(uint16_t);
				uint16_t port     = ntohs(*((uint16_t*) get_packet_data(pdata))); offset+= sizeof(uint16_t);

				char *target = malloc(32 * sizeof(char));
				if (target == NULL)
				{
					ERR("Failed to allocate memory for SRV resource record target...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				uint16_t target_length = 0;
				load_domain_name(&target, pdata, &offset, 32, &target_length);

				record->rdata = malloc(3 * UINT16_STRLEN + target_length + 4); // +3 whitespace, +1 '\0'
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for SRV resource record data...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				sprintf(record->rdata, "%d %d %d %s", priority, weight, port, target);
				free(target);
			}
			break;
		case DNS_TYPE_KX:
		case DNS_TYPE_MX:
			/*  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				|                  PREFERENCE                   | 16bits integer
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				/                   EXCHANGE                    / domain-name
				/                                               /
				+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ */
			{
				uint16_t offset = pdata->offset;
				uint16_t preference = ntohs(*((uint16_t*) get_packet_data(pdata))); offset+= sizeof(uint16_t);

				char *exchange = malloc(32 * sizeof(char));
				if (exchange == NULL)
				{
					ERR("Failed to allocate memory for KX/MX resource record exchange...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				uint16_t exchange_length = 0;
				load_domain_name(&exchange, pdata, &offset, 32, &exchange_length);

				record->rdata = malloc(UINT16_STRLEN + exchange_length + 2); // +1 whitespace, +1 '\0'
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for KX/MX resource record data...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				sprintf(record->rdata, "%d %s", preference, exchange);
				free(exchange);
			}
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
			{
				uint16_t offset = pdata->offset;

				uint16_t key_tag     = ntohs(*((uint16_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint16_t);
				uint8_t  algorithm   = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);
				uint8_t  digest_type = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);

				uint16_t digest_length = record->rdata_length - (offset - pdata->offset);
				uint8_t *digest = malloc(digest_length * sizeof(uint8_t));
				if (digest == NULL)
				{
					ERR("Failed to allocate memory for TA/DLV/DS resource record digest...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				for (uint16_t i = 0; i < digest_length; i++)
					digest[i] = get_packet_data_custom(pdata, offset)[i];

				uint16_t digest_encoded_length = digest_length * 2 + 1;
				char *digest_encoded = malloc(digest_encoded_length * sizeof(char));
				for (int i = 0; i < digest_length; i++)
					sprintf(digest_encoded + i * 2, "%02X", digest[i]);

				//  Allocate string and paste data
				record->rdata = malloc(2 * UINT8_STRLEN + UINT16_STRLEN + digest_encoded_length);
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for TA/DLV/DS resource record data...");
					perror("malloc");
					free(digest);
					return EXIT_FAILURE;
				}
				sprintf(record->rdata, "%d %d %d %s", key_tag, algorithm, digest_type, digest_encoded);

				free(digest);
				free(digest_encoded);
			}
			break;
		case DNS_TYPE_SOA:
			/*  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
				/                     MNAME                     /
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
			{
				uint16_t offset = pdata->offset;

				//  MNAME
				char *mname = malloc(32 * sizeof(char));
				if (mname == NULL)
				{
					ERR("Failed to allocate memory for SOA resource record mname...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				uint16_t mname_length = 0;
				load_domain_name(&mname, pdata, &offset, 32, &mname_length);

				//  RNAME
				char *rname = malloc(32 * sizeof(char));
				if (rname == NULL)
				{
					ERR("Failed to allocate memory for SOA resource record rname...");
					perror("malloc");
					free(mname);
					return EXIT_FAILURE;
				}
				uint16_t rname_length = 0;
				load_domain_name(&rname, pdata, &offset, 32, &rname_length);

				//  SERIAL, REFRESH, ...
				int serial  = (int)ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(int);
				int refresh = (int)ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(int);
				int retry   = (int)ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(int);
				int expire  = (int)ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(int);
				int minimum = (int)ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset)));


				record->rdata = malloc(mname_length + rname_length + 5 * UINT32_STRLEN + 7); //  +7 = 6 spaces, 1 '\0'
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for SOA resource record data...");
					perror("malloc");
					free(mname);
					free(rname);
					return EXIT_FAILURE;
				}

				//  Paste all data to allocated string
				sprintf(record->rdata, "%s %s %d %d %d %d %d", mname, rname, serial, refresh, retry, expire, minimum);
				free(mname);
				free(rname);
			}
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
			{
				uint16_t offset = pdata->offset;

				char *next_domain_name = malloc(32 * sizeof(char));
				if (next_domain_name == NULL)
				{
					ERR("Failed to allocate memory for NSEC resource record next domain name...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				uint16_t next_domain_name_length = 0;
				load_domain_name(&next_domain_name, pdata, &offset, 32, &next_domain_name_length);


				//  TODO: skip domain name & parse type bit maps?


				record->rdata = malloc(next_domain_name_length + 1 + strlen("*TYPES*") + 1); //  +1 whitespace, +1 '\0'
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for NSEC resource record data...");
					perror("malloc");
					free(next_domain_name);
					return EXIT_FAILURE;
				}

				sprintf(record->rdata, "%s *TYPES*", next_domain_name);
				free(next_domain_name);
			}
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
			{
				uint16_t offset = pdata->offset;

				uint8_t  algorithm  = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);
				uint8_t  flags      = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);
				uint16_t iterations = ntohs(*((uint16_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint16_t);


				//  TODO: parse alt?
				//  TODO: parse hashed owner name?
				//  TODO: parse type bit maps?


				record->rdata = malloc(2 * UINT8_STRLEN + UINT16_STRLEN + 3); //  +3 = +2 whitespace, +1 '\0'
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for NSEC3 resource record data...");
					perror("malloc");
					return EXIT_FAILURE;
				}

				sprintf(record->rdata, "%d %d %d *SALT* *HASHED_OWNER_NAME* *TYPES*", algorithm, flags, iterations);
			}
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
			{
				uint16_t offset = pdata->offset;

				uint16_t type_covered = ntohs(*((uint16_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint16_t);
				uint8_t  algorithm    = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);
				uint8_t  labels       = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);
				uint32_t ttl          = ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint32_t);
				uint32_t expiration   = ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint32_t);
				uint32_t inception    = ntohl(*((uint32_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint32_t);
				uint16_t key_tag      = ntohs(*((uint16_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint16_t);

				char *signer = malloc(32 * sizeof(char));
				if (signer == NULL)
				{
					ERR("Failed to allocate memory for RRSIG resource record signer...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				uint16_t signer_length = 0;
				load_domain_name(&signer, pdata, &offset, 32, &signer_length);

				uint16_t signature_length = record->rdata_length - (offset - pdata->offset);
				uint8_t *signature = malloc(signature_length * sizeof(uint8_t));
				if (signature == NULL)
				{
					ERR("Failed to allocate memory for RRSIG resource record signature...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				for (uint16_t i = 0; i < signature_length; i++)
					signature[i] = get_packet_data_custom(pdata, offset)[i];

				uint16_t signature_encoded_length = Base64encode_len(signature_length);
				char *signature_encoded = malloc(signature_encoded_length * sizeof(char));
				Base64encode(signature_encoded, (char *)signature, (int)signature_length);

				//  Allocate string and paste data
				record->rdata = malloc(3 * UINT8_STRLEN + UINT16_STRLEN + 3 * UINT32_STRLEN + signer_length + signature_encoded_length);
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for RRSIG resource record data...");
					perror("malloc");
					free(signer);
					free(signature);
					return EXIT_FAILURE;
				}
				sprintf(record->rdata, "%s %d %d %d %d %d %d %s %s", translate_dns_type(type_covered), algorithm, labels, ttl, expiration, inception, key_tag, signer, signature_encoded);

				free(signer);
				free(signature);
				free(signature_encoded);
			}
			break;
		case DNS_TYPE_KEY:
		case DNS_TYPE_DNSKEY:
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
			{
				uint16_t offset = pdata->offset;

				uint16_t flags     = ntohs(*((uint16_t *) get_packet_data_custom(pdata, offset))); offset+= sizeof(uint16_t);
				uint8_t  protocol  = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);
				uint8_t  algorithm = *get_packet_data_custom(pdata, offset); offset+= sizeof(uint8_t);

				uint16_t signature_length = record->rdata_length - (offset - pdata->offset);
				uint8_t *signature = malloc(signature_length * sizeof(uint8_t));
				if (signature == NULL)
				{
					ERR("Failed to allocate memory for KEY/DNSKEY resource record signature...");
					perror("malloc");
					return EXIT_FAILURE;
				}
				for (uint16_t i = 0; i < signature_length; i++)
					signature[i] = get_packet_data_custom(pdata, offset)[i];

				uint16_t signature_encoded_length = Base64encode_len(signature_length);
				char *signature_encoded = malloc(signature_encoded_length * sizeof(char));
				Base64encode(signature_encoded, (char *)signature, (int)signature_length);

				//  Allocate string and paste data
				record->rdata = malloc(2 * UINT8_STRLEN + UINT16_STRLEN + signature_encoded_length);
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for KEY/DNSKEY resource record data...");
					perror("malloc");
					free(signature);
					return EXIT_FAILURE;
				}
				sprintf(record->rdata, "%d %d %d %s", flags, protocol, algorithm, signature_encoded);

				free(signature);
				free(signature_encoded);
			}
			break;
		case DNS_TYPE_SPF:
		case DNS_TYPE_TXT:
			{
				len = (uint16_t)(strlen((char *) get_packet_data(pdata)) + 1); // +1 '\0'
				record->rdata = malloc(len);
				if (record->rdata == NULL)
				{
					ERR("Failed to allocate memory for SPF/TXT resource record data...");
					perror("malloc");
					return EXIT_FAILURE;
				}

				for(int i = 0; i < len; i++)
					(record->rdata)[i] = get_packet_data(pdata)[i];
			}
			break;
		default:
			{
				char *str = "***UNSUPPORTED DNS RECORD***";
				record->rdata = malloc(strlen(str) + 1);
				strcpy(record->rdata, str);
			}
	}
	return EXIT_SUCCESS;
}

void load_domain_name( char **destination, PacketDataPtr pdata, uint16_t *offset_ptr, uint16_t size, uint16_t *length_ptr )
{
	assert(destination != NULL);
	assert(*destination != NULL);
	assert(pdata != NULL);
	assert(pdata->data != NULL);
	assert(offset_ptr != NULL);
	assert(length_ptr != NULL);

    DEBUG_LOG("LOAD-DNS-STRING", "Loading string...");
	uint8_t data = 0;
	uint16_t length = *length_ptr;
	uint16_t offset = *offset_ptr;

	while (1)
	{
		data = *get_packet_data_custom(pdata, offset);
		offset+= sizeof(uint8_t);

		if ((data & DNS_RECURSION_MASK) == DNS_RECURSION_MASK)
		{
			//	Byte indicates string reference
			DEBUG_LOG("LOAD-DNS-STRING", "Is recursion...");

			//	Load label reference
			uint16_t recursion_offset = *((uint16_t *) get_packet_data_custom(pdata, offset - sizeof(uint8_t)));
			//  Remove first two bits
			recursion_offset^= (DNS_RECURSION_MASK);
			//  Convert from network byte order
			recursion_offset = ntohs(recursion_offset);

			DEBUG_PRINT("\trecusrion_offset: %u (%#4x)\n", recursion_offset, recursion_offset);

			offset+= sizeof(uint8_t);
			load_domain_name(destination, pdata, &recursion_offset, size, &length);
			break;
		}
		else
		{
			//	In this case, value of data indicates length of next label
			while (length + data + 2 > size) // +1 because '.' or '\0' or both
			{
				DEBUG_PRINT("%d bytes wont fit in %d, increasing to %d\n", length + data + 1, size, size * 2);
				//	Make sure, that there is enough space for the string
				size*= 2;
				*destination = realloc(*destination, size);
				if (*destination == NULL)
                {
				    ERR("Failed to realloc domain name...");
				    perror("realloc");
				    return;
                }
			}

			//	Separate labels by '.'
			if (length != 0)
				(*destination)[length++] = '.';

			//	Exit loop on label end
			if (data == '\0')
			{
				(*destination)[length] = data;
				break;
			}

			//	Copy label to allocated string
			uint8_t c = 0;
			uint16_t label_len = 0;
			while (label_len < data)
			{
				//	Load data
				c = *get_packet_data_custom(pdata, offset);
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

DNSPacketPtr parse_dns_packet( PacketDataPtr pdata )
{
	DEBUG_LOG("DNS-PACKET-PARSE", "Parsing DNS packet...");
	DNSPacketPtr packet = (DNSPacketPtr) malloc(sizeof(DNSPacket));
	if (packet == NULL)
	{
		ERR("Failed to allocate memory for DNS packet...");
		perror("malloc");
		return NULL;
	}
	memset(packet, 0, sizeof(DNSPacket));

	DNSPacketPtr data = (DNSPacketPtr) get_packet_data(pdata);

	packet->transaction_id = ntohs(data->transaction_id);
	packet->flags          = ntohs(data->flags);

	packet->question_count   = ntohs(data->question_count);
	packet->answer_count     = ntohs(data->answer_count);
	packet->authority_count  = ntohs(data->authority_count);
	packet->additional_count = ntohs(data->additional_count);

	//  UDP??
	pdata->offset = get_dns_packet_head_size() - 4; // TODO: Kde se berou 4 bajty navíc??

	DEBUG_PRINT("offset location pre queryparse: %s\n", get_packet_data_custom(pdata, pdata->offset));
	if (packet->question_count > 0)
	{
		packet->questions = malloc(packet->question_count * sizeof(DNSQueryPtr));
		if (packet->questions == NULL)
		{
			ERR("Failed to allocate memory for DNS packet questions...");
			perror("malloc");
			destroy_dns_packet(packet);
			return NULL;
		}
		memset(packet->questions, 0, packet->question_count * sizeof(DNSQueryPtr));

		for (int i = 0; i < packet->question_count; i++)
			packet->questions[i] = parse_dns_packet_query(pdata);
	}

	if (packet->answer_count > 0)
	{
		packet->answers = malloc(packet->answer_count * sizeof(DNSResourceRecordPtr));
		if (packet->answers == NULL)
		{
			ERR("Failed to allocate memory for DNS packet answers...");
			perror("malloc");
			destroy_dns_packet(packet);
			return NULL;
		}
		memset(packet->answers, 0, packet->answer_count * sizeof(DNSResourceRecordPtr));

		for (int i = 0; i < packet->answer_count; i++)
			packet->answers[i] = parse_dns_packet_resource_record(pdata);
	}

	if (packet->authority_count > 0 && DNS_PROCESS_AUTHORITIES)
	{
		packet->authorities = malloc(packet->authority_count * sizeof(DNSResourceRecordPtr));
		if (packet->authorities == NULL)
		{
			ERR("Failed to allocate memory for DNS packet authorities...");
			perror("malloc");
			destroy_dns_packet(packet);
			return NULL;
		}
		memset(packet->authorities, 0, packet->authority_count * sizeof(DNSResourceRecordPtr));

		for (int i = 0; i < packet->authority_count; i++)
			packet->authorities[i] = parse_dns_packet_resource_record(pdata);
	}

	if (packet->additional_count > 0 && DNS_PROCESS_AUTHORITIES && DNS_PROCESS_ADDITIONALS)
	{
		packet->additionals = malloc(packet->additional_count * sizeof(DNSResourceRecordPtr));
		if (packet->additionals == NULL)
		{
			ERR("Failed to allocate memory for DNS packet additionals...");
			perror("malloc");
			destroy_dns_packet(packet);
			return NULL;
		}
		memset(packet->additionals, 0, packet->additional_count * sizeof(DNSResourceRecordPtr));

		for (int i = 0; i < packet->additional_count; i++)
			packet->additionals[i] = parse_dns_packet_resource_record(pdata);
	}

	return packet;
}

DNSQueryPtr parse_dns_packet_query( PacketDataPtr pdata )
{
	DEBUG_LOG("DNS-QUERY-PARSE", "Parsing DNS query...");
	DNSQueryPtr query = (DNSQueryPtr) malloc(sizeof(DNSQuery));
	if (query == NULL)
	{
		ERR("Failed to allocate memory for DNS packet query...");
		perror("malloc");
		return NULL;
	}

	uint16_t name_length = 0;
	query->name = malloc(32 * sizeof(char));
	if (query->name == NULL)
	{
		ERR("Failed to allocate memory for DNS packet query domain name...");
		perror("malloc");
		destroy_dns_packet_query(query);
		return NULL;
	}
	load_domain_name(&query->name, pdata, &pdata->offset, 32, &name_length);

	memcpy(&query->record_type, get_packet_data(pdata), sizeof(uint16_t));
	query->record_type = ntohs(query->record_type);
	pdata->offset+= sizeof(uint16_t);

	memcpy(&query->record_class, get_packet_data(pdata), sizeof(uint16_t));
	query->record_class = ntohs(query->record_class);
	pdata->offset+= sizeof(uint16_t);

	return query;
}

DNSResourceRecordPtr parse_dns_packet_resource_record( PacketDataPtr pdata )
{
	DEBUG_LOG("DNS-RECORD-PARSE", "Parsing DNS resource record...");
	DNSResourceRecordPtr record = (DNSResourceRecordPtr) malloc(sizeof(DNSResourceRecord));
	if (record == NULL)
	{
		ERR("Failed to allocate memory for DNS packet resource record...");
		perror("malloc");
		return NULL;
	}

	uint16_t name_length = 0;
	record->name = malloc(32 * sizeof(char));
	if (record->name == NULL)
	{
		ERR("Failed to allocate memory for DNS packet resource record domain name...");
		perror("malloc");
		destroy_dns_packet_resource_record(record);
		return NULL;
	}
	load_domain_name(&record->name, pdata, &pdata->offset, 32, &name_length);

	memcpy(&record->record_type, get_packet_data(pdata), sizeof(uint16_t));
	record->record_type = ntohs(record->record_type);
	pdata->offset+= sizeof(uint16_t);

	memcpy(&record->record_class, get_packet_data(pdata), sizeof(uint16_t));
	record->record_class = ntohs(record->record_class);
	pdata->offset+= sizeof(uint16_t);

	memcpy(&record->ttl, get_packet_data(pdata), sizeof(uint32_t));
	record->ttl = ntohl(record->ttl);
	pdata->offset+= sizeof(uint32_t);

	memcpy(&record->rdata_length, get_packet_data(pdata), sizeof(uint16_t));
	record->rdata_length = ntohs(record->rdata_length);
	pdata->offset+= sizeof(uint16_t);

	if (load_resource_record_data(pdata, record) != EXIT_SUCCESS)
	{
		destroy_dns_packet_resource_record(record);
		return NULL;
	}
	pdata->offset+= record->rdata_length;

	DEBUG_LOG("DNS-RECORD-PARSE", "Returning...");
	return record;
}

void destroy_dns_packet( DNSPacketPtr packet )
{
	assert(packet != NULL);
	DEBUG_LOG("DNS-PACKET-DESTROY", "Destroying DNS packet...");

	if (packet->question_count > 0 && packet->questions != NULL)
	{
		for (int i = 0; i < packet->question_count; i++)
			if (packet->questions[i] != NULL) destroy_dns_packet_query(packet->questions[i]);
		free(packet->questions);
	}

	if (packet->answer_count > 0 && packet->answers != NULL)
	{
		for (int i = 0; i < packet->answer_count; i++)
			if (packet->answers[i] != NULL) destroy_dns_packet_resource_record(packet->answers[i]);
		free(packet->answers);
	}

	if (packet->authority_count > 0 && packet->authorities != NULL && DNS_PROCESS_AUTHORITIES)
	{
		for (int i = 0; i < packet->authority_count; i++)
			if (packet->authorities[i] != NULL) destroy_dns_packet_resource_record(packet->authorities[i]);
		free(packet->authorities);
	}

	if (packet->additional_count > 0 && packet->additionals != NULL && DNS_PROCESS_AUTHORITIES && DNS_PROCESS_ADDITIONALS)
	{
		for (int i = 0; i < packet->additional_count; i++)
			if (packet->additionals[i] != NULL) destroy_dns_packet_resource_record(packet->additionals[i]);
		free(packet->additionals);
	}

	free(packet);
}

void destroy_dns_packet_query( DNSQueryPtr query )
{
	assert(query != NULL);
	DEBUG_LOG("DNS-QUERY-DESTROY", "Destroying DNS query...");

	if (query->name != NULL)
		free(query->name);
	free(query);
}

void destroy_dns_packet_resource_record( DNSResourceRecordPtr record )
{
	assert(record != NULL);
	DEBUG_LOG("DNS-RECORD-DESTROY", "Destroying DNS resource record...");

	if (record->name != NULL)
		free(record->name);
	if (record->rdata != NULL)
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
	for (int i = 0; i < packet->question_count && packet->questions != NULL; i++)
		print_dns_packet_query(packet->questions[i]);

	fprintf(stderr, "DNS_Answers:\n");
	for (int i = 0; i < packet->answer_count && packet->answers != NULL; i++)
		print_dns_packet_resource_record(packet->answers[i]);

	if (DNS_PROCESS_AUTHORITIES)
	{
		fprintf(stderr, "DNS_Authorities:\n");
		for (int i = 0; i < packet->authority_count && packet->authorities != NULL; i++)
			print_dns_packet_resource_record(packet->authorities[i]);

		if (DNS_PROCESS_ADDITIONALS)
		{
			fprintf(stderr, "DNS_Additionals:\n");
			for (int i = 0; i < packet->additional_count && packet->additionals != NULL; i++)
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
			stderr, "DNS_PACKET_RESOURCE_RECORD: {\n\tname\t%s\n\ttype\t%d (%s)\n\tclass\t%#x (%s)\n\tttl\t%d\n\trdata_length\t%d\n\trdata\t%s\n}\n",
			record->name,
			record->record_type, translate_dns_type(record->record_type),
			record->record_class, "-",
			record->ttl,
			record->rdata_length,
			record->rdata
	);
#endif
}
