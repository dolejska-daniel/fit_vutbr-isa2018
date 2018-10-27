// dns.h
// ISA, 03.10.2018
// Author: Daniel Dolejska, FIT


#ifndef _DNS_H
#define _DNS_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "network.h"

#define DNS_PORT 53

#define GET_DNS_FLAG_VALUE1B(flag, offset) (((flag) & (0b1 << offset)) >> offset)
#define GET_DNS_FLAG_VALUE4B(flag, offset) (((flag) & (0b1111 << offset)) >> offset)

#define DNS_RECURSION_MASK		(0b11 << 6)	///< String recursion mask

#define DNS_FLAG_QR				15	///< Offset
#define DNS_FLAG_QR_QUERY		0	///< Query
#define DNS_FLAG_QR_RESPONSE	1	///< Response

#define DNS_FLAG_OPCODE			11	///< Offset
#define DNS_FLAG_OPCODE_QUERY	0	///< Standard query
#define DNS_FLAG_OPCODE_IQUERY	1	///< Inverse query
#define DNS_FLAG_OPCODE_STATUS	2	///< Server status request
#define DNS_FLAG_OPCODE_NOTIFY	4	///< Notify
#define DNS_FLAG_OPCODE_UPDATE	5	///< Update

#define DNS_FLAG_AA		10	///< Offset
#define DNS_FLAG_AA_NO	0	///< Not authoritative
#define DNS_FLAG_AA_YES	1	///< Is authoritative

#define DNS_FLAG_TC		9	///< Offset
#define DNS_FLAG_TC_NO	0	///< Not authoritative
#define DNS_FLAG_TC_YES	1	///< Is authoritative

#define DNS_FLAG_RD		8	///< Offset
#define DNS_FLAG_RD_NO	0	///< Recursion not desired
#define DNS_FLAG_RD_YES	1	///< Recursion desired

#define DNS_FLAG_RA		7	///< Offset
#define DNS_FLAG_RA_NO	0	///< Recursive query support not available
#define DNS_FLAG_RA_YES	1	///< Recursive query support available

#define DNS_FLAG_Z		6	///< Offset
#define DNS_FLAG_AD		5	///< Offset
#define DNS_FLAG_CD		4	///< Offset

#define DNS_FLAG_RCODE				0	///< Offset
#define DNS_FLAG_RCODE_NOERR		0	///< The request completed successfully
#define DNS_FLAG_RCODE_FORMATERR	1	///< The name server was unable to interpret the query
#define DNS_FLAG_RCODE_SERVERERR	2	///< The name server was unable to process this query due to a problem with the name server
#define DNS_FLAG_RCODE_NAMEERR		3	///< Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist
#define DNS_FLAG_RCODE_NOTIMPL		4	///< The name server does not support the requested kind of query
#define DNS_FLAG_RCODE_REFUSED		5	///< The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data

#define DNS_TYPE_A		1	///< IPv4 address
#define DNS_TYPE_NS		2	///< Authoritative name server
#define DNS_TYPE_CNAME	5	///< Canonical name for an alias
#define DNS_TYPE_SOA	6	///< Start of [a zone of] authority record
#define DNS_TYPE_PTR	12	///< Domain name pointer
#define DNS_TYPE_MX		15	///< Mail exchange
#define DNS_TYPE_TXT	16	///< Text strings
#define DNS_TYPE_KEY	25	///< Key record
#define DNS_TYPE_AAAA	28	///< IPv6 address
#define DNS_TYPE_KX		36	///< Key Exchanger record
#define DNS_TYPE_DS		43	///< Delegation signer
#define DNS_TYPE_RRSIG	46	///< DNSSEC Lookaside Validation record
#define DNS_TYPE_NSEC	47	///< Next Secure record
#define DNS_TYPE_DNSKEY	48	///< DNS Key record
#define DNS_TYPE_NSEC3	50	///< Next Secure record version 3
#define DNS_TYPE_SPF	99	///< Sender Policy Framework
#define DNS_TYPE_TA		32768	///< DNSSEC Lookaside Validation record
#define DNS_TYPE_DLV	32769	///< DNSSEC Lookaside Validation record

#define DNS_CLASS_IN	1	///< Internet
#define DNS_CLASS_CH	3	///< Chaos
#define DNS_CLASS_HS	4	///< HS
#define DNS_CLASS_NONE	254	///< None
#define DNS_CLASS_ANY	255	///< Any

#define DNS_PROCESS_AUTHORITIES 1
#define DNS_PROCESS_ADDITIONALS 1


/**
 * Struktura reprezentujici DNS dotaz.
 */
struct dns_query {
	char		*name;
	uint16_t	record_type;
	uint16_t	record_class;
};
typedef struct dns_query  DNSQuery;
typedef struct dns_query* DNSQueryPtr;

/**
 * Struktura reprezentujici DNS odpoved.
 */
struct dns_rr {
	char		*name;
	uint16_t	record_type;
	uint16_t	record_class;
	uint32_t	ttl;
	uint16_t	rdata_length;
	char		*rdata;
};
typedef struct dns_rr  DNSResourceRecord;
typedef struct dns_rr* DNSResourceRecordPtr;

/**
 * Struktura reprezentujici DNS packet.
 */
struct dns_packet {
	uint16_t	transaction_id; ///< ID Transakce
	uint16_t	flags;          ///< Stavy odpovedi

	uint16_t	question_count;		///< Number of entries in the question list that were returned.
	uint16_t	answer_count;		///< Number of entries in the answer resource record list that were returned.
	uint16_t	authority_count;	///< Number of entries in the authority resource record list that were returned.
	uint16_t	additional_count;	///< Number of entries in the additional resource record list that were returned.

	DNSQueryPtr				*questions;		///< Entries in the question list that were returned.
	DNSResourceRecordPtr	*answers;		///< Entries in the answer resource record list that were returned.
	DNSResourceRecordPtr	*authorities;	///< Entries in the authority resource record list that were returned.
	DNSResourceRecordPtr	*additionals;	///< Entries in the additional resource record list that were returned.
};
typedef struct dns_packet  DNSPacket;
typedef struct dns_packet* DNSPacketPtr;

/**
 * Struktura reprezentujici
 */
struct dns_rtype {
    uint16_t    type;       ///< Unikatni identifikator typu
    char        *string;    ///< Nazev typu
};
typedef struct dns_rtype DNSRecordType;

/**
 * Prelozi unikatni identifiktar typu DNS zaznamu do textove podoby.
 * Zadna dynamicka alokace neprobiha.
 *
 * @param type
 * @return
 */
char *translate_dns_type( uint16_t type );

/**
 * Prelozi data DNS odpovedi do odpovidajici podoby a ulozi jej do znakoveho
 * retezce, ktery dynamicky alokuje.
 *
 * @param pdata
 * @param record
 * @return exit status code
 */
int load_resource_record_data( PacketDataPtr pdata, DNSResourceRecordPtr record );

/**
 * Prekopiruje znakovy retezec z daneho offsetu (offset) dane DNS odpovedi
 * (packet) do predem alokovane promenne (destination) velikosti (size). Delku
 * nacteneho retezce vrati v promenne length_ptr.
 *
 * @param destination
 * @param pdata
 * @param offset
 * @param size
 * @param length_ptr
 */
void load_domain_name( char **destination, PacketDataPtr pdata, uint16_t *offset, uint16_t size, uint16_t *length_ptr );

/**
 * Ziska velikost "uvodni" (pred queries, answers, ...) casti DNS packetu.
 *
 * @return
 */
size_t get_dns_packet_head_size();

/**
 * Alokuje a inicializuje datovou strukturu pro DNS packet dle prijatych dat.
 *
 * @param pdata
 * @return DNSPacketPtr
 */
DNSPacketPtr parse_dns_packet( PacketDataPtr pdata );

/**
 * Alokuje a inicializuje datovou strukturu pro Query v DNS packetu dle
 * prijatych dat.
 *
 * @param pdata
 * @return DNSQueryPtr
 */
DNSQueryPtr parse_dns_packet_query( PacketDataPtr pdata );

/**
 * Alokuje a inicializuje datovou strukturu pro Resource Record v DNS packetu
 * dle prijatych dat.
 *
 * @param pdata
 * @return DNSResourceRecordPtr
 */
DNSResourceRecordPtr parse_dns_packet_resource_record( PacketDataPtr pdata );

/**
 * Zrusi alokovanou strukturu pro DNS packet.
 *
 * @param packet
 */
void destroy_dns_packet( DNSPacketPtr packet );

/**
 * Zrusi alokovanou strukturu pro Query v DNS packetu.
 *
 * @param query
 */
void destroy_dns_packet_query( DNSQueryPtr query );

/**
 * Zrusi alokovanou strukturu pro Resource Record v DNS packetu.
 *
 * @param record
 */
void destroy_dns_packet_resource_record( DNSResourceRecordPtr record );

/**
 * Vypise obsah DNS packetu na stderr.
 *
 * @param packet
 */
void print_dns_packet( DNSPacketPtr packet );

/**
 * Vypise obsah Query v DNS packetu na stderr.
 *
 * @param packet
 */
void print_dns_packet_query( DNSQueryPtr packet );

/**
 * Vypise obsah Resource Record v DNS packetu na stderr.
 *
 * @param packet
 */
void print_dns_packet_resource_record( DNSResourceRecordPtr packet );

#endif //_DNS_H
