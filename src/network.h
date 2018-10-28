// network.h
// IPK-PROJ2, 07.04.2018
// ISA, 30.09.2018
// Author: Daniel Dolejska, FIT

#ifndef _NETWORK_H
#define _NETWORK_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


//  L3 Protocols
#define IPv4    0x0800
#define IPv6    0x86dd
#define ARP     0x0806

//  L4 Protocols
#define TCP 0x06
#define UDP 0x11


// ///////////////////////////////////////////////////////////////////////
//      PACKET DATA
// ///////////////////////////////////////////////////////////////////////

struct packet_data {
	uint8_t     *data;	///< Data
	uint16_t    offset;	///< Data read offset
};
typedef struct packet_data  PacketData;
typedef struct packet_data* PacketDataPtr;

/**
 * Alokuje a inicializuje datovou strukturu reprezentujici data packetu.
 *
 * @param data
 * @param offset
 * @return PacketDataPtr
 */
PacketDataPtr create_packet_data(uint8_t *data, uint16_t offset);

/**
 * Zrusi alokovanou strukturu reprezentujici data packetu.
 *
 * @param packet
 */
void destroy_packet_data( PacketDataPtr pdata );

/**
 * Ziska ukazatel na data packetu pro aktualni pozici.
 *
 * @param packet
 * @return uint8_t*
 */
uint8_t *get_packet_data( PacketDataPtr pdata );

/**
 * Ziska ukazatel na data packetu pro vlastni pozici.
 *
 * @param packet
 * @param offset
 * @return uint8_t*
 */
uint8_t *get_packet_data_custom( PacketDataPtr pdata, uint16_t offset );


// ///////////////////////////////////////////////////////////////////////
//      TCP
// ///////////////////////////////////////////////////////////////////////

struct tcp_packet {
	struct ethhdr 	*eth_header;	///< Ehternet header structure
	struct iphdr  	*ip_header;		///< IP header structure
	struct tcphdr 	*tcp_header;	///< TCP header structure
	PacketDataPtr   data;           ///< Packet data
};
typedef struct tcp_packet  TCPPacket;
typedef struct tcp_packet* TCPPacketPtr;

/**
 * Alokuje a inicializuje datovou strukturu pro hlavicky packetu dle prijatych
 * dat.
 *
 * @param packet_data
 * @return TCPPacketPtr
 */
TCPPacketPtr parse_tcp_packet( uint8_t *packet_data );

/**
 * Zrusi alokovanou strukturu pro hlavicky packetu.
 *
 * @param packet
 */
void destroy_tcp_packet( TCPPacketPtr packet );


// ///////////////////////////////////////////////////////////////////////
//      UDP
// ///////////////////////////////////////////////////////////////////////

struct udp_packet {
	struct ethhdr 	*eth_header;	///< Ehternet header structure
	struct iphdr  	*ip_header;		///< IP header structure
	struct udphdr 	*udp_header;	///< UDP header structure
	PacketDataPtr   data;           ///< Packet data
};
typedef struct udp_packet  UDPPacket;
typedef struct udp_packet* UDPPacketPtr;

/**
 * Alokuje a inicializuje datovou strukturu pro hlavicky packetu dle prijatych
 * dat.
 *
 * @param packet_data
 * @return UDPPacketPtr
 */
UDPPacketPtr parse_udp_packet( uint8_t *packet_data );

/**
 * Zrusi alokovanou strukturu pro hlavicky packetu.
 *
 * @param packet
 */
void destroy_udp_packet( UDPPacketPtr packet );


// ///////////////////////////////////////////////////////////////////////
//      ETH HEADERS
// ///////////////////////////////////////////////////////////////////////

/**
 * Struktura reprezentujici Ethernet hlavicku.
 */
struct eth_header {
	uint8_t	destination[6];	///< Cilova MAC adresa
	uint8_t	source[6];		///< Zdrojova MAC adresa
	uint8_t	type[2];		///< EtherType
};
typedef struct eth_header  ETHHeader;
typedef struct eth_header* ETHHeaderPtr;

/**
 * Z datoveho packetu ziska ukazatel na cast s ETH headerem.
 *
 * @param packet
 * @return struct ethhdr*
 */
struct ethhdr *get_eth_header( uint8_t *packet );

/**
 * Ziska velikost ETH headeru.
 *
 * @return uint16_t
 */
uint16_t get_eth_header_size();

/**
 * Vypise obsah ETH headeru z packetu na stderr.
 *
 * @param packet
 */
void print_eth_header( UDPPacketPtr packet );

/**
 * Vypise obsah ETH headeru na stderr.
 *
 * @param eh
 */
void print_eth_header_struct( const struct ethhdr *eh );

/**
 * Vytvori ETH header pro dany packet, nastavi pridanou velikost packetu.
 *
 * @param packet
 * @param packet_len
 * @param source_mac
 * @param destination_mac
 */
void eth_encaps( uint8_t *packet, uint16_t *packet_len, const uint8_t *source_mac, const uint8_t *destination_mac );


// ///////////////////////////////////////////////////////////////////////
//      IP HEADERS
// ///////////////////////////////////////////////////////////////////////

/**
 * Z datoveho packetu ziska ukazatel na cast s IP headerem.
 *
 * @param packet
 * @return struct iphdr*
 */
struct iphdr *get_ip_header( uint8_t *packet );

/**
 * Ziska velikost IP headeru.
 *
 * @return uint16_t
 */
uint16_t get_ip_header_size();

/**
 * Vypise obsah IP headeru z packetu na stderr.
 *
 * @param packet
 */
void print_ip_header( UDPPacketPtr packet );

/**
 * Vypise obsah IP headeru na stderr.
 *
 * @param iph
 */
void print_ip_header_struct( const struct iphdr *iph );

/**
 * Vytvori IP header pro dany packet, nastavi pridanou velikost packetu.
 *
 * @param packet
 * @param packet_len
 */
void ip_encaps( uint8_t *packet, uint16_t *packet_len );


// ///////////////////////////////////////////////////////////////////////
//      UDP HEADERS
// ///////////////////////////////////////////////////////////////////////

/**
 * Struktura reprezentujici UDP hlavicku
 */
struct udp_header {
	uint16_t    source;			///< Zdrojovy port
	uint16_t    destination;	///< Cilovy port
	uint16_t    length;			///< Delka dat
	uint16_t    check;			///< Checksum
};
typedef struct udp_header  UDPHeader;
typedef struct udp_header* UDPHeaderPtr;

/**
 * Z datoveho packetu ziska ukazatel na cast s UDP headerem.
 *
 * @param packet
 * @return struct udphdr*
 */
struct udphdr *get_udp_header( uint8_t *packet );

/**
 * Ziska velikost UDP headeru.
 *
 * @return uint16_t
 */
uint16_t get_udp_header_size();

/**
 * Vypise obsah UDP headeru z packetu na stderr.
 *
 * @param packet
 */
void print_udp_header( UDPPacketPtr packet );

/**
 * Vypise obsah UDP headeru na stderr.
 *
 * @param udph
 */
void print_udp_header_struct( const struct udphdr *udph );

/**
 * Vytvori UDP header pro dany packet, nastavi pridanou velikost packetu.
 *
 * @param packet
 * @param packet_len
 * @param source_port
 * @param destination_port
 */
void udp_encaps( uint8_t *packet, uint16_t *packet_len, uint16_t source_port, uint16_t destination_port );


// ///////////////////////////////////////////////////////////////////////
//      TCP HEADERS
// ///////////////////////////////////////////////////////////////////////

/**
 * Struktura reprezentujici TCP hlavicku
 */
struct tcp_header {
	uint16_t    source;			///< Zdrojovy port
	uint16_t    destination;	///< Cilovy port
	uint16_t    length;			///< Delka dat
	uint16_t    check;			///< Checksum
};
typedef struct tcp_header  TCPHeader;
typedef struct tcp_header* TCPHeaderPtr;

/**
 * Z datoveho packetu ziska ukazatel na cast s TCP headerem.
 *
 * @param packet
 * @return struct tcphdr*
 */
struct tcphdr *get_tcp_header( uint8_t *packet );

/**
 * Ziska velikost TCP headeru.
 *
 * @param packet
 * @return uint16_t
 */
uint16_t get_tcp_header_size(TCPPacketPtr packet);

/**
 * Vypise obsah TCP headeru z packetu na stderr.
 *
 * @param packet
 */
void print_tcp_header( TCPPacketPtr packet );

/**
 * Vypise obsah TCP headeru na stderr.
 *
 * @param tcph
 * @param size
 */
void print_tcp_header_struct( const struct tcphdr *tcph, uint16_t size );


// ///////////////////////////////////////////////////////////////////////
//      GENERAL
// ///////////////////////////////////////////////////////////////////////

/**
 * Vypocte kontrolni soucet pro obsah packetu.
 *
 * @param buf
 * @param nwords
 *
 * @return unsigned short
 */
unsigned short check_sum(unsigned short *buf, int nwords);

/**
 * Ziska celkovou velikost hlavicek UDP packetu (ETH + IP + UDP).
 *
 * @return uint16_t
 */
uint16_t get_header_sizes_udp();

/**
 * Ziska celkovou velikost hlavicek TCP packetu (ETH + IP + TCP).
 *
 * @param packet
 * @return uint16_t
 */
uint16_t get_header_sizes_tcp(TCPPacketPtr packet);

#endif //_NETWORK_H
