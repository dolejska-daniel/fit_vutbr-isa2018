// network.h
// IPK-PROJ2, 07.04.2018
// ISA, 30.09.2018
// Author: Daniel Dolejska, FIT

#ifndef _NETWORK_H
#define _NETWORK_H


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
 * Ziska celkovou velikost hlavicek packetu (ETH + IP + UDP).
 *
 * @return size_t
 */
size_t get_header_sizes();


// ///////////////////////////////////////////////////////////////////////
//      ETH HEADERS
// ///////////////////////////////////////////////////////////////////////

/**
 * Z datoveho packetu ziska ukazatel na cast s ETH headerem.
 *
 * @param packet
 * @return
 */
struct ethhdr *get_eth_header( uint8_t *packet );

/**
 * Ziska velikost ETH headeru.
 *
 * @return
 */
size_t get_eth_header_size();

/**
 * Vypise obsah ETH headeru na stderr.
 *
 * @param eh
 */
void print_eth_header( const struct ethhdr *eh );

/**
 * Vytvori ETH header pro dany packet, nastavi pridanou velikost packetu.
 *
 * @param packet
 * @param packet_len
 * @param mac
 */
void eth_encaps( uint8_t *packet, uint16_t *packet_len, const uint8_t *mac );


// ///////////////////////////////////////////////////////////////////////
//      IP HEADERS
// ///////////////////////////////////////////////////////////////////////

/**
 * Z datoveho packetu ziska ukazatel na cast s IP headerem.
 *
 * @param packet
 * @return
 */
struct iphdr *get_ip_header( uint8_t *packet );

/**
 * Ziska velikost IP headeru.
 *
 * @return
 */
size_t get_ip_header_size();

/**
 * Vypise obsah IP headeru na stderr.
 *
 * @param iph
 */
void print_ip_header( const struct iphdr *iph );

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
 * Z datoveho packetu ziska ukazatel na cast s UDP headerem.
 *
 * @param packet
 * @return
 */
struct udphdr *get_udp_header( uint8_t *packet );

/**
 * Ziska velikost UDP headeru.
 *
 * @return
 */
size_t get_udp_header_size();

/**
 * Vypise obsah UDP headeru na stderr.
 *
 * @param udph
 */
void print_udp_header( const struct udphdr *udph );

/**
 * Vytvori UDP header pro dany packet, nastavi pridanou velikost packetu.
 *
 * @param packet
 * @param packet_len
 */
void udp_encaps( uint8_t *packet, uint16_t *packet_len );

#endif //_NETWORK_H
