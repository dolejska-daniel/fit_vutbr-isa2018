// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

#ifndef _PROCESS_H
#define _PROCESS_H

#include "stdint.h"
#include "dns.h"
#include "pcap.h"


/**
 * Zacne naslouchat na danem sitovem rozhrani a zpracovavat provoz.
 *
 * @pre entry_table is allocated and initialized
 *
 * @param interface
 * @param send_interval
 * @return exit status code
 */
int start_interface_listening( char *interface, uint32_t send_interval );

/**
 * Zpracuje dany pcap soubor.
 *
 * @pre entry_table is allocated and initialized
 *
 * @param file
 * @param send_interval
 * @return exit status code
 */
int start_file_processing( PcapFilePtr file, uint32_t send_interval );

/**
 * Nacte data ze socketu.
 *
 * @param sock
 * @param data
 * @return short
 */
short receive_data( int sock, uint8_t *data );

/**
 * Zpracovani prenosu...
 *
 * @param data
 */
int process_traffic( uint8_t *data );

/**
 * Zpracovani DNS prenosu...
 *
 * @param dns
 */
void process_dns_traffic( DNSPacketPtr dns );


#endif //_PROCESS_H
