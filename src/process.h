// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

#ifndef _PROCESS_H
#define _PROCESS_H

#include "stdint.h"
#include "dns.h"
#include "pcap.h"

#define TCP_BUFFER_SIZE 65535


extern long send_interval_current;
extern uint8_t *tcp_buffer;
extern uint16_t tcp_buffer_offset;


// ///////////////////////////////////////////////////////////////////////
//      TCP PACKET BUFFER
// ///////////////////////////////////////////////////////////////////////

/**
 * Alokuje a vynuluje buffer pro data TCP packetu.
 *
 * @return
 */
int create_tcp_buffer();

/**
 * Zrusi dynamicky alokovany buffer pro TCP packety.
 */
void destroy_tcp_buffer();

/**
 * Vlozi nova data z TCP packetu do bufferu, pokud se jedna o DNS packet. Pokud
 * ne, ukonci predchozi TCP packet.
 *
 * @param packet
 */
void push_tcp_data( TCPPacketPtr packet );

/**
 *
 * @param packet
 * @return uint16_t
 */
uint16_t pop_tcp_data( TCPPacketPtr packet );


// ///////////////////////////////////////////////////////////////////////
//      PACKET PROCESSING
// ///////////////////////////////////////////////////////////////////////

/**
 * Zacne naslouchat na danem sitovem rozhrani a zpracovavat provoz.
 *
 * @pre entry_table is allocated and initialized
 *
 * @param interface
 * @return exit status code
 */
int start_interface_listening( char *interface );

/**
 * Zpracuje dany pcap soubor.
 *
 * @pre entry_table is allocated and initialized
 *
 * @param file
 * @return exit status code
 */
int start_file_processing( PcapFilePtr file );

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

/**
 * Zpracovani (ulozeni do tabulky) konkretniho resource record DNS odpovedi.
 *
 * @param record
 */
void process_dns_resource_record( DNSResourceRecordPtr record );

/**
 * Odesle aktualni statistiky.
 *
 * @param clear_table
 * @param force_print
 */
void send_statistics( short clear_table, short force_print );


#endif //_PROCESS_H
