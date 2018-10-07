// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT


#include <stdint.h>
#include <bits/types/FILE.h>

#ifndef _PCAP_H
#define _PCAP_H


/**
 * @link https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
 */
struct pcap_hdr_s {
    uint32_t magic_number;   ///< magic number
    uint16_t version_major;  ///< major version number
    uint16_t version_minor;  ///< minor version number
    int32_t  thiszone;       ///< GMT to local correction
    uint32_t sigfigs;        ///< accuracy of timestamps
    uint32_t snaplen;        ///< max length of captured packets, in octets
    uint32_t network;        ///< data link type
};
typedef struct pcap_hdr_s  PcapGlobalHeader;
typedef struct pcap_hdr_s *PcapGlobalHeaderPtr;

/**
 * @link https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
 */
struct pcaprec_hdr_s {
    uint32_t ts_sec;    ///< timestamp seconds
    uint32_t ts_usec;   ///< timestamp microseconds
    uint32_t incl_len;  ///< number of octets of packet saved in file
    uint32_t orig_len;  ///< actual length of packet
};
typedef struct pcaprec_hdr_s  PcapPacketHeader;
typedef struct pcaprec_hdr_s *PcapPacketHeaderPtr;

struct pcap_packet {
    PcapPacketHeader header; ///< packet header
    uint8_t          *data;  ///< packet data
};
typedef struct pcap_packet  PcapPacket;
typedef struct pcap_packet *PcapPacketPtr;

struct pcap_file {
    FILE             *fd;			///< file descriptor
    PcapGlobalHeader header;		///< global file header
    PcapPacketPtr    *packets;		///< array of packets
	uint32_t		 packet_count;	///< number of packets in array
	uint32_t		 packet_max;	///< maximum number of packets in array (size of array)
};

typedef struct pcap_file PcapFile;
typedef struct pcap_file *PcapFilePtr;


PcapFilePtr pcap_file_open(char *filepath);

void pcap_file_close(PcapFilePtr file);

int pcap_file_process(PcapFilePtr file);

void pcap_file_foreach(PcapFilePtr file, void (*cb)(PcapPacketPtr));

PcapPacketPtr pcap_packet_parseNext(PcapFilePtr);

void pcap_packet_destroy(PcapPacketPtr packet);

#endif //_PCAP_H
