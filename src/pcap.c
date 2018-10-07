// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "macros.h"
#include "pcap.h"


PcapFilePtr pcap_file_open(char *filepath)
{
	assert(filepath != NULL);
	assert(strlen(filepath) > 0);
    DEBUG_LOG("PCAP-FILE-OPEN", "Allocating structure...");

	//	Allocate memory for PcapFile structure
    PcapFilePtr file = malloc(sizeof(PcapFile));
    if (file == NULL)
    {
        perror("malloc");
        return NULL;
    }

    DEBUG_LOG("PCAP-FILE-OPEN", "Opening file...");
    //	Open .pcap file
    file->fd = fopen(filepath, "r"); // fd closed in destructor
    if (file->fd == NULL)
	{
		DEBUG_ERR("PCAP-FILE-OPEN", "Failed to open the file...");
    	perror("fopen");
    	free(file);
    	return NULL;
	}

    //	Read file global header
    fread(&file->header, sizeof(PcapGlobalHeader), 1, file->fd);

	DEBUG_PRINT("file->header.version: %d.%d\n", file->header.version_major, file->header.version_minor);
	DEBUG_PRINT("file->header.network: %d\n", file->header.network);

    DEBUG_LOG("PCAP-FILE-OPEN", "Allocating packet array...");
    //	Initialize packet array
	file->packet_count = 0;
	file->packet_max   = 128;
	file->packets	   = calloc(file->packet_max, sizeof(PcapPacketPtr));

	if (pcap_file_process(file) != EXIT_SUCCESS)
	{
		//	Packet loading was unsuccessful
		pcap_file_close(file);
		return NULL;
	}

	return file;
}

void pcap_file_close(PcapFilePtr file)
{
	assert(file != NULL);

    DEBUG_LOG("PCAP-FILE-CLOSE", "Closing FD...");
	//	CLose file descriptor
	fclose(file->fd);

    DEBUG_LOG("PCAP-FILE-OPEN", "Freeing allocated memory...");
	//	Free allocated structures
	pcap_file_foreach(file, &pcap_packet_destroy);
	free(file->packets);
	free(file);
}

int pcap_file_process(PcapFilePtr file)
{
	assert(file != NULL);

	DEBUG_LOG("PCAP-FILE-PROCESS", "Processing file...");
	PcapPacketPtr packet = pcap_packet_parseNext(file);
	while (packet != NULL)
	{
		if (file->packet_count + 1 > file->packet_max)
		{
			DEBUG_LOG("PCAP-FILE-PROCESS", "Packet array too small, increasing...");
			file->packet_max*= 2;
			file->packets = realloc(file->packets, file->packet_max * sizeof(PcapPacketPtr));
			if (file->packets == NULL)
			{
				//	TODO: Error message?
				DEBUG_ERR("PCAP-FILE-PROCESS", "Failed to reallocate packet array...");
				perror("realloc");
				return EXIT_FAILURE;
			}
			DEBUG_PRINT("\tnew size: %d\n", file->packet_max);
		}

		file->packets[file->packet_count++] = packet;
		packet = pcap_packet_parseNext(file);
	}

	return EXIT_SUCCESS;
}

void pcap_file_foreach(PcapFilePtr file, void (*cb)(PcapPacketPtr))
{
	assert(file != NULL);

    DEBUG_LOG("PCAP-FILE-FOREACH", "Invoking callback for each packet...");
	//	For each parsed packet in structure
	for (uint32_t i = 0; i < file->packet_count; i++)
		//	Invoke callback with packet pointer
		(*cb)(file->packets[i]);
}

PcapPacketPtr pcap_packet_parseNext(PcapFilePtr file)
{
	assert(file != NULL);

    DEBUG_LOG("PCAP-PACKET-PARSENEXT", "Allocating structure...");
	//	Allocate memory for PcapPacket structure
	PcapPacketPtr packet = malloc(sizeof(PcapPacket));
	if (packet == NULL)
	{
		perror("malloc");
		return NULL;
	}

    DEBUG_LOG("PCAP-PACKET-PARSENEXT", "Reading packet header...");
	//	Read packet specific header
	if (fread(&packet->header, sizeof(PcapPacketHeader), 1, file->fd) != 1)
	{
		//	Reading failed / file is empty
		//	TODO: Check for error?
		free(packet);
		return NULL;
	}

	DEBUG_PRINT("packet->header.incl_len: %d\n", packet->header.incl_len);
	DEBUG_PRINT("packet->header.orig_len: %d\n", packet->header.orig_len);

    DEBUG_LOG("PCAP-PACKET-PARSENEXT", "Reading packet data...");
	uint32_t count = packet->header.incl_len;
	//	Allocate memory for actual packet data based on information from header
	packet->data = calloc(count, sizeof(uint8_t)); // TODO: validate incl_len (orig_len?)
	//	Read packet data from file
	if (fread(packet->data, sizeof(uint8_t), count, file->fd) != count)
	{
		//	Reading failed, report error & free memory
		pcap_packet_destroy(packet);

		perror("fread");
		return NULL;
	}

	return packet;
}

void pcap_packet_destroy(PcapPacketPtr packet)
{
	assert(packet != NULL);

    //DEBUG_LOG("PCAP-PACKET-DESTROY", "Freeing allocated memory...");
	free(packet->data);
	free(packet);
}
