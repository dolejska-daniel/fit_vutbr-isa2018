// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

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
		ERR("Failed to allocate memory for file...");
        perror("malloc");
        return NULL;
    }
    memset(file, 0, sizeof(PcapFile));

    DEBUG_LOG("PCAP-FILE-OPEN", "Opening file...");
    //	Open .pcap file
    file->fd = fopen(filepath, "r"); // fd closed in destructor
    if (file->fd == NULL)
	{
		ERR("Failed to open the file...");
    	perror("fopen");
    	free(file);
    	return NULL;
	}

    //	Read file global header
    if (fread(&file->header, sizeof(PcapGlobalHeader), 1, file->fd) != 1)
	{
		ERR("Failed to read global file header...");
    	free(file);
    	return NULL;
	}

	DEBUG_PRINT("file->header.version: %d.%d\n", file->header.version_major, file->header.version_minor);
	DEBUG_PRINT("file->header.network: %d\n", file->header.network);

    DEBUG_LOG("PCAP-FILE-OPEN", "Allocating packet array...");
    //	Initialize packet array
	file->packet_count = 0;
	file->packet_max   = 128;
	file->packets	   = malloc(file->packet_max * sizeof(PcapPacketPtr));

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

	DEBUG_LOG("PCAP-FILE-CLOSE", "Destroying pcap file structure...");
	//	CLose file descriptor
	if (file->fd != NULL)
	{
		DEBUG_LOG("PCAP-FILE-CLOSE", "Closing FD...");
		fclose(file->fd);
	}

	//	Free allocated structures
	if (file->packets != NULL)
	{
		DEBUG_LOG("PCAP-FILE-OPEN", "Freeing allocated memory for packets...");
		pcap_file_foreach(file, &pcap_packet_destroy);
		free(file->packets);
	}
	DEBUG_LOG("PCAP-FILE-OPEN", "Freeing allocated memory for main structure...");
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
				ERR("Failed to realloc packet array...");
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
	{
		if (file->packets[i] != NULL)
		{
			//	Invoke callback with packet pointer
			(*cb)(file->packets[i]);
		}
	}
}

PcapPacketPtr pcap_packet_parseNext(PcapFilePtr file)
{
	assert(file != NULL);

    DEBUG_LOG("PCAP-PACKET-PARSENEXT", "Allocating structure...");
	//	Allocate memory for PcapPacket structure
	PcapPacketPtr packet = malloc(sizeof(PcapPacket));
	if (packet == NULL)
	{
		ERR("Failed to allocate memory for packet...");
		perror("malloc");
		return NULL;
	}

    DEBUG_LOG("PCAP-PACKET-PARSENEXT", "Reading packet header...");
	//	Read packet specific header
	if (fread(&packet->header, sizeof(PcapPacketHeader), 1, file->fd) != 1)
	{
		//	Reading failed / file is empty
		ERR("Failed to read packet header...");
		//	TODO: Check for error?
		free(packet);
		return NULL;
	}

	DEBUG_PRINT("packet->header.incl_len: %d\n", packet->header.incl_len);
	DEBUG_PRINT("packet->header.orig_len: %d\n", packet->header.orig_len);

    DEBUG_LOG("PCAP-PACKET-PARSENEXT", "Reading packet data...");
	uint32_t count = packet->header.incl_len;
	//	Allocate memory for actual packet data based on information from header
	packet->data = malloc(count * sizeof(uint8_t));
	//	Read packet data from file
	if (fread(packet->data, sizeof(uint8_t), count, file->fd) != count)
	{
		//	Reading failed, report error & free memory
		pcap_packet_destroy(packet);

		ERR("Failed to read packet body...");
		perror("fread");
		return NULL;
	}

	return packet;
}

void pcap_packet_destroy(PcapPacketPtr packet)
{
	assert(packet != NULL);

    //DEBUG_LOG("PCAP-PACKET-DESTROY", "Freeing allocated memory...");
    if (packet->data != NULL)
		free(packet->data);
	free(packet);
}
