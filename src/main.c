// main.c
// IPK-PROJ2, 03.04.2018
// ISA, 30.09.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <arpa/inet.h>
#include <ctype.h>

#include "main.h"
#include "process.h"
#include "network.h"
#include "macros.h"
#include "ht.h"
#include "pcap.h"
#include "syslog.h"


tHTable *entry_table;
SyslogSenderPtr syslog;
uint8_t flags = 0b00000000;
long send_interval = 0;


/**
 * Main program function.
 *
 * @param argc
 * @param argv
 *
 * @return
 */
int main(int argc, char **argv)
{
	DEBUG_LOG("MAIN", "Processing options...");
	/* Spuštění aplikace
	dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]

	-r : zpracuje daný pcap soubor
	-i : naslouchá na daném síťovém rozhraní a zpracovává DNS provoz
	-s : hostname/ipv4/ipv6 adresa syslog serveru
	-t : doba výpočtu statistik, výchozí hodnota 60s
	 */
	char *filepath = NULL;
	char *interface = NULL;
	char *server = NULL;
	char *time = "60";

	int c;
	while ((c = getopt(argc, argv, "r:i:s:t:")) != -1)
	{
		switch (c)
		{
			/** zpracuje daný pcap soubor */
			case 'r':
				if (IS_FLAG_ACTIVE(FLAG_INTERFACE))
				{
					//  Interface flag is already active, cannot use read flag
					ERR("Option -i is already active! You cannot use option -r and -i together.\n");
					exit(EXIT_FAILURE);
				}

				SET_FLAG_ACTIVE(FLAG_READ);
				filepath = optarg;

				break;

			/** naslouchá na daném síťovém rozhraní a zpracovává DNS provoz */
			case 'i':
				if (IS_FLAG_ACTIVE(FLAG_READ))
				{
					//  Read flag is already active, cannot use interface flag
					ERR("Option -r is already active! You cannot use option -r and -i together.\n");
					exit(EXIT_FAILURE);
				}

				SET_FLAG_ACTIVE(FLAG_INTERFACE);
				interface = optarg;
				if (strlen(interface) == 0)
				{
					ERR("Interface name must be non-empty string identifier.");
					exit(EXIT_FAILURE);
				}

				break;

			/** hostname/ipv4/ipv6 adresa syslog serveru */
			case 's':
				SET_FLAG_ACTIVE(FLAG_SERVER);
				server = optarg;
				if (strlen(server) == 0)
				{
					ERR("Syslog server must be non-empty string representation of either IPv4, IPv6 or hostname.");
					exit(EXIT_FAILURE);
				}

				break;

			/** doba výpočtu statistik, výchozí hodnota 60s */
			case 't':
				SET_FLAG_ACTIVE(FLAG_TIME);
				time = optarg;

				break;

			case '?':
				if (optopt == 'r' || optopt == 'i' || optopt == 's' || optopt == 't')
					ERR("Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					ERR("Unknown option `-%c'.\n", optopt);
				else
					ERR("Unknown option character `\\x%x'.\n", optopt);
				exit(EXIT_FAILURE);
			default:
				ERR("Failed to process options.\n");
				exit(EXIT_FAILURE);
		}
	}

	if (flags == 0)
	{
		ERR("Usage: dns-export [-r <file.pcap>] | [-i <interface>] [-s <syslog-server>] [-t <interval_s>]\n");
		exit(EXIT_FAILURE);
	}
	else if (IS_FLAG_ACTIVE(FLAG_READ) == 0 && IS_FLAG_ACTIVE(FLAG_INTERFACE) == 0)
	{
		ERR("Either -r or -i option must be present.\n");
		exit(EXIT_FAILURE);
	}

	char *err;
	send_interval = (long) strtoul(time, &err, 10);
	if (strlen(err))
	{
		DEBUG_PRINT("time: '%s'\nerr: '%s'\n", time, err);
		ERR("Argument for option -t is invalid. Unsigned long is expected.\n");
		exit(EXIT_FAILURE);
	}

	DEBUG_PRINT("Using following arguments:\n\t-r: '%s'\n\t-i: '%s'\n\t-s: '%s'\n\t-t: %ld\n",
			filepath, interface, server, send_interval);

	DEBUG_LOG("MAIN", "Starting application...");
	int status = EXIT_SUCCESS;

	entry_table = malloc(HTSIZE * sizeof(tHTItem));
	if (entry_table == NULL)
	{
		perror("malloc");
		ERR("Failed to allocate hash table, application is unable to continue and will now exit.\n");
		exit(EXIT_FAILURE);
	}
	htInit(entry_table);

	if (IS_FLAG_ACTIVE(FLAG_SERVER))
	{
		syslog = init_syslog_sender(server);
		if (syslog == NULL)
		{
			ERR("Failed to allocate and initialize syslog sender, application is unable to continue and will now exit.\n");
			exit(EXIT_FAILURE);
		}
	}

	//	Setup signal capture
	signal(SIGUSR1, signal_handler);

	if (IS_FLAG_ACTIVE(FLAG_INTERFACE))
	{
		//	Start listening on interface
		status = start_interface_listening(interface);
	}
	else if (IS_FLAG_ACTIVE(FLAG_READ))
	{
		//  Start parsing file
		PcapFilePtr file = pcap_file_open(filepath);
		if (file == NULL)
		{
			ERR("Failed to open specified file, application is unable to continue and will now exit.\n");
			exit(EXIT_FAILURE);
		}

		status = start_file_processing(file);
		pcap_file_close(file);
	}

	DEBUG_LOG("MAIN", "Cleaning up...");
	if (IS_FLAG_ACTIVE(FLAG_SERVER) && syslog != NULL)
		destroy_syslog_sender(syslog);

	htClearAll(entry_table);
	free(entry_table);

	DEBUG_LOG("MAIN", "Exiting program...");
	exit(status);
}

void signal_handler( int signal )
{
	switch (signal)
	{
		case SIGUSR1:
			DEBUG_LOG("MAIN", "Received SIGUSR1, printing current statistics...");
			send_statistics(0, 1);
			break;
		default:
			DEBUG_LOG("MAIN", "Received signal...");
			DEBUG_PRINT("\tsignal id: %d\n", signal);
	}
}

void entry_sender( tKey key, tData data )
{
	send_syslog_message(syslog, key, data);
}

void entry_printer( tKey key, tData data )
{
	fprintf(stdout, "%s %d\n",
			key,
			data);
}
