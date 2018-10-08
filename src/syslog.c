// syslog.c
// ISA, 08.10.2018
// Author: Daniel Dolejska, FIT

#define DEBUG_PRINT_ENABLED
#define DEBUG_LOG_ENABLED
#define DEBUG_ERR_ENABLED

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <memory.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>

#include "syslog.h"
#include "network_utils.h"
#include "macros.h"
#include "dns.h"


SyslogSenderPtr init_syslog_sender( char *server )
{
	DEBUG_LOG("INIT-SYSLOG-SENDER", "Allocating memory...");
	SyslogSenderPtr sender = malloc(sizeof(SyslogSender));
	if (sender == NULL)
	{
		perror("malloc");
		return NULL;
	}
	memset(sender, 0, sizeof(SyslogSender));

	if (process_address(&sender->receiver, server) != EXIT_SUCCESS)
	{
		destroy_syslog_sender(sender);
		return NULL;
	}
	sender->receiver.sin_port = htons(SYSLOG_PORT);
	DEBUG_PRINT("\tserver: %s:%d\n", inet_ntoa(sender->receiver.sin_addr), ntohs(sender->receiver.sin_port));

	DEBUG_LOG("INIT-SYSLOG-SENDER", "Creating socket...");
	//  UDP socket
	if ((sender->sock = socket(sender->receiver.sin_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	{
		perror("socket");
		destroy_syslog_sender(sender);
		return NULL;
	}

	/*
	DEBUG_LOG("INIT-SYSLOG-SENDER", "Performing connect...");
	if (connect(sender->sock, (struct sockaddr *) &sender->receiver, sizeof(sender->receiver)) < 0)
	{
		perror("connect");
		destroy_syslog_sender(sender);
		return NULL;
	}

	struct sockaddr sockaddress;
	socklen_t socksize = sizeof(sockaddress);
	if (getsockname(sender->sock, &sockaddress, &socksize) < 0)
	{
		perror("getsockname");
		destroy_syslog_sender(sender);
		return NULL;
	}

	if (inet_ntop(sockaddress.sa_family, &sockaddress.sa_data, sender->sender_address, INET6_ADDRSTRLEN) == NULL)
	{
		ERR("Failed to convert source network address.");
		perror("inet_ntop");
		destroy_syslog_sender(sender);
		return NULL;
	}
	DEBUG_PRINT("\taddress: %s\n", sender->sender_address);
	 */

	return sender;
}

void destroy_syslog_sender( SyslogSenderPtr sender )
{
	DEBUG_LOG("DESTROY-SYSLOG-SENDER", "Destroying sender...");
	if (sender->buffer_offset > 0)
		syslog_buffer_flush(sender);

	free(sender);
}

int send_syslog_message( SyslogSenderPtr sender, const char *message, int count )
{
	DEBUG_LOG("SEND-SYSLOG-MSG", "Adding message to buffer...");
	char syslog_message[MESSAGE_LEN_LIMIT + 1];
	char *timestamp = syslog_get_timestamp();
	snprintf(syslog_message, MESSAGE_LEN_LIMIT, "<%d> 1 %s IPADDR %s %d - - %s %d\13\10",
			SYSLOG_FACILITY * SYSLOG_FACILITY_MUL_CONSTANT + SYSLOG_SEVERITY,
			timestamp,
			SYSLOG_APP_NAME,
			getpid(),
			message,
			count
	);

	free(timestamp);
	if (strlen(sender->buffer) + strlen(syslog_message) > MESSAGE_LEN_LIMIT)
	{
		//  There is not enough space in the buffer for this message
		DEBUG_LOG("SEND-SYSLOG-MSG", "Buffer full, flushing first...");

		if (syslog_buffer_flush(sender) != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}

	syslog_buffer_append(sender, syslog_message);
	return EXIT_SUCCESS;
}

void syslog_buffer_append( SyslogSenderPtr sender, const char *message )
{
	DEBUG_LOG("SYSLOG-BUFFER-APPEND", "Appending message...");
	assert(sender->buffer_offset + strlen(message) <= MESSAGE_LEN_LIMIT);

	strcpy(sender->buffer + sender->buffer_offset, message);
	sender->buffer_offset+= strlen(message);
}

int syslog_buffer_flush( SyslogSenderPtr sender )
{
	*(sender->buffer + (--sender->buffer_offset) - 1) = '\0'; // terminate last message -> ignore LF and turn CR to '\0'

	DEBUG_LOG("SYSLOG-BUFFER-FLUSH", "Sending packet...");
	int status = (int) sendto(
		sender->sock,
		sender->buffer, sender->buffer_offset,
		0,
		(struct sockaddr *) &sender->receiver, sizeof(sender->receiver)
	);
	DEBUG_PRINT("\tjust sent: %d characters\n", status);
	DEBUG_PRINT("\tbuffer: '%s'\n", sender->buffer);

	if (status == -1)
	{
		perror("send");
		ERR("Failed to send syslog message.");
		return EXIT_FAILURE;
	}

	syslog_buffer_empty(sender);
	return EXIT_SUCCESS;
}

void syslog_buffer_empty( SyslogSenderPtr sender )
{
	DEBUG_LOG("SYSLOG-BUFFER-EMPTY", "Emptying buffer...");
	memset(sender->buffer, 0, MESSAGE_LEN_LIMIT + 1);
	sender->buffer_offset = 0;
}

char *syslog_get_timestamp()
{
	char *timestamp = malloc(25);
	if (timestamp == NULL)
	{
		ERR("Failed to allocate memory for current timestamp.");
		perror("malloc");
		return NULL;
	}

	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	sprintf(timestamp, "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);

	return  timestamp;
}
