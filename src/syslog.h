// syslog.c
// ISA, 08.10.2018
// Author: Daniel Dolejska, FIT


#ifndef _SYSLOG_H
#define _SYSLOG_H

#include <stdint.h>

#include "network_utils.h"


#define SYSLOG_PORT 514

#define MESSAGE_LEN_LIMIT   1024
#define SYSLOG_FACILITY_MUL_CONSTANT    8 ///< magic multiplication constant
#define SYSLOG_FACILITY     16		///< local0
#define SYSLOG_SEVERITY     6   	///< informational
#define SYSLOG_APP_NAME     "dns-export"


struct syslog_sender {
	int             sock;   	///< Socket FD
	SocketAddress   receiver;   ///< Adresa a nastaveni prijemce
	SocketAddress6  receiver6;  ///< Adresa IPv6 a nastaveni prijemce
	short  			v6;  		///< Pouzivat IPv6
	char            sender_address[INET6_ADDRSTRLEN];  ///<
	uint16_t        buffer_offset; ///< Offset bufferu pro vkladani zprav
	char            buffer[MESSAGE_LEN_LIMIT + 1];  ///< Buffer zpravy
};
typedef struct syslog_sender  SyslogSender;
typedef struct syslog_sender *SyslogSenderPtr;


/**
 * Alokuje a inicializuje strukturu syslog odesilatoru.
 *
 * @param server
 * @return SyslogSenderPtr|NULL
 */
SyslogSenderPtr init_syslog_sender( char *server );

/**
 * Zrusi strukturu odesilatoru. Pred zrusenim odesle vsechny cekajici zpravy
 * v bufferu.
 *
 * @param sender
 */
void destroy_syslog_sender( SyslogSenderPtr sender );

/**
 * Zada zpravu k odeslani. Zprava je ulozena do bufferu a ceka, nez je dostatek
 * zprav k jejich odeslani.
 *
 * @param sender
 * @param message
 * @param count
 * @return exit status code
 */
int send_syslog_message( SyslogSenderPtr sender, const char *message, int count );

/**
 * Odesle veskere cekajici zpravy a vyprazdni buffer.
 *
 * @param sender
 * @return exit status code
 */
int syslog_buffer_flush( SyslogSenderPtr sender);

/**
 * Prida zpravu do bufferu odesilatoru.
 *
 * @param sender
 * @param message
 */
void syslog_buffer_append( SyslogSenderPtr sender, const char *message );

/**
 * Vyprazdni buffer odesilatoru.
 *
 * @param sender
 */
void syslog_buffer_empty( SyslogSenderPtr sender );

/**
 * Dynamicky alokuje znakovy retezec pro aktualni timestamp a inicializuje jej.
 *
 * @post dynamicky alokovany retezec, je nutne jej uvolnit
 * @return char*|NULL
 */
char *syslog_get_timestamp();

#endif //_SYSLOG_H
