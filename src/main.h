// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

#ifndef _MAIN_H
#define _MAIN_H

#include <stdint.h>

#include "ht.h"
#include "syslog.h"


#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1600 // send and receive buffer size in bits
#endif

#define FLAG_READ       7
#define FLAG_INTERFACE  6
#define FLAG_SERVER     5
#define FLAG_TIME       4


extern tHTable *entry_table;
extern tHTable *entry_table_full;
extern SyslogSenderPtr syslog;
extern uint8_t flags;
extern long send_interval;
extern short keep_running;


#define FLAG_MASK(offset)       (1 << offset)
#define IS_FLAG_ACTIVE(offset)  ((flags & FLAG_MASK(offset)) != 0)
#define SET_FLAG_ACTIVE(offset) (flags = flags | FLAG_MASK(offset))


int main(int argc, char **argv);

/**
 *
 * @param signal
 */
void signal_handler( int signal );

/**
 *
 * @param key
 * @param data
 */
void entry_printer( tKey key, tData data );

/**
 *
 * @param key
 * @param data
 */
void entry_sender( tKey key, tData data );


#endif //_MAIN_H
