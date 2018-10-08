// dns.h
// ISA, 07.10.2018
// Author: Daniel Dolejska, FIT

#ifndef _MAIN_H
#define _MAIN_H

#include <stdint.h>

#include "ht.h"

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1500 // send and receive buffer size in bits
#endif

#define FLAG_READ       7
#define FLAG_INTERFACE  6
#define FLAG_SERVER     5
#define FLAG_TIME       4


extern tHTable *entry_table;
extern uint8_t flags;


#define FLAG_MASK(offset)       (1 << offset)
#define IS_FLAG_ACTIVE(offset)  ((flags & FLAG_MASK(offset)) != 0)
#define SET_FLAG_ACTIVE(offset) (flags = flags | FLAG_MASK(offset))


int main(int argc, char **argv);

void signal_handler( int signal );

void entry_processor( tKey key, tData data );


#endif //_MAIN_H
