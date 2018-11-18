# Makefile
# IPK-PROJ2, 03.04.2018
# ISA, 05.11.2018
# Author: Daniel Dolejska, FIT

CC=gcc
CFLAGS=-O3 -std=gnu99 -Wall -Wextra
CFLAGS_DEBUG=-std=gnu99 -Wall -Wextra -DDEBUG_LOG_ENABLED -DDEBUG_PRINT_ENABLED -DDEBUG_ERR_ENABLED
COUT=dns-export

all:
	make dns-export

debug:
	make dns-export-debug


dns-export: base64.o dns.o ht.o main.o network.o network_utils.o pcap.o process.o syslog.o
	$(CC) $(CFLAGS) base64.o dns.o ht.o main.o network.o network_utils.o pcap.o process.o syslog.o -o $(COUT)

main.o:
	$(CC) $(CFLAGS) src/main.c -c

base64.o:
	$(CC) $(CFLAGS) src/base64.c -c

dns.o:
	$(CC) $(CFLAGS) src/dns.c -c

ht.o:
	$(CC) $(CFLAGS) src/ht.c -c

network.o:
	$(CC) $(CFLAGS) src/network.c -c

network_utils.o:
	$(CC) $(CFLAGS) src/network_utils.c -c

pcap.o:
	$(CC) $(CFLAGS) src/pcap.c -c

process.o:
	$(CC) $(CFLAGS) src/process.c -c

syslog.o:
	$(CC) $(CFLAGS) src/syslog.c -c


dns-export-debug: base64.od dns.od ht.od main.od network.od network_utils.od pcap.od process.od syslog.od
	$(CC) $(CFLAGS_DEBUG) base64.o dns.o ht.o main.o network.o network_utils.o pcap.o process.o syslog.o -o $(COUT)

main.od:
	$(CC) $(CFLAGS_DEBUG) src/main.c -c

base64.od:
	$(CC) $(CFLAGS_DEBUG) src/base64.c -c

dns.od:
	$(CC) $(CFLAGS_DEBUG) src/dns.c -c

ht.od:
	$(CC) $(CFLAGS_DEBUG) src/ht.c -c

network.od:
	$(CC) $(CFLAGS_DEBUG) src/network.c -c

network_utils.od:
	$(CC) $(CFLAGS_DEBUG) src/network_utils.c -c

pcap.od:
	$(CC) $(CFLAGS_DEBUG) src/pcap.c -c

process.od:
	$(CC) $(CFLAGS_DEBUG) src/process.c -c

syslog.od:
	$(CC) $(CFLAGS_DEBUG) src/syslog.c -c


clean:
	rm *.o *.od $(COUT) -f -v 2>/dev/null

pack:
	tar -cvf xdolej08.tar src/* doc/manual.tex doc/zdroje.bib doc/manual.pdf dns-export.1 README.md Makefile
