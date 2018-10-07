cmake_minimum_required(VERSION 3.5.1)
project(dns-export)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-Wall -Wextra")

set(SOURCES
	src/main.c
	src/network.c
	src/dns.c
	src/ht.c
	src/pcap.c
	src/process.c
	)

set(INCLUDES
	src/main.h
	src/macros.h
	src/network.h
	src/dns.h
	src/ht.h
	src/pcap.h
	src/process.h
	)

add_executable(dns-export ${SOURCES} ${INCLUDES})
