cmake_minimum_required(VERSION 3.5.1)
project(dns-export)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-Wall -Wextra")

set(SOURCES
	src/main.c
	src/network.c
	src/dns.c
	src/ht.c
        src/pcap.c src/pcap.h)

set(INCLUDES
	src/macros.h
	src/network.h
	src/dns.h
	src/ht.h

	# Libraries
	#src/pcap.h
	)

include(GNUInstallDirs)

add_executable(dns-export ${SOURCES} ${INCLUDES})

#target_link_libraries(dns-export ${CMAKE_SOURCE_DIR}/lib/libpcap.a)

