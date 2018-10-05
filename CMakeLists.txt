cmake_minimum_required(VERSION 3.5.1)
project(dns-export)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS -Wall)

add_executable(dns-export
        src/main.c src/macros.h src/network.h src/network.c src/dns.h src/dns.c)
