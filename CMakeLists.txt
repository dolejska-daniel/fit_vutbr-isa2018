cmake_minimum_required(VERSION 3.12)
project(dns-export)

set(CMAKE_C_STANDARD 99)

add_executable(dns-export
        src/main.c src/macros.h src/network.h src/network.c)
