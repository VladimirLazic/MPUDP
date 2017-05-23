cmake_minimum_required(VERSION 3.7)
project(UDP-continuous-stream)

set(CMAKE_C_STANDARD 11)
include_directories(include)

set(SOURCE_FILES main.c )
add_executable(P ${SOURCE_FILES})