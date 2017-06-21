
project(MPUDP)
set(CMAKE_C_STANDARD 11)
include_directories(include)
link_libraries(pcap pthread)
set(SOURCE_FILES src/segmenter.c src/network.c)
add_executable(sender ${SOURCE_FILES} src/sender.c)
add_executable(reciever ${SOURCE_FILES} src/reciever.c)
