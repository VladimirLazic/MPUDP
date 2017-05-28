#ifndef MPUDP_NETWORK_H
#define MPUDP_NETWORK_H

#define DEFAULT_PORT   27015
#define DEFAULT_FILE_LEN 1024
#define DEFAULT_MESSAGE_LEN 512
#define BUF_LEN 512
#define NUM_OF_THREADS 5


#ifdef _WIN32
#define HAVE_STRUCT_TIMESPEC
#pragma comment(lib, "Ws2_32.lib")
#endif // _WIN32

#include <pthread.h>
#include <pcap.h>

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

/**
 * @struct EthernetHeader
 * @brief
 *  Ethernet header with destination/source address and type of next layer
 *
 */
typedef struct ethernet_header{
    unsigned char dstAddress[6];/**<Destination address*/
    unsigned char srcAddress[6];/**<Source address*/
    unsigned short type;/**<Type of next layer*/
}EthernetHeader;
/**
 * @struct IPHeader
 * @brief
 *  Internet Protocol header with: header_length, version, type of service, length, id, fragment flags,
 *  fragment offset, Time to live,
 *  next protocol, checksum, src/dst address and option + padding
 */
typedef struct ip_header{
    unsigned char headerLength :4;/**<Internet header length (4bits)*/
    unsigned char version :4;/**<Version (4b)*/
    unsigned char tos;/**<Type of Service  (8b)*/
    unsigned short length;/**<Total length (16b)*/
    unsigned short identification;/**<Identification (16b)*/
    unsigned short fragmentFlags :3;/**<Flags (3b)*/
    unsigned short fragmentOffset :13;/**<Fragment offset (13b)*/
    unsigned char ttl;/**<Time To Live (8b)*/
    unsigned char nextProtocol;/**<Protocol of next layer (8b)*/
    unsigned short checkSum;/**<Header checksum (16b)*/
    unsigned char srcAddr[4];/**<Source address (4B)*/
    unsigned char dstAddr[4];/**<Destination address (4B)*/
    unsigned int optionPadding;/**<Internet header length (Vary)*/
    /**
     * + variable part of the header
     */
}IPHeader;

/**
 * @struct UDPHeader
 * @brief
 *  User Datagram Protocol header structure
 *      Contains src/dst port length of datagram and UDP checksum
 */
typedef struct udp_header{
    unsigned short srcPort;/**<Source port (16b)*/
    unsigned short dstPort;/**<Destination port (16b)*/
    unsigned short datagramLength;/**<Total Length (16b)*/
    unsigned short checkSum;/**<Header Checksum (16b)*/
}UDPHeader;
/**
 * @struct Datagram
 * @brief
 *  datagram data
 */
typedef struct datagram
{
    char message[DEFAULT_MESSAGE_LEN];
    int datagramId;
    bool sent;
}Datagram;
#endif //MPUDP_NETWORK_H
