/** @file network.h
 * @brief Standard network utilities prototypes and structures
 *  This file contains all the prototypes necessary for for printing information about every header and other
 *  general use functions and network structures
 * @author Vladimir Lazic
 * @author Stefan Nicetin (niketic95)
 * @bug None for now
 */

#ifndef MPUDP_NETWORK_H
#define MPUDP_NETWORK_H

#ifdef _WIN32
#define HAVE_STRUCT_TIMESPEC
#pragma comment(lib, "Ws2_32.lib")
#endif // _WIN32

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#else
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdbool.h>
#include <pthread.h>
#include <pcap.h>

#define DEFAULT_PORT   27015
#define DEFAULT_FILE_LEN 1024
#define DEFAULT_MESSAGE_LEN 512
#define BUF_LEN 512
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

/**
 * @brief
 *  Prints detailed info about the device including its IPv4 info
 * @param dev
 *  Device descriptor
 */
void printInterface(pcap_if_t *dev);

/**
 * @brief
 *  Converts sockaddr to human readable text
 * @param address
 *  Socket address structure
 * @return
 *  Human readable text
 */
char *convertSockaddrToString(struct sockaddr *address);

/**
 * @brief
 *  Prints data for given len
 * @param data
 *  Data to print
 * @param data_length
 *  How much to print
 */
void printRawData(unsigned char *data, long data_length);

/**
 * @brief
 *  Prints Ethernet header info
 * @param eh
 *  EthernetHeader to print
 */
void printEthernetHeader(EthernetHeader *eh);

/**
 * @brief
 *  Prints IP header info
 * @param ih
 *  IP header to print
 */
void printIPHeader(IPHeader *ih);

/**
 * @brief
 *  Prints UDP header info
 * @param uh
 *  UDP header to print
 */
void printUDPHeader(UDPHeader *uh);

/**
 * @brief
 *  Prints top layer info
 * @param data
 *  Data to print
 * @param data_length
 *  How much to print
 */
void printAppData(unsigned char *data, long data_length);

#endif
