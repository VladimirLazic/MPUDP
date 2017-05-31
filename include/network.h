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
#include <segmenter.h>

#define DEFAULT_PORT   27015
/**
 * @struct EthernetHeader
 * @brief
 *  Ethernet header with destination/source address and type of next layer
 *
 */
#pragma pack(1)
typedef struct ethernet_header
{
    unsigned char dstAddress[6];/**<Destination address*/
    unsigned char srcAddress[6];/**<Source address*/
    unsigned short type;/**<Type of next layer*/
} EthernetHeader;
/**
 * @struct IPHeader
 * @brief
 *  Internet Protocol header with: header_length, version, type of service, length, id, fragment flags,
 *  fragment offset, Time to live,
 *  next protocol, checksum, src/dst address and option + padding
 */
#pragma pack(1)
typedef struct ip_header
{
    unsigned char headerLength :4;/**<Internet header length (4bits)*/
    unsigned char version :4;/**<Version (4b)*/
    unsigned char tos;/**<Type of Service  (8b)*/
    unsigned short length;/**<Total length (16b)*/
    unsigned short identification;/**<Identification (16b)*/
    unsigned short fragmentFlags :3;/**<Flags (3b)*/
    unsigned short fragmentOffset :13;/**<Fragment offset (13b)*/
    unsigned char ttl;/**<Time To Live (8b)*/
    unsigned char nextProtocol;/**<Protocol of next layer (8b)*/
    unsigned short checkSum :16;/**<Header checksum (16b)*/
    unsigned char srcAddr[4];/**<Source address (4B)*/
    unsigned char dstAddr[4];/**<Destination address (4B)*/
    unsigned int optionPadding;/**<Internet header length (Vary)*/
} IPHeader;

/**
 * @struct UDPHeader
 * @brief
 *  User Datagram Protocol header structure
 *      Contains src/dst port length of datagram and UDP checksum
 */
#pragma pack(1)
typedef struct udp_header
{
    unsigned short srcPort;/**<Source port (16b)*/
    unsigned short dstPort;/**<Destination port (16b)*/
    unsigned short datagramLength;/**<Total Length (16b)*/
    unsigned short checkSum;/**<Header Checksum (16b)*/
} UDPHeader;
/**
 * @struct Datagram
 * @brief
 *  datagram data
 */
#pragma pack(1)
typedef struct datagram
{
    unsigned char *data;
    int datagramId;
    bool sentCorrectly;
} Datagram;

/**
 * @brief
 *  Prints detailed info about the device including its IPv4 info
 * @param dev
 *  Device descriptor
 */
void PrintInterface(pcap_if_t *dev);

/**
 * @brief
 *  Converts sockaddr to human readable text
 * @param address
 *  Socket address structure
 * @return
 *  Human readable text
 */
char *ConvertSockaddrToString(struct sockaddr *address);

/**
 * @brief
 *  Prints data for given len
 * @param data
 *  Data to print
 * @param data_length
 *  How much to print
 */
void PrintRawData(unsigned char *data, long data_length);

/**
 * @brief
 *  Prints Ethernet header info
 * @param eh
 *  EthernetHeader to print
 */
void PrintEthernetHeader(EthernetHeader *eh);

/**
 * @brief
 *  Prints IP header info
 * @param ih
 *  IP header to print
 */
void PrintIPHeader(IPHeader *ih);

/**
 * @brief
 *  Prints UDP header info
 * @param uh
 *  UDP header to print
 */
void PrintUDPHeader(UDPHeader *uh);

/**
 * @brief
 *  Prints top layer info
 * @param data
 *  Data to print
 * @param data_length
 *  How much to print
 */
void PrintAppData(unsigned char *data, long data_length);

/**
 * @brief
 *  Fits 2 chars into a short
 * @param X
 *  Bigger half of the short
 * @param Y
 *  Lower half of the short
 * @return
 *  Returns the short
 */
unsigned short BytesTo16(unsigned char X, unsigned char Y);


/**
 *  @brief
 *  Calculates checksum for UDP header
 * @param udp
 *  UDP Header
 * @param ip
 *  IP Header
 * @param data
 *  Raw data
 * @return
 *  Checksum
 */
unsigned short UDPCheckSum(UDPHeader *udp, IPHeader *ip, Datagram data, unsigned short len);

/**
 * @brief
 *  Calculates checksum for IP header
 * @param ip
 *  IP Header
 * @return
 *  Checksum
 */
unsigned short IPChecksum(unsigned char *ip);

#endif
