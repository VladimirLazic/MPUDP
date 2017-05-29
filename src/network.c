#include <network.h>

void printInterface(pcap_if_t *dev) {
    pcap_addr_t *addr;

    printf("\n\t ---------------------- Network interface "
                   "---------------------------- \n\n");
    printf("\t Name: \t\t %s\n", dev->name);
    if (dev->description)
        printf("\t Description: \t %s\n", dev->description);
    for (addr = dev->addresses; addr; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            printf("\n\t IPv4:\n");
            if (addr->netmask)
                printf("\t\tNetmask: %s\n", convertSockaddrToString(addr->netmask));
            if (addr->broadaddr)
                printf("\t\tBroadcast: %s\n",
                       convertSockaddrToString(addr->broadaddr));
            if (addr->addr)
                printf("\t\tAddress: %s\n", convertSockaddrToString(addr->addr));
        }
    }
}

char *convertSockaddrToString(struct sockaddr *address) {
    return inet_ntoa(((struct sockaddr_in *) address)->sin_addr);
}

void printRawData(unsigned char *data, long data_length) {
    int i;
    printf("\n-------------------------------------------------------------\n\t");
    for (i = 0; i < data_length; i = i + 1) {
        printf("%.2x ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n\t");
        } else if ((i + 1) % 8 == 0) {
            printf(" ");
        }
    }
    printf("\n-------------------------------------------------------------");
}

void printEthernetHeader(EthernetHeader *eh) {
    printf("\n=============================================================");
    printf("\n\tDATA LINK LAYER  -  Ethernet");
    printf("\n\tDestination address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
           eh->dstAddress[0], eh->dstAddress[1], eh->dstAddress[2],
           eh->dstAddress[3], eh->dstAddress[4], eh->dstAddress[5]);
    printf("\n\tSource address:\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
           eh->srcAddress[0], eh->srcAddress[1], eh->srcAddress[2],
           eh->srcAddress[3], eh->srcAddress[4], eh->srcAddress[5]);
    printf("\n\tNext protocol:\t\t0x%.4x", ntohs(eh->type));
    printf("\n=============================================================");
    return;
}

void printIPHeader(IPHeader *ih) {
    printf("\n=============================================================");
    printf("\n\tNETWORK LAYER  -  Internet Protocol (IP)");
    printf("\n\tVersion:\t\t%u", ih->version);
    printf("\n\tHeader Length:\t\t%u", ih->headerLength * 4);
    printf("\n\tType of Service:\t%u", ih->tos);
    printf("\n\tTotal length:\t\t%u", ntohs(ih->length));
    printf("\n\tIdentification:\t\t%u", ntohs(ih->identification));
    printf("\n\tFlags:\t\t\t%u", ntohs(ih->fragmentFlags));
    printf("\n\tFragment offset:\t%u", ntohs(ih->fragmentOffset));
    printf("\n\tTime-To-Live:\t\t%u", ih->ttl);
    printf("\n\tNext protocol:\t\t%u", ih->nextProtocol);
    printf("\n\tHeader checkSum:\t%u", ntohs(ih->checkSum));
    printf("\n\tSource:\t\t\t%u.%u.%u.%u", ih->srcAddr[0], ih->srcAddr[1],
           ih->srcAddr[2], ih->srcAddr[3]);
    printf("\n\tDestination:\t\t%u.%u.%u.%u", ih->dstAddr[0], ih->dstAddr[1],
           ih->dstAddr[2], ih->dstAddr[3]);
    printf("\n=============================================================");
    return;
}

void printUDPHeader(UDPHeader *uh) {

    printf("\n=============================================================");
    printf("\n\tAPPLICATION LAYER   -  User Datagram Protocol (UDP)");
    printf("\n\tChecksum:\t\t%u", ntohs(uh->checkSum));
    printf("\n\tData Length:\t\t%u", ntohs(uh->datagramLength));
    printf("\n\tDestination port:\t%u", ntohs(uh->dstPort));
    printf("\n\tSource port:\t\t%u", ntohs(uh->srcPort));
    printf("\n=============================================================");
    return;
}

void printAppData(unsigned char *data, long data_length) {
    printf("\n=============================================================");
    printf("\n\tAPPLICATION LAYER   -  Application Data\n");
    printRawData(data, data_length);
    printf("\n=============================================================");
}