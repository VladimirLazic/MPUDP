#include <network.h>

void PrintInterface(pcap_if_t *dev)
{
    pcap_addr_t *addr;

    printf("\n\t ---------------------- Network interface "
                   "---------------------------- \n\n");
    printf("\t Name: \t\t %s\n", dev->name);
    if (dev->description)
        printf("\t Description: \t %s\n", dev->description);
    for (addr = dev->addresses; addr; addr = addr->next)
    {
        if (addr->addr->sa_family == AF_INET)
        {
            printf("\n\t IPv4:\n");
            if (addr->netmask)
                printf("\t\tNetmask: %s\n", ConvertSockaddrToString(addr->netmask));
            if (addr->broadaddr)
                printf("\t\tBroadcast: %s\n",
                       ConvertSockaddrToString(addr->broadaddr));
            if (addr->addr)
                printf("\t\tAddress: %s\n", ConvertSockaddrToString(addr->addr));
        }
    }
}

char *ConvertSockaddrToString(struct sockaddr *address)
{
    return inet_ntoa(((struct sockaddr_in *) address)->sin_addr);
}

void PrintRawData(unsigned char *data, long data_length)
{
    int i;
    printf("\n-------------------------------------------------------------\n\t");
    for (i = 0; i < data_length; i = i + 1)
    {
        printf("%.2x ", data[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n\t");
        } else if ((i + 1) % 8 == 0)
        {
            printf(" ");
        }
    }
    printf("\n-------------------------------------------------------------");
}

void PrintEthernetHeader(EthernetHeader *eh)
{
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

void PrintIPHeader(IPHeader *ih)
{
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

void PrintUDPHeader(UDPHeader *uh)
{

    printf("\n=============================================================");
    printf("\n\tAPPLICATION LAYER   -  User Datagram Protocol (UDP)");
    printf("\n\tChecksum:\t\t%u", ntohs(uh->checkSum));
    printf("\n\tData Length:\t\t%u", ntohs(uh->datagramLength));
    printf("\n\tDestination port:\t%u", ntohs(uh->dstPort));
    printf("\n\tSource port:\t\t%u", ntohs(uh->srcPort));
    printf("\n=============================================================");
    return;
}

void PrintAppData(unsigned char *data, long data_length)
{
    printf("\n=============================================================");
    printf("\n\tAPPLICATION LAYER   -  Application Data\n");
    PrintRawData(data, data_length);
    printf("\n=============================================================");
}

unsigned short BytesTo16(unsigned char X, unsigned char Y)
{
    unsigned short Tmp = X;
    Tmp = Tmp << 8;
    Tmp = Tmp | Y;
    return Tmp;
}

unsigned short UDPCheckSum(UDPHeader *udp, IPHeader *ip, BlitzHeader data)
{
    unsigned short CheckSum = 0;

///length of pseudo_header = Data length + 8 bytes UDP header + Two 4 byte IP's + 1 byte protocol
    unsigned short pseudo_length = sizeof(BlitzHeader) - 8 + data.length + 8 + 9;

///If bytes are not an even number, add an extra.
    pseudo_length += pseudo_length % 2;

///This is just UDP + Data length.
    unsigned short length = sizeof(BlitzHeader) - 8 + data.length + 8;

///Init
    unsigned char *pseudo_header = (unsigned char *) malloc(pseudo_length * sizeof(unsigned char));
    for (int i = 0; i < pseudo_length; i++)
    {
        pseudo_header[i] = 0x00;
    }

///Protocol
    memcpy(pseudo_header, &(ip->nextProtocol), 1);

///Source and dst IP
    memcpy(pseudo_header + 1, &(ip->srcAddr), 4);
    memcpy(pseudo_header + 5, &(ip->dstAddr), 4);

///Length is not network byte order yet
    length = htons(length);

///Included twice
    memcpy(pseudo_header + 9, (void *) &length, 2);
    memcpy(pseudo_header + 11, (void *) &length, 2);

///Source Port
    memcpy(pseudo_header + 13, &(udp->srcPort), 2);

///Dst Port
    memcpy(pseudo_header + 15, &(udp->dstPort), 2);


    memcpy(pseudo_header + 17, &data, sizeof(BlitzHeader) - 8);
    memcpy(pseudo_header + 17 + sizeof(BlitzHeader) - 8, data.data, data.length);


    for (int i = 0; i < pseudo_length; i += 2)
    {
        unsigned short Tmp = BytesTo16(pseudo_header[i], pseudo_header[i + 1]);
        unsigned short Difference = (unsigned short) 65535 - CheckSum;
        CheckSum += Tmp;
        if (Tmp > Difference) { CheckSum += 1; }
    }
    CheckSum = ~CheckSum; //One's complement

    pseudo_header = NULL;
    free(pseudo_header);

    return CheckSum;
}

unsigned short IPChecksum(unsigned char *ip)
{
    unsigned short CheckSum = 0;
    for (int i = 0; i < 22; i += 2)
    {
        unsigned short Tmp = BytesTo16(ip[i], ip[i + 1]);
        unsigned short Difference = (unsigned short) 65535 - CheckSum;
        CheckSum += Tmp;
        if (Tmp > Difference) { CheckSum += 1; }
    }
    CheckSum = ~CheckSum;
    return htons(CheckSum);
}

void PrintDatagram(unsigned len)
{
    unsigned i = 0;
    for (i = 0; i < len; i++)
    {
        unsigned j = 0;
        printf("Packets: %u\nIdentification: %u\nLength: %u\nAcknowledge: %u\n Data:\n", headers[i].totalPackets,
               headers[i].identification, headers[i].length, headers[i].ack);
        for (j = 0; j < headers[i].length; j++)
        {
            if (!j % 8)
            {
                printf(" ");
            }
            if (!j % 16)
            {
                printf("\n");
            }
            printf("%c", headers[i].data[j]);
        }
    }
    printf("\n");
}

void InitDatagram(FileInfo fileinfo, Segment *segment)
{
    int i = 0;
    headers = (BlitzHeader *) malloc(fileinfo.numberOfSegments * sizeof(BlitzHeader));
    for (i = 0; i < fileinfo.numberOfSegments; i++)
    {
        headers[i].identification = segment[i].segmentNumber;
        headers[i].totalPackets = fileinfo.numberOfSegments;
        headers[i].signalization = SIGNAL;
        memset(headers[i].filename, 0, FILENAME_LEN);
        memcpy(headers[i].filename, file.fileName, filenameLength);
        headers[i].ack = 0;
        if (i != fileinfo.numberOfSegments - 1)
        {
            headers[i].length = fileinfo.lengthOfSegment;
        } else
        {
            headers[i].length = fileinfo.lengthOfLastSegment;
        }
        headers[i].data = (unsigned char *) malloc(headers[i].length);
        memset(headers[i].data, 0, headers[i].length);
        memcpy(headers[i].data, segment[i].data, headers[i].length);
    }
}

void SetIP(unsigned char IP[4], char *IPStr)
{
    char *token;
    unsigned char ipPart;
    int i = 0;
    token = strtok(IPStr, ".");
    if (token == NULL)
    {
        printf("Bad IP\n");
        exit(EXIT_FAILURE);
    }
    ipPart = (unsigned char) atoi(token);
    IP[0] = ipPart;
    for (i = 1; i < 4; i++)
    {
        token = strtok(NULL, ".");
        if (token == NULL)
        {
            printf("Bad IP\n");
            exit(EXIT_FAILURE);
        }
        ipPart = (unsigned char) atoi(token);
        IP[i] = ipPart;
    }
}

void SetMAC(unsigned char MAC[6], char *MACStr)
{
    char *token;
    unsigned char macPart;
    int i = 0;
    token = strtok(MACStr, ":");
    if (token == NULL)
    {
        printf("Bad MAC\n");
        exit(EXIT_FAILURE);
    }
    macPart = (unsigned char) strtol(token, NULL, 16);
    MAC[0] = macPart;
    for (i = 1; i < 6; i++)
    {
        token = strtok(NULL, ":");
        if (token == NULL)
        {
            printf("Bad MAC\n");
            exit(EXIT_FAILURE);
        }
        macPart = (unsigned char) strtol(token, NULL, 16);
        MAC[i] = macPart;
    }
}