#include <network.h>

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

BlitzHeader *headers;
FileInfo file;
unsigned filenameLength = 0;
unsigned char currentPacket = 1;
unsigned char dstIP[4];
unsigned char srcMAC[6];

void PacketHandler(unsigned char *param, const struct pcap_pkthdr *packetHeader, const unsigned char *packetData);

void *DeviceThreadFunction(void *params);

void CreatePacketHeader(unsigned char *data, BlitzHeader header, pcap_if_t *device);
int main()
{
    pcap_if_t *devices;
    pcap_if_t *device;

    pthread_t *device_threads;
    unsigned char workingInterfaces = 0;
    unsigned char thread;
    char errBuffer[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devices, errBuffer) == -1)
    {
        printf("Error in finding devices: %s\n", errBuffer);
        exit(-1);
    }
    for (device = devices; device; device = device->next)
    {
        /**<We want all network interfaces that aren't loop back and aren't "any" (for linux any captures usb and lo)*/
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_RUNNING && device->flags & PCAP_IF_UP) &&
            strcasecmp(device->name, "any"))
        {
            workingInterfaces++;
            PrintInterface(device);
        }
    }
    if (!workingInterfaces)
    {
        printf("No running network interfaces were found exiting\n");
        exit(-2);
    }
    device_threads = malloc(sizeof(pthread_t) * workingInterfaces);
    workingInterfaces = 0;
    for (device = devices; device; device = device->next)
    {
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_RUNNING && device->flags & PCAP_IF_UP) &&
            strcasecmp(device->name, "any"))
        {
            if (pthread_create(&device_threads[workingInterfaces], NULL, &DeviceThreadFunction, device))
            {
                printf("Couldn't create thread for %s\n", device->name);
                exit(-3);
            }
            workingInterfaces++;
        }
    }
    for (thread = 0; thread < workingInterfaces; thread++)
    {
        pthread_join(device_threads[thread], NULL);
    }
    free(device_threads);
    ReconstructFromHeaders(headers);
    return 0;
}

void *DeviceThreadFunction(void *device)
{
    pcap_if_t *threadDevice = (pcap_if_t *) device;
    pcap_t *deviceHandle;
    BlitzHeader response;
    char errBuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
    char filterExpr[] = "ip and udp";
    unsigned int netmask = 0;
#ifdef _WIN32
    if (threadDevice->addresses != NULL)
    netmask = ((struct sockaddr_in *)(threadDevice->addresses->netmask))->sin_addr.S_un.S_addr;
     else
    netmask = 0xffffff;
#else
    if (!threadDevice->addresses->netmask)
        netmask = 0;
    else
        netmask = ((struct sockaddr_in *) (threadDevice->addresses->netmask))->sin_addr.s_addr;
#endif
    if ((deviceHandle = pcap_open_live(threadDevice->name,
                                       65536,
                                       1,
                                       2000,
                                       errBuffer
    )) == NULL)
    {
        printf("\n%s\n", errBuffer);
        return NULL;
    }
    if(pcap_datalink(deviceHandle) != 1)
    {
        printf("Not ethernet terminating %s", threadDevice->name);
        return  NULL;
    }
    if (pcap_compile(deviceHandle, &fcode, filterExpr, 1, netmask))
    {
        printf("\n Unable to compile the packet filter. Check the syntax.\n");
        return NULL;
    }
    if (pcap_setfilter(deviceHandle, &fcode) < 0)
    {
        printf("\n Error setting the filter.\n");
        return NULL;
    }


    while(currentPacket == 1)
    {
        pthread_mutex_lock(&mutex);
        pcap_loop(deviceHandle, 1, PacketHandler, NULL);
        pthread_mutex_unlock(&mutex);
    }
    ///Response init
    pthread_mutex_lock(&mutex);
    memset(response.filename,0,FILENAME_LEN);
    memcpy(response.filename, "RESPONSE", 8);
    response.totalPackets = headers[0].totalPackets;
    response.length = 0;///No data attached
    response.identification = headers[0].identification;
    response.signalization = SIGNAL;
    response.ack =(unsigned char)(currentPacket - 1);
    unsigned char *packet = (unsigned char*) malloc(sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(BlitzHeader) - 12);

    CreatePacketHeader(packet, response, threadDevice);

    memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) - 4), &response,
           sizeof(BlitzHeader) - 8);
    ///Send UDP datagram
    if (pcap_sendpacket(deviceHandle, packet,
                        sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(BlitzHeader) - 12) != 0)
    {
        printf("Error sending response id: %d\n", response.identification);
    }
    pthread_mutex_unlock(&mutex);
    while(currentPacket <= headers[0].totalPackets)
    {
        pthread_mutex_lock(&mutex);
        pcap_loop(deviceHandle, 1, PacketHandler, NULL);
        response.identification = currentPacket;
        response.ack =(unsigned char)(currentPacket - 1);
        packet = (unsigned char*) malloc(sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(BlitzHeader) - 12);
        CreatePacketHeader(packet, response, threadDevice);
        memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) - 4), &response,
               sizeof(BlitzHeader) - 8);
        if (pcap_sendpacket(deviceHandle, packet,
                            sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(BlitzHeader) - 12) != 0)
        {
            printf("Error sending response id: %d\n", response.identification);
        }
        pthread_mutex_unlock(&mutex);
        MySleep(5);
    }
    return NULL;
}

void PacketHandler(unsigned char *param, const struct pcap_pkthdr *packetHeader, const unsigned char *packetData)
{
    BlitzHeader temp;
    unsigned long appLength;
    unsigned char *appData;
    static long long bytes = 0;
    static long long startTime = 0,endTime = 0;
    EthernetHeader *eh;
    IPHeader *ih;
    UDPHeader *udph;
    eh = (EthernetHeader *) packetData;
    ih = (IPHeader *) (packetData + sizeof(EthernetHeader));
    udph = (UDPHeader *) ((unsigned char *) ih + ih->headerLength * 4);
    appLength = (unsigned long) (ntohs(udph->datagramLength) - 8);
    appData = (unsigned char *) udph + 8;
    if(currentPacket == 1)
    {
        startTime = packetHeader->ts.tv_sec * 1000000 + packetHeader->ts.tv_usec;
    }
    if (appLength > sizeof(BlitzHeader) - 8)
    {
        memcpy(&temp, appData, sizeof(BlitzHeader) - 8);
        if (temp.signalization == SIGNAL)
        {
            dstIP[0] = ih->srcAddr[0];
            dstIP[1] = ih->srcAddr[1];
            dstIP[2] = ih->srcAddr[2];
            dstIP[3] = ih->srcAddr[3];
            if (temp.identification == currentPacket && currentPacket == 1)
            {
                srcMAC[0] = eh->dstAddress[0];
                srcMAC[1] = eh->dstAddress[1];
                srcMAC[2] = eh->dstAddress[2];
                srcMAC[3] = eh->dstAddress[3];
                srcMAC[4] = eh->dstAddress[4];
                srcMAC[5] = eh->dstAddress[5];
                headers = (BlitzHeader*)malloc(sizeof(BlitzHeader)*temp.totalPackets);
                memcpy(&headers[0], appData, sizeof(BlitzHeader)-8);
                headers[0].data = (unsigned char *) malloc(temp.length + 1);
                memset(headers[0].data,  0, temp.length + 1);
                memcpy(headers[0].data, appData + sizeof(BlitzHeader) - 8, temp.length);
                printf("\n\tBlitz detected\n");
                printf("%u.%u.%u.%u from %u.%u.%u.%u ", ih->dstAddr[0], ih->dstAddr[1], ih->dstAddr[2], ih->dstAddr[3],
                       ih->srcAddr[0], ih->srcAddr[1], ih->srcAddr[2], ih->srcAddr[3]);
                printf("got packet %u ", headers[0].identification);
                printf("of %u\n", headers[0].totalPackets);
                printf("%s\n",headers[0].data);
                currentPacket++;
                bytes += packetHeader->len;
                if(currentPacket == headers[0].totalPackets + 1)
                {
                    endTime = packetHeader->ts.tv_sec * 1000000 + packetHeader->ts.tv_usec;
                    printf("Total: %llu [Bytes]\n rate: %f [bits/sec]\n",bytes,(double)(bytes*8)/(endTime - startTime)*1000000);
                }
            }
            else if (temp.identification == currentPacket && currentPacket != 1)
            {
                memcpy(&headers[currentPacket - 1], appData, sizeof(BlitzHeader)-8);
                headers[currentPacket - 1].data = (unsigned char *) malloc(temp.length + 1);
                memset(headers[currentPacket - 1].data,  0, temp.length + 1);
                memcpy(headers[currentPacket - 1].data, appData + sizeof(BlitzHeader) - 8, temp.length);
                printf("\n\tBlitz detected\n");
                printf("%u.%u.%u.%u from %u.%u.%u.%u ", ih->dstAddr[0], ih->dstAddr[1], ih->dstAddr[2], ih->dstAddr[3],
                       ih->srcAddr[0], ih->srcAddr[1], ih->srcAddr[2], ih->srcAddr[3]);
                printf("got packet %u ", headers[currentPacket - 1].identification);
                printf("of %u\n", headers[currentPacket - 1].totalPackets);
                printf("File: %s\n", headers[currentPacket - 1].filename);
                printf("%s\n", headers[currentPacket - 1].data);
                currentPacket++;
                bytes += packetHeader->len;
                if(currentPacket == headers[0].totalPackets + 1)
                {
                    endTime = packetHeader->ts.tv_sec * 1000000 + packetHeader->ts.tv_usec;
                    printf("Total: %llu [Bytes]\n rate: %f [bits/sec]\n",bytes,(double)(bytes*8)/(endTime - startTime)*1000000);
                }
            }
        }
    }
}


void CreatePacketHeader(unsigned char *data, BlitzHeader header, pcap_if_t *device)
{
    UDPHeader *UDPHdr = (UDPHeader *) malloc(sizeof(UDPHeader));
    IPHeader *IPHdr = (IPHeader *) malloc(sizeof(IPHeader));
    EthernetHeader *ETHdr = (EthernetHeader *) malloc(sizeof(EthernetHeader));
    unsigned char IPHelper[sizeof(IPHeader) - sizeof(unsigned short)];
    char srcIP[16];
    ///Setting up destinations
    pcap_addr_t *addr;
    for (addr = device->addresses; addr; addr = addr->next)
    {
        if (addr->addr->sa_family == AF_INET)
        {
            if (addr->addr)
                strcpy(srcIP, ConvertSockaddrToString(addr->addr));
        }
    }

    ///Initializing
    memset(UDPHdr, 0, sizeof(UDPHeader));
    memset(IPHdr, 0, sizeof(IPHeader));
    memset(ETHdr, 0, sizeof(EthernetHeader));

    ///Creating a udp header
    UDPHdr->datagramLength = htons(sizeof(BlitzHeader) - 8 + sizeof(UDPHeader));
    UDPHdr->srcPort = htons(DEFAULT_PORT);
    UDPHdr->dstPort = htons(DEFAULT_PORT);

    ///Creating an ip header
    IPHdr->nextProtocol = 17;//0x11 UDP protocol
    IPHdr->dstAddr[0]=dstIP[0];
    IPHdr->dstAddr[1]=dstIP[1];
    IPHdr->dstAddr[2]=dstIP[2];
    IPHdr->dstAddr[3]=dstIP[3];
    SetIP(IPHdr->srcAddr, srcIP);
    IPHdr->version = 4;
    IPHdr->headerLength = 20 / 4;
    IPHdr->tos = 0;
    IPHdr->ttl = 128;
    IPHdr->length = htons(sizeof(IPHeader) + sizeof(BlitzHeader) - 12 + sizeof(UDPHeader));
    IPHdr->fragmentOffset = htons(0x800);
    memcpy(IPHelper, IPHdr, 22);

    ///Creating ip and udp headers
    UDPHdr->checkSum = UDPCheckSum(UDPHdr, IPHdr, header);
    IPHdr->checkSum = IPChecksum(IPHelper);


    ///Creating a ethernet header
    ETHdr->srcAddress[0]=srcMAC[0];
    ETHdr->srcAddress[1]=srcMAC[1];
    ETHdr->srcAddress[2]=srcMAC[2];
    ETHdr->srcAddress[3]=srcMAC[3];
    ETHdr->srcAddress[4]=srcMAC[4];
    ETHdr->srcAddress[5]=srcMAC[5];
    ETHdr->dstAddress[0] = 0xff;
    ETHdr->dstAddress[1] = 0xff;
    ETHdr->dstAddress[2] = 0xff;
    ETHdr->dstAddress[3] = 0xff;
    ETHdr->dstAddress[4] = 0xff;
    ETHdr->dstAddress[5] = 0xff;
    ETHdr->type = htons(0x0800);
    memcpy(data, ETHdr, sizeof(EthernetHeader));
    memcpy(data + sizeof(EthernetHeader), IPHdr, sizeof(IPHeader));
    memcpy(data + sizeof(EthernetHeader) + sizeof(IPHeader) - 4, UDPHdr, sizeof(UDPHeader));

    UDPHdr = NULL;
    IPHdr = NULL;
    ETHdr = NULL;

    free(UDPHdr);
    free(IPHdr);
    free(ETHdr);
}
