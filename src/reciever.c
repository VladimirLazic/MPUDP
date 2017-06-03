#include <network.h>

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

BlitzHeader *headers;
FileInfo file;
unsigned filenameLength = 0;

void PacketHandler(unsigned char *param, const struct pcap_pkthdr *packetHeader, const unsigned char *packetData);

void *DeviceThreadFunction(void *params);

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
    return 0;
}

void *DeviceThreadFunction(void *device)
{
    pcap_if_t *threadDevice = (pcap_if_t *) device;
    pcap_t *deviceHandle;
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

    pcap_loop(deviceHandle, 0, PacketHandler, NULL);

    return NULL;
}


/**
 * @todo
 *  Get timestamps from packetHeader
 *
 */

void PacketHandler(unsigned char *param, const struct pcap_pkthdr *packetHeader, const unsigned char *packetData)
{
    pthread_mutex_lock(&mutex);
    BlitzHeader temp;
    unsigned long size = 0;
    unsigned long appLength;
    unsigned char *appData;
    EthernetHeader *eh;
    IPHeader *ih;
    UDPHeader *udph;
    eh = (EthernetHeader *) packetData;
    ih = (IPHeader *) (packetData + sizeof(EthernetHeader));
    udph = (UDPHeader *) ((unsigned char *) ih + ih->headerLength * 4);
    appLength = (unsigned long) (ntohs(udph->datagramLength) - 8);
    appData = (unsigned char *) udph + 8;

    if (appLength > sizeof(BlitzHeader) - 8)
    {
        memcpy(&temp, appData, sizeof(BlitzHeader) - 8);
        if (temp.signalization == SIGNAL)
        {
            printf("\n___________________________________________\n");
            printf("\tBlitz detected\n");
            printf("-------------------------------------------\n");
            printf("%u.%u.%u.%u from %u.%u.%u.%u", ih->dstAddr[0], ih->dstAddr[1], ih->dstAddr[2], ih->dstAddr[3],
                   ih->srcAddr[0], ih->srcAddr[1], ih->srcAddr[2], ih->srcAddr[3]);
            printf("got packet %u ", temp.identification);
            printf("of %u\n", temp.totalPackets);
            printf("File: %s\n", temp.filename);
            temp.data = (unsigned char *) malloc(temp.length + 1);
            memset(temp.data, 0, temp.length + 1);
            memcpy(temp.data, appData + sizeof(BlitzHeader) - 8, temp.length);
            printf("%s\n", temp.data);
            /*
            PrintEthernetHeader(eh);
            PrintIPHeader(ih);
            PrintUDPHeader(udph);
            PrintRawData(temp.data, size);
            */
        }
    }
    pthread_mutex_unlock(&mutex);
}
