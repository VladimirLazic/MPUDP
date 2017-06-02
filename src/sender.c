#include <network.h>
#include <zconf.h>

BlitzHeader *headers;
FileInfo file;
unsigned filenameLength = 0;
char dstIPStr[16];
char dstMACStr[18];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
Segment *segment = NULL;

void PacketHandler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);

void *DeviceThreadFunction(void *params);

void CreatePacketHeader(unsigned char *data, BlitzHeader datagram, pcap_if_t *device);

int main(int argc, char **argv)
{
    unsigned char workingInterfaces = 0;
    unsigned char thread;
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    pcap_if_t *device;
    pthread_t *device_threads;
    if (argc != 5)
    {
        printf("pathToFile Length dstIP dstMAC srcMAC\n");
        exit(-1);
    }
    file = OpenAndDivide((unsigned) atoi(argv[2]), argv[1],
                         &segment);
    printf("Forming datagrams\n");
    filenameLength = ExtractFilenameLength(file);
    if (filenameLength > FILENAME_LEN)
    {
        printf("Filename longer than %d", FILENAME_LEN);
        exit(-2);
    }
    InitDatagram(file, segment);
    if (pcap_findalldevs(&devices, errBuff) == -1)
    {
        printf("Error finding devices: %s\n", errBuff);
        exit(-3);
    }
    for (device = devices; device; device = device->next)
    {
        ///<We want all network interfaces that aren't loop back and aren't "any" (for linux any captures usb and lo)
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_UP && device->flags & PCAP_IF_RUNNING) &&
            strcasecmp(device->name, "any"))
        {
            workingInterfaces++;
            PrintInterface(device);
        }
    }
    if (!workingInterfaces)
    {
        printf("No running network interfaces were found exiting\n");
        exit(-4);
    }
    device_threads = malloc(sizeof(pthread_t) * workingInterfaces);
    workingInterfaces = 0;
    ///Setting up destination addresses to globals
    memset(dstIPStr, 0, 16);
    memcpy(dstIPStr, argv[3], 15);
    memset(dstMACStr, 0, 22);
    memcpy(dstMACStr, argv[4], 17);
    ///
    for (device = devices; device; device = device->next)
    {
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_UP && device->flags & PCAP_IF_RUNNING) &&
            strcasecmp(device->name, "any"))
        {
            if (pthread_create(&device_threads[workingInterfaces], NULL, &DeviceThreadFunction, device))
            {
                printf("Couldn't create thread for %s\n", device->name);
                exit(-5);
            }
            workingInterfaces++;
        }
    }
    for (thread = 0; thread < workingInterfaces; thread++)
    {
        pthread_join(device_threads[thread], NULL);
    }

    EraseData(&segment, file);
    free(device_threads);
    pcap_freealldevs(devices);
    return 0;

}


void *DeviceThreadFunction(void *device)
{
    pcap_if_t *thread_device = (pcap_if_t *) device;
    pcap_t *device_handle;
    char errBuffer[PCAP_ERRBUF_SIZE];
    static unsigned i = 0;
    if ((device_handle = pcap_open_live(thread_device->name,
                                        65536,
                                        1,
                                        2000,
                                        errBuffer
    )) == NULL)
    {
        printf("\nUnable to open the adapter. %s\n%s\n", thread_device->name, errBuffer);
        return NULL;
    }
    if (pcap_datalink(device_handle) != 1)
    {
        printf("Not ethernet terminating %s", thread_device->name);
        return NULL;
    }
    while (i < file.numberOfSegments)
    {
        pthread_mutex_lock(&mutex);
        if (sizeof(EthernetHeader) + sizeof(IPHeader) - 4 + sizeof(UDPHeader) + sizeof(BlitzHeader) - 8 +
            headers[i].length > MTU)
        {
            printf("Data is bigger than MTU, either fragment or set smaller length\n");
            return NULL;
        }
        unsigned char *packet = (unsigned char *) malloc(
                sizeof(EthernetHeader) + sizeof(IPHeader) - 4 + sizeof(UDPHeader) + sizeof(BlitzHeader) - 8 +
                headers[i].length);
        CreatePacketHeader(packet, headers[i], thread_device);
        memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) - 4), &headers[i],
               sizeof(BlitzHeader) - 8);
        memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) - 4 + sizeof(BlitzHeader) - 8),
               headers[i].data, headers[i].length);
        ///Send UDP datagram
        if (pcap_sendpacket(device_handle, packet,
                            sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(BlitzHeader) +
                            headers[i].length - 12) != 0)
        {
            printf("Error sending packet id: %d\n", headers[i].identification);
        } else
        {
            printf("Success sending packet id: %d by thread: %s\n", headers[i].identification, thread_device->name);
        }
        i++;
        usleep(100);
        pthread_mutex_unlock(&mutex);
        usleep(100);
    }
    return NULL;
}

void CreatePacketHeader(unsigned char *data, BlitzHeader header, pcap_if_t *device)
{
    UDPHeader *udp_hdr = (UDPHeader *) malloc(sizeof(UDPHeader));
    IPHeader *ip_hdr = (IPHeader *) malloc(sizeof(IPHeader));
    EthernetHeader *eth_hdr = (EthernetHeader *) malloc(sizeof(EthernetHeader));
    unsigned char ip_helper[sizeof(IPHeader) - sizeof(unsigned short)];
    char dstIP[16];
    char dstMAC[18];
    char srcIP[16];
    ///Setting up destinations
    strcpy(dstIP, dstIPStr);
    strcpy(dstMAC, dstMACStr);
    ///Settings up sources
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
    memset(udp_hdr, 0, sizeof(UDPHeader));
    memset(ip_hdr, 0, sizeof(IPHeader));
    memset(eth_hdr, 0, sizeof(EthernetHeader));

    ///Creating a udp header
    udp_hdr->datagramLength = htons(sizeof(BlitzHeader) - 8 + header.length + sizeof(UDPHeader));
    udp_hdr->srcPort = htons(DEFAULT_PORT);
    udp_hdr->dstPort = htons(DEFAULT_PORT);

    ///Creating a ip header
    ip_hdr->nextProtocol = 17;//0x11 UDP protocol

    SetIP(ip_hdr->dstAddr, dstIP);
    SetIP(ip_hdr->srcAddr, srcIP);
    ip_hdr->version = 4;
    ip_hdr->headerLength = 20 / 4;
    ip_hdr->tos = 0;
    ip_hdr->ttl = 128;
    ip_hdr->length = htons(sizeof(IPHeader) + sizeof(BlitzHeader) - 12 + header.length + sizeof(UDPHeader));
    ip_hdr->fragmentOffset = htons(0x800);
    memcpy(ip_helper, ip_hdr, 22);

    ///Creating ip and udp headers
    udp_hdr->checkSum = UDPCheckSum(udp_hdr, ip_hdr, header);
    ip_hdr->checkSum = IPChecksum(ip_helper);


    ///Creating a ethernet header
    SetMAC(eth_hdr->dstAddress, dstMAC);

    eth_hdr->srcAddress[0] = 0x00;
    eth_hdr->srcAddress[1] = 0x00;
    eth_hdr->srcAddress[2] = 0x00;
    eth_hdr->srcAddress[3] = 0x00;
    eth_hdr->srcAddress[4] = 0x00;
    eth_hdr->srcAddress[5] = 0x00;
    eth_hdr->type = htons(0x0800);
    memcpy(data, eth_hdr, sizeof(EthernetHeader));
    memcpy(data + sizeof(EthernetHeader), ip_hdr, sizeof(IPHeader));
    memcpy(data + sizeof(EthernetHeader) + sizeof(IPHeader) - 4, udp_hdr, sizeof(UDPHeader));

    udp_hdr = NULL;
    ip_hdr = NULL;
    eth_hdr = NULL;

    free(udp_hdr);
    free(ip_hdr);
    free(eth_hdr);
}

