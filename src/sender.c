#include <segmenter.h>
#include <stdbool.h>
#include <network.h>

Datagram *datagrams;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
FileInfo file;
Segment *segment = NULL;

void PacketHandler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);

void *DeviceThreadFunction(void *params);

void create_packet_header(unsigned char *data, Datagram datagram, unsigned short dataLen);

void InitDatagram(FileInfo fileinfo, Segment *pSegment);

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
        printf("pathToFile Length dstIP dstMAC\n");
        exit(-1);
    }
    file = OpenAndDivide((unsigned) atoi(argv[2]), argv[1],
                         &segment);
    printf("Forming datagrams\n");
    InitDatagram(file, segment);
    if (pcap_findalldevs(&devices, errBuff) == -1)
    {
        printf("Error finding devices: %s\n", errBuff);
        exit(-1);
    }
    for (device = devices; device; device = device->next)
    {
        ///<We want all network interfaces that aren't loop back and aren't "any" (for linux any captures usb and lo)
        if (device->flags & PCAP_IF_LOOPBACK)
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
        if (device->flags & PCAP_IF_LOOPBACK)
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
    EraseData(&segment, file);
    free(device_threads);
    pcap_freealldevs(devices);
    return 0;

}

void InitDatagram(FileInfo fileinfo, Segment *segment)
{
    int i = 0;
    datagrams = (Datagram *) malloc(fileinfo.numberOfSegments * sizeof(Datagram));
    for (i = 0; i < fileinfo.numberOfSegments; i++)
    {
        datagrams[i].datagramId = segment[i].segmentNumber;
        datagrams[i].sentCorrectly = false;
        if (i != fileinfo.numberOfSegments - 1)
        {
            datagrams[i].data = (unsigned char *) malloc(fileinfo.lengthOfSegment);
            memcpy(datagrams[i].data, segment[i].data, fileinfo.lengthOfSegment);
        } else
        {
            datagrams[i].data = (unsigned char *) malloc(fileinfo.lengthOfLastSegment);
            memcpy(datagrams[i].data, segment[i].data, fileinfo.lengthOfLastSegment);
        }
    }
}


void *DeviceThreadFunction(void *device)
{
    pcap_if_t *thread_device = (pcap_if_t *) device;
    pcap_t *device_handle;
    char errBuffer[PCAP_ERRBUF_SIZE];
    unsigned char packet[sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(Datagram)];
    int i = 0;
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


    for (i = 0; i < file.numberOfSegments; i++)
    {
        pthread_mutex_lock(&mutex);
        unsigned len = 0;
        unsigned char *packet;
        if (!datagrams[i].sentCorrectly)
        {
            if (i != file.numberOfSegments - 1)
            {
                len = file.lengthOfSegment;
            } else
            {
                len = file.lengthOfLastSegment - 1;
            }
            packet = (unsigned char *) malloc(
                    sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(datagrams[i].datagramId) +
                    len);
            printf("%u\n", sizeof(datagrams[i].datagramId) + len);
            create_packet_header(packet, datagrams[i], sizeof(datagrams[i].datagramId) + len);
            memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader)), &(datagrams[i].datagramId),
                   sizeof(datagrams[i].datagramId));
            memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) +
                    sizeof(datagrams[i].datagramId)), datagrams[i].data,
                   len);
            PrintRawData(packet, sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader));
            //Send a usp datagram
            if (pcap_sendpacket(device_handle, packet,
                                sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) +
                                sizeof(datagrams[i].datagramId) + len) != 0)
            {
                printf("Error sending packet id: %d\n", datagrams[i].datagramId);
            } else
            {
                printf("Success sending packet id: %d by thread: %s\n", datagrams[i].datagramId, thread_device->name);
                datagrams[i].sentCorrectly = true;
            }
        }
        free(packet);
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

void create_packet_header(unsigned char *data, Datagram datagram, unsigned short dataLen)
{
    UDPHeader *udp_hdr = (UDPHeader *) malloc(sizeof(UDPHeader));
    IPHeader *ip_hdr = (IPHeader *) malloc(sizeof(IPHeader));
    EthernetHeader *eth_hdr = (EthernetHeader *) malloc(sizeof(EthernetHeader));
    unsigned char ip_helper[sizeof(IPHeader) - sizeof(unsigned short)];

    //Initializing
    memset(udp_hdr, 0, sizeof(UDPHeader));
    memset(ip_hdr, 0, sizeof(UDPHeader));
    memset(eth_hdr, 0, sizeof(UDPHeader));

    //Creating a udp header
    udp_hdr->datagramLength = htons(dataLen + sizeof(UDPHeader));
    udp_hdr->srcPort = htons(DEFAULT_PORT);
    udp_hdr->dstPort = htons(DEFAULT_PORT);

    //Creating a ip header
    ip_hdr->nextProtocol = 17;//0x11 UDP protocol

    ip_hdr->dstAddr[0] = 192;
    ip_hdr->dstAddr[1] = 168;
    ip_hdr->dstAddr[2] = 0;
    ip_hdr->dstAddr[3] = 12;

    ip_hdr->srcAddr[0] = 192;
    ip_hdr->srcAddr[1] = 168;
    ip_hdr->srcAddr[2] = 0;
    ip_hdr->srcAddr[3] = 107;
    ip_hdr->version = 4;
    ip_hdr->headerLength = 20 / 4;
    ip_hdr->tos = 0;
    ip_hdr->ttl = 128;
    ip_hdr->length = htons(sizeof(IPHeader) + dataLen + sizeof(UDPHeader));
    ip_hdr->fragmentOffset = htons(0x800);
    memcpy(ip_helper, ip_hdr, 22);

    //Creating ip and udp headers
    udp_hdr->checkSum = UDPCheckSum(udp_hdr, ip_hdr, datagram, dataLen);
    ip_hdr->checkSum = IPChecksum(ip_helper);


    //Creating a ethernet header
    eth_hdr->dstAddress[0] = 0x90;
    eth_hdr->dstAddress[1] = 0xe6;
    eth_hdr->dstAddress[2] = 0xba;
    eth_hdr->dstAddress[3] = 0xaa;
    eth_hdr->dstAddress[4] = 0xfa;
    eth_hdr->dstAddress[5] = 0xdb;


    eth_hdr->srcAddress[0] = 0x14;
    eth_hdr->srcAddress[1] = 0x2d;
    eth_hdr->srcAddress[2] = 0x27;
    eth_hdr->srcAddress[3] = 0xf3;
    eth_hdr->srcAddress[4] = 0x94;
    eth_hdr->srcAddress[5] = 0x0b;
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