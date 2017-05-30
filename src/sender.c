#include <segmenter.h>
#include <stdbool.h>
#include <network.h>

#define SEGMENT_LENGTH 512
int NumberOfPackets = 0;
Datagram datagrams[1024];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
FileInfo file;
Segment *segment = NULL;

#define NUM_OF_THREADS 5

void PacketHandler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);

void *DeviceThreadFunction(void *params);

void create_packet_header(unsigned char *datagram, Datagram data);

void FillDatagram(char *file_name);

int main(int argc, char **argv)
{
    file = OpenAndDivide(SEGMENT_LENGTH, "/home/niketic95/Documents/University/VI/ORM2/MPUDP/files/FILE.data",
                         &segment);
    EraseData(&segment, file);
    pcap_if_t *devices, *selected_devices;                        // List of network interface controllers
    pcap_if_t *device;                        // Network interface controller
    unsigned int netmask;
    char error_buffer[PCAP_ERRBUF_SIZE];    // Error buffer
    char filter_exp[] = "udp and ip";
    struct bpf_program fcode;
    pthread_t device_thread[NUM_OF_THREADS];
    int i = 0, NumberOfThreads = 0, device_number[2];

    //Filling datagrams
    printf("File to be loaded: %s\n", argv[1]);
    FillDatagram(argv[1]);

    //Printing out datagrams
    for (i = 0; i < 1024; i++)
    {
        if (datagrams[i].datagramId != -1)
            printf("%d: %s", datagrams[i].datagramId, datagrams[i].message);
    }
    printf("\n\n\n");
    pthread_t *device_threads;
    unsigned char working_intefaces = 0;
    unsigned char thread;
    if (pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        exit(-1);
    }
    for (device = devices; device; device = device->next)
    {
        /**<We want all network interfaces that aren't loop back and aren't "any" (for linux any captures usb and lo)*/
        if (device->flags & PCAP_IF_LOOPBACK)
        {
            working_intefaces++;
            PrintInterface(device);
        }
    }
    if (!working_intefaces)
    {
        printf("No running network interfaces were found exiting\n");
        exit(-2);
    }
    device_threads = malloc(sizeof(pthread_t) * working_intefaces);
    working_intefaces = 0;
    for (device = devices; device; device = device->next)
    {
        if (device->flags & PCAP_IF_LOOPBACK)
        {
            if (pthread_create(&device_threads[working_intefaces], NULL, &DeviceThreadFunction, device))
            {
                printf("Couldn't create thread for %s\n", device->name);
                exit(-3);
            }
            working_intefaces++;
        }
    }
    for (thread = 0; thread < working_intefaces; thread++)
    {
        pthread_join(device_threads[thread], NULL);
    }
    free(device_threads);

    return 0;

}

void FillDatagram(char *file_name)
{
    FILE *file;
    char line[512];
    int i = 0;


    //Annulling datagrams and datagram helper
    for (i = 0; i < 512; i++)
    {
        strcpy(datagrams[i].message, "");
        datagrams[i].datagramId = -1;
        datagrams[i].sent = false;
    }

    file = fopen(file_name, "r");

    if (file == NULL)
    {
        exit(EXIT_FAILURE);
    }

    i = 0;
    while (fgets(line, 510, file) != NULL)
    {
        if (i == 1024)
        {
            perror("File size is higher than allowed\n");
            exit(EXIT_FAILURE);
        }

        datagrams[i].datagramId = i;
        strcpy(datagrams[i].message, line);
        i++;
        NumberOfPackets = i;
    }
}

void *DeviceThreadFunction(void *device)
{
    pcap_if_t *thread_device = (pcap_if_t *) device;
    pcap_t *device_handle;                    // Descriptor of capture device
    char error_buffer[PCAP_ERRBUF_SIZE];    // Error buffer
    unsigned char packet[sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(Datagram)];
    int i = 0;

    // Open the capture device
    if ((device_handle = pcap_open_live(thread_device->name,
                                        65536,
                                        1,
                                        2000,
                                        error_buffer
    )) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", thread_device->name);
        return NULL;
    }


    for (i = 0; i < NumberOfPackets; i++)
    {
        pthread_mutex_lock(&mutex);
        if (!datagrams[i].sent)
        {
            //Create a udp datagram
            create_packet_header(packet, datagrams[i]);
            memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader)), &datagrams[i],
                   sizeof(Datagram));
            PrintRawData(packet, sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader));
            //Send a usp datagram
            if (pcap_sendpacket(device_handle, packet,
                                sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(Datagram)) != 0)
            {
                printf("Error sending packet id: %d\n", datagrams[i].datagramId);
            } else
            {
                printf("Success sending packet id: %d by thread: %s\n", datagrams[i].datagramId, thread_device->name);
                datagrams[i].sent = true;
            }
        }
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

void create_packet_header(unsigned char *datagram, Datagram data)
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
    udp_hdr->datagramLength = htons(sizeof(Datagram) + sizeof(UDPHeader));
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
    ip_hdr->length = htons(sizeof(IPHeader) + sizeof(Datagram) + sizeof(UDPHeader));
    ip_hdr->fragmentOffset = htons(0x800);
    memcpy(ip_helper, ip_hdr, 22);

    //Creating ip and udp headers
    udp_hdr->checkSum = UDPCheckSum(udp_hdr, ip_hdr, data);
    ip_hdr->checkSum = IPChecksum(ip_helper);


    //Creating a ethernet header
    eth_hdr->dstAddress[0] = 0x90;
    eth_hdr->dstAddress[1] = 0xe6;
    eth_hdr->dstAddress[2] = 0xba;
    eth_hdr->dstAddress[3] = 0xaa;
    eth_hdr->dstAddress[4] = 0xfa;
    eth_hdr->dstAddress[5] = 0xdb;


    eth_hdr->srcAddress[0] = 0xff;
    eth_hdr->srcAddress[1] = 0x2d;
    eth_hdr->srcAddress[2] = 0x27;
    eth_hdr->srcAddress[3] = 0xf3;
    eth_hdr->srcAddress[4] = 0x94;
    eth_hdr->srcAddress[5] = 0x0b;
    eth_hdr->type = htons(0x0800);

    memcpy(datagram, eth_hdr, sizeof(EthernetHeader));
    memcpy(datagram + sizeof(EthernetHeader), ip_hdr, sizeof(IPHeader));
    memcpy(datagram + sizeof(EthernetHeader) + sizeof(IPHeader) - 4, udp_hdr, sizeof(UDPHeader));

    udp_hdr = NULL;
    ip_hdr = NULL;
    eth_hdr = NULL;

    free(udp_hdr);
    free(ip_hdr);
    free(eth_hdr);
}