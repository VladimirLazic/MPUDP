#include <segmenter.h>
#include <stdbool.h>
#include <network.h>


int NumberOfPackets = 0;
Datagram datagrams[DEFAULT_FILE_LEN];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
FileInfo file;
Segment *segment = NULL;

void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);

void *device_thread_function(void *params);

void create_packet_header(unsigned char *datagram, Datagram data);

unsigned short calculate_ip_checksum(unsigned char *ip_hdr);

unsigned short BytesTo16(unsigned char X, unsigned char Y);

unsigned short calculate_udp_checksum(UDPHeader *udp, IPHeader *ip, Datagram data);

void fill_datagrams(char *file_name);

int main(int argc, char **argv) {
    file = OpenAndDivide(SEGMENT_LENGTH, "/home/niketic95/Documents/University/VI/ORM2/MPUDP/files/FILE.data",
                         &segment);
    EraseData(&segment, file);
    pcap_if_t *devices, *selected_devices;                        // List of network interface controllers
    pcap_if_t *device;                        // Network interface controller
    unsigned int netmask;
    char error_buffer[PCAP_ERRBUF_SIZE];    // Error buffer
    char filter_exp[] = "udp";
    struct bpf_program fcode;
    pthread_t device_thread[NUM_OF_THREADS];
    int i = 0, NumberOfThreads = 0, device_number[2];

    //Filling datagrams
    printf("File to be loaded: %s\n", argv[1]);
    fill_datagrams(argv[1]);

    //Printing out datagrams
    for (i = 0; i < DEFAULT_FILE_LEN; i++) {
        if (datagrams[i].datagramId != -1)
            printf("%d: %s", datagrams[i].datagramId, datagrams[i].message);
    }
    printf("\n\n\n");

    //Opening device adapters
    if (pcap_findalldevs(&devices, error_buffer) == -1) {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    //Testing print
    printf("Devices found: \n");
    for (device = devices; device; device = device->next) {
        printf("\tDevice: name - %s\n\t        description - %s\n", device->name, device->description);
    }
    printf("\n");

    for (device = devices, i = 0; device; device = device->next, i++) {
        if (pthread_create(&device_thread[i], NULL, &device_thread_function, device)) {
            printf("Error creating a thread for device: %s\n", device->name);
        } else {
            NumberOfThreads++;
        }
    }

    for (i = 0; i < NumberOfThreads; i++) {
        pthread_join(device_thread[i], NULL);
    }

    //pcap_freealldevs(devices);

    return 0;
}

void fill_datagrams(char *file_name) {
    FILE *file;
    char line[DEFAULT_MESSAGE_LEN];
    int i = 0;


    //Annulling datagrams and datagram helper
    for (i = 0; i < DEFAULT_FILE_LEN; i++) {
        strcpy(datagrams[i].message, "");
        datagrams[i].datagramId = -1;
        datagrams[i].sent = false;
    }

    file = fopen(file_name, "r");

    if (file == NULL) {
        exit(EXIT_FAILURE);
    }

    i = 0;
    while (fgets(line, DEFAULT_MESSAGE_LEN, file) != NULL) {
        if (i == DEFAULT_FILE_LEN) {
            perror("File size is higher than alowed\n");
            exit(EXIT_FAILURE);
        }

        datagrams[i].datagramId = i;
        strcpy(datagrams[i].message, line);
        i++;
        NumberOfPackets = i;
    }
}

void *device_thread_function(void *device) {
    pcap_if_t *thread_device = (pcap_if_t *) device;
    pcap_t *device_handle;                    // Descriptor of capture device
    char error_buffer[PCAP_ERRBUF_SIZE];    // Error buffer
    unsigned char packet[sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + sizeof(Datagram)];
    int i = 0;

    // Open the capture device
    if ((device_handle = pcap_open_live(thread_device->name,
                                        65536,
                                        0,
                                        2000,
                                        error_buffer
    )) == NULL) {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", thread_device->name);
        return NULL;
    }


    for (i = 0; i < NumberOfPackets; i++) {
        pthread_mutex_lock(&mutex);
        if (!datagrams[i].sent) {
            //Create a udp datagram
            create_packet_header(packet, datagrams[i]);
            memcpy((packet + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader)), &datagrams[i],
                   sizeof(Datagram));

            //Send a usp datagram
            if (pcap_sendpacket(device_handle, packet, 12 + sizeof(Datagram)) != 0) {
                printf("Error sending packet id: %d\n", datagrams[i].datagramId);
            } else {
                printf("Success sending packet id: %d by thread: %s\n", datagrams[i].datagramId, thread_device->name);
                datagrams[i].sent = true;
            }
        }
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

void create_packet_header(unsigned char *datagram, Datagram data) {
    UDPHeader *udp_hdr = (UDPHeader *) malloc(sizeof(UDPHeader));
    IPHeader *ip_hdr = (IPHeader *) malloc(sizeof(IPHeader));
    EthernetHeader *eth_hdr = (EthernetHeader *) malloc(sizeof(EthernetHeader));
    unsigned char ip_helper[sizeof(IPHeader) - sizeof(unsigned short)];

    //Initializing
    memset(udp_hdr, 0, sizeof(UDPHeader));
    memset(ip_hdr, 0, sizeof(UDPHeader));
    memset(eth_hdr, 0, sizeof(UDPHeader));

    //Creating a udp header
    udp_hdr->srcPort = htons(8080);
    udp_hdr->dstPort = htons(8080);
    udp_hdr->datagramLength = sizeof(Datagram) + sizeof(UDPHeader);

    //Creating a ip header
    ip_hdr->nextProtocol = 17;//0x11 UDP protocol

    ip_hdr->dstAddr[0]=192;
    ip_hdr->dstAddr[1]=168;
    ip_hdr->dstAddr[2]=0;
    ip_hdr->dstAddr[3]=12;

    ip_hdr->srcAddr[0]=192;
    ip_hdr->srcAddr[1]=168;
    ip_hdr->srcAddr[2]=0;
    ip_hdr->srcAddr[3]=107;

    memcpy(ip_helper, ip_hdr, 22);

    //Creating ip and udp headers
    udp_hdr->checkSum = calculate_udp_checksum(udp_hdr, ip_hdr, data);
    ip_hdr->checkSum = calculate_ip_checksum(ip_helper);


    //Creating a ethernet header
    eth_hdr->dstAddress[0]=0x90;
    eth_hdr->dstAddress[1]=0xe6;
    eth_hdr->dstAddress[2]=0xba;
    eth_hdr->dstAddress[3]=0xaa;
    eth_hdr->dstAddress[4]=0xfa;
    eth_hdr->dstAddress[5]=0xdb;


    eth_hdr->srcAddress[0]=0x14;
    eth_hdr->srcAddress[1]=0x2d;
    eth_hdr->srcAddress[2]=0x27;
    eth_hdr->srcAddress[3]=0xf3;
    eth_hdr->srcAddress[4]=0x94;
    eth_hdr->srcAddress[5]=0x0b;
    eth_hdr->type = htons(0x0800);
    memcpy(datagram, eth_hdr, sizeof(EthernetHeader));
    memcpy(datagram + sizeof(EthernetHeader), ip_hdr, sizeof(IPHeader));
    memcpy(datagram + sizeof(EthernetHeader) + sizeof(IPHeader), udp_hdr, sizeof(UDPHeader));

    udp_hdr = NULL;
    ip_hdr = NULL;
    eth_hdr = NULL;

    free(udp_hdr);
    free(ip_hdr);
    free(eth_hdr);
}

unsigned short calculate_ip_checksum(unsigned char *ip_hdr) {
    unsigned short CheckSum = 0;
    for (int i = 0; i < 22; i += 2) {
        unsigned short Tmp = BytesTo16(ip_hdr[i], ip_hdr[i + 1]);
        unsigned short Difference = 65535 - CheckSum;
        CheckSum += Tmp;
        if (Tmp > Difference) { CheckSum += 1; }
    }
    CheckSum = ~CheckSum;
    return htons(CheckSum);
}

unsigned short calculate_udp_checksum(UDPHeader *udp, IPHeader *ip, Datagram data) {
    unsigned short CheckSum = 0;

    //length of pseudo_header = Data length + 8 bytes UDP header + Two 4 byte IP's + 1 byte protocol
    unsigned short pseudo_length = sizeof(Datagram) + 8 + 9;

    //If bytes are not an even number, add an extra.
    pseudo_length += pseudo_length % 2;

    // This is just UDP + Data length.
    unsigned short length = sizeof(Datagram) + 8;

    //Init
    unsigned char *pseudo_header = (unsigned char *) malloc(pseudo_length * sizeof(unsigned char));
    for (int i = 0; i < pseudo_length; i++) {
        pseudo_header[i] = 0x00;
    }

    // Protocol
    memcpy(pseudo_header, &(ip->nextProtocol), 1);

    // Source and Dest IP
    memcpy(pseudo_header + 1, &(ip->srcAddr), 4);
    memcpy(pseudo_header + 5, &(ip->dstAddr), 4);

    // length is not network byte order yet
    length = htons(length);

    //Included twice
    memcpy(pseudo_header + 9, (void *) &length, 2);
    memcpy(pseudo_header + 11, (void *) &length, 2);

    //Source Port
    memcpy(pseudo_header + 13, &(udp->srcPort), 2);

    //Dest Port
    memcpy(pseudo_header + 15, &(udp->dstPort), 2);
    memcpy(pseudo_header + 17, &data, sizeof(Datagram));


    for (int i = 0; i < pseudo_length; i += 2) {
        unsigned short Tmp = BytesTo16(pseudo_header[i], pseudo_header[i + 1]);
        unsigned short Difference = 65535 - CheckSum;
        CheckSum += Tmp;
        if (Tmp > Difference) { CheckSum += 1; }
    }
    CheckSum = ~CheckSum; //One's complement

    pseudo_header = NULL;
    free(pseudo_header);

    return CheckSum;
}

unsigned short BytesTo16(unsigned char X, unsigned char Y) {
    unsigned short Tmp = X;
    Tmp = Tmp << 8;
    Tmp = Tmp | Y;
    return Tmp;
}