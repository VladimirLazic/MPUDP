#include <segmenter.h>
#include <network.h>

int NumberOfPackets = 0;
//Datagram recivedDatagrams[DEFAULT_FILE_LEN]; //NEVER USED


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void packet_handler(unsigned char *param, const struct pcap_pkthdr *packetHeader, const unsigned char *packetData);
void *device_thread_function(void *params);
int main() {
    pcap_if_t *devices;
    pcap_if_t *device;
    pthread_t *device_threads;
    unsigned char working_intefaces = 0;
    unsigned char thread;
    char error_buffer[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        exit(-1);
    }
    for (device = devices; device; device = device->next) {
        /**<We want all network interfaces that aren't loop back and aren't "any" (for linux any captures usb and lo)*/
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_RUNNING && device->flags & PCAP_IF_UP) &&
            strcasecmp(device->name, "any")) {
            working_intefaces++;
            printInterface(device);
        }
    }
    if (!working_intefaces) {
        printf("No running network interfaces were found exiting\n");
        exit(-2);
    }
    device_threads = malloc(sizeof(pthread_t) * working_intefaces);
    working_intefaces = 0;
    for (device = devices; device; device = device->next) {
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_RUNNING && device->flags & PCAP_IF_UP) &&
            strcasecmp(device->name, "any")) {
            if (pthread_create(&device_threads[working_intefaces], NULL, &device_thread_function, device)) {
                printf("Couldn't create thread for %s\n", device->name);
                exit(-3);
            }
            working_intefaces++;
        }
    }
    for (thread = 0; thread < working_intefaces; thread++) {
        pthread_join(device_threads[thread], NULL);
    }
    free(device_threads);
    return 0;
}

void *device_thread_function(void *device) {
    pcap_if_t *threadDevice = (pcap_if_t *) device;
    pcap_t *deviceHandle;
    char error_buffer[PCAP_ERRBUF_SIZE];
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


    //char packet[12 + sizeof(Datagram)];  //NEVER USED
    if ((deviceHandle = pcap_open_live(threadDevice->name,
                                       65536,
                                       1,
                                       2000,
                                       error_buffer
    )) == NULL)
    {
        printf("\n%s\n", error_buffer);
        return NULL;
    }
    if (pcap_compile(deviceHandle, &fcode, filterExpr, 1, netmask)) {
        printf("\n Unable to compile the packet filter. Check the syntax.\n");
        return NULL;
    }
    if (pcap_setfilter(deviceHandle, &fcode) < 0) {
        printf("\n Error setting the filter.\n");
        return NULL;
    }

    pcap_loop(deviceHandle, 0, packet_handler, NULL);

    return NULL;
}


/**
 * @todo
 *  Get timestamps from packetHeader
 *
 */

void packet_handler(unsigned char *param, const struct pcap_pkthdr *packetHeader, const unsigned char *packetData) {
    pthread_mutex_lock(&mutex);
    Datagram temp;
    unsigned long size = 0;
    memset(temp.message, 0, sizeof(temp.message));
    unsigned long appLength;
    unsigned char *appData;
    EthernetHeader* eh;
    IPHeader *ih;
    UDPHeader *uh;
    eh = (EthernetHeader *) packetData;
    ih = (IPHeader *) (packetData + sizeof(EthernetHeader));
    uh = (UDPHeader *) ((unsigned char *) ih + ih->headerLength * 4);
    appLength = (unsigned long) (ntohs(uh->datagramLength) - 8);
    appData = (unsigned char *) uh + 8;
    if (sizeof(temp.message) > appLength) {
        size = appLength;
    } else {
        size = sizeof(temp.message);
    }
    memcpy(&temp.message, appData, size);
    printEthernetHeader(eh);
    printIPHeader(ih);
    printUDPHeader(uh);
    printAppData(appData, appLength);
    printRawData((unsigned char *) temp.message, size);
    pthread_mutex_unlock(&mutex);
    getchar();
}
