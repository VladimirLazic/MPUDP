#include<stdbool.h>
#include <segmenter.h>
#include <network.h>
int NumberOfPackets = 0;

Datagram recivedDatagrams[DEFAULT_FILE_LEN];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
void *device_thread_function(void *params);

int main() {
    pcap_if_t *devices;
    pcap_if_t *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "udp";
    struct bpf_program fcode;
    pthread_t device_thread[NUM_OF_THREADS];
    int i = 0, NumberOfThreads = 0;

    if (pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return -1;
    }

    //Testing print
    printf("Devices found: \n");
    for (device = devices; device; device = device->next) {
        printf("\tDevice: name - %s\n\t        description - %s\n", device->name, device->description);
    }
    printf("\n");
    /*
    for (device = devices, i = 0; device; device = device->next, i++) {
        if (pthread_create(&device_thread[i], NULL, &device_thread_function, device)) {
            printf("Error creating a thread for device: %s\n", device->name);
        }
        else {
            NumberOfThreads++;
        }
    }

    for (i = 0; i < NumberOfThreads; i++) {
        pthread_join(device_thread[i], NULL);
    }
*/
    return 0;
}

void *device_thread_function(void *device) {
    pcap_if_t *thread_device = (pcap_if_t *)device;
    pcap_t* device_handle;					// Descriptor of capture device
    char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
    char packet[12 + sizeof(Datagram)];
    int i = 0;

    // Open the capture device
    if ((device_handle = pcap_open_live(thread_device->name,
                                        65536,
                                        0,
                                        2000,
                                        error_buffer
    )) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", thread_device->name);
        return NULL;
    }

    pcap_loop(device_handle, 0, packet_handler, NULL);
}


void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data) {
    pthread_mutex_lock(&mutex);
    Datagram temp;
    // Retrieve position of ethernet_header
    EthernetHeader* eh;
    eh = (EthernetHeader*)packet_data;

    // Check the type of next protocol in packet
    if (ntohs(eh->type) == 0x800)	// Ipv4
    {
        IPHeader* ih;
        ih = (IPHeader*)(packet_data + sizeof(EthernetHeader));

        if (ih->nextProtocol == 17) // UDP
        {
            //memset(&temp, &packet_data, sizeof(Datagram));
        }
    }

    pthread_mutex_unlock(&mutex);
}