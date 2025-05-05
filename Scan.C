#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h> // For ETH_ALEN
#include <errno.h>
#include <pthread.h>

// Include libpcap for sending ARP requests (if available)
#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif

// Default interface to use
#define DEFAULT_INTERFACE "eth0"
// Default timeout for receiving ARP replies
#define TIMEOUT_SEC 2
// Number of retries for sending ARP request
#define ARP_RETRIES 3

// Structure for storing IP and MAC address
typedef struct {
    unsigned char mac_addr[ETH_ALEN];
    unsigned char ip_addr[4];
} device_info;

// Function to convert MAC address to string
char *mac_ntoa(unsigned char *mac_addr, char *str) {
    if (!mac_addr || !str) return NULL;
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac_addr[0], mac_addr[1], mac_addr[2],
            mac_addr[3], mac_addr[4], mac_addr[5]);
    return str;
}

// Function to convert IP address to string
char *ip_ntoa(unsigned char *ip_addr, char *str) {
    if (!ip_addr || !str) return NULL;
    sprintf(str, "%d.%d.%d.%d",
            ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
    return str;
}

// Function to send ARP request (using libpcap)
#ifdef HAVE_PCAP
int send_arp_request_pcap(const char *if_name, unsigned char *target_ip_addr) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "arp";
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct ether_header eth_header;
    struct arp_header arp_header;
    unsigned char packet[sizeof(eth_header) + sizeof(arp_header)];
    unsigned char src_mac[ETH_ALEN];  // Source MAC address
    unsigned char src_ip[4];      // Source IP address
    struct ifreq ifr;
    int sock;

    // Open the network interface
    handle = pcap_open_live(if_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", if_name, errbuf);
        return -1;
    }

    // Get the network address and mask
    if (pcap_lookupnet(if_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not get netmask for device %s: %s\n", if_name, errbuf);
        net = 0;
        mask = 0;
    }

     // Compile and set the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't compile filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't set filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    // Create a socket to get interface information (MAC, IP)
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        pcap_close(handle);
        return -1;
    }

    // Get source MAC address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl (SIOCGIFHWADDR)");
        close(sock);
        pcap_close(handle);
        return -1;
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    // Get source IP address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl (SIOCGIFADDR)");
        close(sock);
        pcap_close(handle);
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(src_ip, &sin->sin_addr.s_addr, 4);
    close(sock);

    // Construct Ethernet header
    memset(&eth_header, 0, sizeof(eth_header));
    memcpy(eth_header.ether_dhost, "\xff\xff\xff\xff\xff\xff", ETH_ALEN); // Broadcast MAC
    memcpy(eth_header.ether_shost, src_mac, ETH_ALEN);
    eth_header.ether_type = htons(ETHERTYPE_ARP);

    // Construct ARP header
    memset(&arp_header, 0, sizeof(arp_header));
    arp_header.arp_hrd = htons(ARPHRD_ETHER);
    arp_header.arp_pro = htons(ETHERTYPE_IP);
    arp_header.arp_hln = ETH_ALEN;
    arp_header.arp_pln = 4;
    arp_header.arp_op = htons(ARPOP_REQUEST);
    memcpy(arp_header.arp_sha, src_mac, ETH_ALEN);
    memcpy(arp_header.arp_spa, src_ip, 4);
    memcpy(arp_header.arp_tha, "\x00\x00\x00\x00\x00\x00", ETH_ALEN); // Target MAC (unknown)
    memcpy(arp_header.arp_tpa, target_ip_addr, 4);

    // Copy headers into packet buffer
    memcpy(packet, &eth_header, sizeof(eth_header));
    memcpy(packet + sizeof(eth_header), &arp_header, sizeof(arp_header));

    // Send the ARP request
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending ARP request: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    pcap_close(handle);
    return 0;
}
#endif // HAVE_PCAP

// Function to receive ARP reply (using raw sockets)
int receive_arp_reply(int sockfd, unsigned char *target_ip_addr, device_info *device) {
    unsigned char buffer[ETH_FRAME_LEN];
    ssize_t num_bytes;
    struct ether_header *eth_header;
    struct arp_header *arp_header;
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    int retries = 0;

    while (retries < ARP_RETRIES) {
        // Receive the ARP reply
        num_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
        if (num_bytes < 0) {
            if (errno == EINTR) continue; // Interrupted, try again
            perror("recvfrom");
            return -1;
        }

        // Check if the received packet is an ARP reply
        eth_header = (struct ether_header *)buffer;
        arp_header = (struct arp_header *)(buffer + sizeof(struct ether_header));
        if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP &&
            ntohs(arp_header->arp_op) == ARPOP_REPLY &&
            memcmp(arp_header->arp_tpa, target_ip_addr, 4) == 0) {

            // Store the MAC and IP address
            memcpy(device->mac_addr, arp_header->arp_sha, ETH_ALEN);
            memcpy(device->ip_addr, arp_header->arp_spa, 4);
            return 0; // Success
        }
        retries++;
        sleep(1);
    }
    return -1; // Timeout or error
}

// Function to perform network discovery for a single IP address
void *discover_device(void *arg) {
    unsigned char target_ip_addr[4];
    device_info device;
    int sockfd;
    struct sockaddr_in addr;
    char ip_str[INET_ADDRSTRLEN];
    char mac_str[18];

    memcpy(target_ip_addr, arg, 4);

    // Create a raw socket for sending and receiving ARP packets
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket(SOCK_RAW)");
        pthread_exit(NULL); // Exit thread on error
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    // Send ARP request (using libpcap or raw socket)
#ifdef HAVE_PCAP
    if (send_arp_request_pcap(DEFAULT_INTERFACE, target_ip_addr) != 0) {
        fprintf(stderr, "Failed to send ARP request using libpcap. Trying with raw sockets.\n");
#endif
        // Send ARP request using raw socket (if libpcap fails or is not available)
        struct ether_header eth_header;
        struct arp_header arp_header;
        unsigned char packet[sizeof(eth_header) + sizeof(arp_header)];
        struct ifreq ifr;
        int sock;
        unsigned char src_mac[ETH_ALEN];
        unsigned char src_ip[4];

        // Create a socket to get interface information (MAC, IP)
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            close(sockfd);
            pthread_exit(NULL);
        }

        // Get source MAC address
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, DEFAULT_INTERFACE, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl (SIOCGIFHWADDR)");
            close(sock);
            close(sockfd);
            pthread_exit(NULL);
        }
        memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        // Get source IP address
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, DEFAULT_INTERFACE, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
            perror("ioctl (SIOCGIFADDR)");
            close(sock);
            close(sockfd);
            pthread_exit(NULL);
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        memcpy(src_ip, &sin->sin_addr.s_addr, 4);
        close(sock);

        // Construct Ethernet header
        memset(&eth_header, 0, sizeof(eth_header));
        memcpy(eth_header.ether_dhost, "\xff\xff\xff\xff\xff\xff", ETH_ALEN); // Broadcast MAC
        memcpy(eth_header.ether_shost, src_mac, ETH_ALEN);
        eth_header.ether_type = htons(ETHERTYPE_ARP);

        // Construct ARP header
        memset(&arp_header, 0, sizeof(arp_header));
        arp_header.arp_hrd = htons(ARPHRD_ETHER);
        arp_header.arp_pro = htons(ETHERTYPE_IP);
        arp_header.arp_hln = ETH_ALEN;
        arp_header.arp_pln = 4;
        arp_header.arp_op = htons(ARPOP_REQUEST);
        memcpy(arp_header.arp_sha, src_mac, ETH_ALEN);
        memcpy(arp_header.arp_spa, src_ip, 4);
        memcpy(arp_header.arp_tha, "\x00\x00\x00\x00\x00\x00", ETH_ALEN); // Target MAC (unknown)
        memcpy(arp_header.arp_tpa, target_ip_addr, 4);

        // Copy headers into packet buffer
        memcpy(packet, &eth_header, sizeof(eth_header));
        memcpy(packet + sizeof(eth_header), &arp_header, sizeof(arp_header));

        if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("sendto");
            close(sockfd);
            pthread_exit(NULL); // Exit thread
        }
#ifdef HAVE_PCAP
    }
#endif

    // Receive ARP reply
    if (receive_arp_reply(sockfd, target_ip_addr, &device) == 0) {
        ip_ntoa(device.ip_addr, ip_str);
        mac_ntoa(device.mac_addr, mac_str);
        printf("Discovered device with IP: %s, MAC: %s\n", ip_str, mac_str);
    } else {
        ip_ntoa(target_ip_addr, ip_str);
        printf("No response from IP: %s\n", ip_str);
    }

    close(sockfd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    unsigned char base_ip[4];
    unsigned char current_ip[4];
    pthread_t threads[254]; // Maximum 254 hosts in a /24 network
    int i;
    char if_name[IFNAMSIZ];
    struct ifreq ifr;
    int sock;

     // Use provided interface or default
    if (argc > 1) {
        strncpy(if_name, argv[1], IFNAMSIZ - 1);
    } else {
        strcpy(if_name, DEFAULT_INTERFACE);
    }

     // Create a socket to get interface information
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    // Get the IP address of the interface
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl (SIOCGIFADDR)");
        close(sock);
        return 1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(base_ip, &sin->sin_addr.s_addr, 4);
    close(sock);

    printf("Scanning network using interface: %s, base IP: %d.%d.%d.%d\n",
           if_name, base_ip[0], base_ip[1], base_ip[2], base_ip[3]);

    // Iterate through all possible hosts in the subnet (assuming /24)
    for (i = 1; i <= 254; i++) {
        memcpy(current_ip, base_ip, 4);
        current_ip[3] = i; // Last octet varies from 1 to 254

        // Create a thread for each IP address
        if (pthread_create(&threads[i - 1], NULL, discover_device, (void *)current_ip) != 0) {
            perror("pthread_create");
            // Handle error, perhaps continue with other IPs, or exit
            continue; // Try next IP
        }
    }

    // Wait for all threads to complete
    for (i = 0; i < 254; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("pthread_join");
            // Handle error, perhaps log it
        }
    }

    printf("Network scan complete.\n");
    return 0;
}

