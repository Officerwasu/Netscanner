#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <pthread.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

#ifndef DEFAULT_INTERFACE
#define DEFAULT_INTERFACE "eth0"
#endif

#ifndef ARP_RETRIES
#define ARP_RETRIES 3
#endif

typedef struct {
    unsigned char mac_addr[ETH_ALEN];
    unsigned char ip_addr[4];
} device_info;

#ifndef HAVE_STRUCT_ARP_HEADER
struct arp_header {
    uint16_t arp_hrd;
    uint16_t arp_pro;
    uint8_t  arp_hln;
    uint8_t  arp_pln;
    uint16_t arp_op;
    unsigned char arp_sha[ETH_ALEN];
    unsigned char arp_spa[4];
    unsigned char arp_tha[ETH_ALEN];
    unsigned char arp_tpa[4];
};
#endif

void ip_addr_to_str(const unsigned char *ip_addr, char *ip_str_buffer) {
    sprintf(ip_str_buffer, "%d.%d.%d.%d",
            ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
}

void mac_addr_to_str(const unsigned char *mac_addr, char *mac_str_buffer) {
    sprintf(mac_str_buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac_addr[0], mac_addr[1], mac_addr[2],
            mac_addr[3], mac_addr[4], mac_addr[5]);
}

int receive_arp_reply(int sockfd, const unsigned char *expected_sender_ip, device_info *device) {
    unsigned char buffer[ETH_FRAME_LEN];
    ssize_t num_bytes;
    struct ether_header *eth_header;
    struct arp_header *arp_header_ptr;
    int retries = 0;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("setsockopt SO_RCVTIMEO");
    }

    while (retries < ARP_RETRIES) {
        num_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (num_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                retries++;
                continue;
            }
            if (errno == EINTR) continue;
            perror("recvfrom");
            return -1;
        }

        if (num_bytes < (sizeof(struct ether_header) + sizeof(struct arp_header))) {
            continue;
        }

        eth_header = (struct ether_header *)buffer;
        if (ntohs(eth_header->ether_type) == ETH_P_ARP) {
            arp_header_ptr = (struct arp_header *)(buffer + sizeof(struct ether_header));

            if (ntohs(arp_header_ptr->arp_op) == ARPOP_REPLY &&
                memcmp(arp_header_ptr->arp_spa, expected_sender_ip, 4) == 0) {

                memcpy(device->mac_addr, arp_header_ptr->arp_sha, ETH_ALEN);
                memcpy(device->ip_addr, arp_header_ptr->arp_spa, 4);
                return 0;
            }
        }
    }
    return -1;
}

void *discover_device(void *arg) {
    unsigned char *target_ip_addr = (unsigned char *)arg;
    device_info device;
    int sockfd_send;
    struct sockaddr_ll dest_sll;
    char ip_str[INET_ADDRSTRLEN];
    char mac_str[18];
    unsigned char packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct arp_header *arp_header_ptr = (struct arp_header *)(packet + sizeof(struct ether_header));
    struct ifreq ifr_mac, ifr_ip, ifr_idx;
    int temp_sock_ioctl;
    unsigned char src_mac[ETH_ALEN];
    unsigned char src_ip[4];
    int ifindex;

    temp_sock_ioctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sock_ioctl < 0) {
        perror("socket (for ioctl)");
        free(arg);
        pthread_exit(NULL);
    }

    memset(&ifr_mac, 0, sizeof(ifr_mac));
    strncpy(ifr_mac.ifr_name, DEFAULT_INTERFACE, IFNAMSIZ - 1);
    ifr_mac.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(temp_sock_ioctl, SIOCGIFHWADDR, &ifr_mac) < 0) {
        perror("ioctl (SIOCGIFHWADDR)");
        close(temp_sock_ioctl);
        free(arg);
        pthread_exit(NULL);
    }
    memcpy(src_mac, ifr_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    memset(&ifr_ip, 0, sizeof(ifr_ip));
    strncpy(ifr_ip.ifr_name, DEFAULT_INTERFACE, IFNAMSIZ - 1);
    ifr_ip.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(temp_sock_ioctl, SIOCGIFADDR, &ifr_ip) < 0) {
        perror("ioctl (SIOCGIFADDR)");
        close(temp_sock_ioctl);
        free(arg);
        pthread_exit(NULL);
    }
    struct sockaddr_in *sin_addr_ptr = (struct sockaddr_in *)&ifr_ip.ifr_addr;
    memcpy(src_ip, &sin_addr_ptr->sin_addr.s_addr, 4);

    memset(&ifr_idx, 0, sizeof(ifr_idx));
    strncpy(ifr_idx.ifr_name, DEFAULT_INTERFACE, IFNAMSIZ - 1);
    ifr_idx.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(temp_sock_ioctl, SIOCGIFINDEX, &ifr_idx) < 0) {
        perror("ioctl (SIOCGIFINDEX)");
        close(temp_sock_ioctl);
        free(arg);
        pthread_exit(NULL);
    }
    ifindex = ifr_idx.ifr_ifindex;
    close(temp_sock_ioctl);

    sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd_send < 0) {
        perror("socket(AF_PACKET, SOCK_RAW)");
        free(arg);
        pthread_exit(NULL);
    }

    memcpy(eth_header->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETH_ALEN);
    memcpy(eth_header->ether_shost, src_mac, ETH_ALEN);
    eth_header->ether_type = htons(ETH_P_ARP);

    arp_header_ptr->arp_hrd = htons(ARPHRD_ETHER);
    arp_header_ptr->arp_pro = htons(ETH_P_IP);
    arp_header_ptr->arp_hln = ETH_ALEN;
    arp_header_ptr->arp_pln = 4;
    arp_header_ptr->arp_op = htons(ARPOP_REQUEST);
    memcpy(arp_header_ptr->arp_sha, src_mac, ETH_ALEN);
    memcpy(arp_header_ptr->arp_spa, src_ip, 4);
    memcpy(arp_header_ptr->arp_tha, "\x00\x00\x00\x00\x00\x00", ETH_ALEN);
    memcpy(arp_header_ptr->arp_tpa, target_ip_addr, 4);

    memset(&dest_sll, 0, sizeof(dest_sll));
    dest_sll.sll_family = AF_PACKET;
    dest_sll.sll_ifindex = ifindex;
    dest_sll.sll_halen = ETH_ALEN;
    memcpy(dest_sll.sll_addr, eth_header->ether_dhost, ETH_ALEN);

    if (sendto(sockfd_send, packet, sizeof(packet), 0, (struct sockaddr *)&dest_sll, sizeof(dest_sll)) < 0) {
        perror("sendto");
        close(sockfd_send);
        free(arg);
        pthread_exit(NULL);
    }

    if (receive_arp_reply(sockfd_send, target_ip_addr, &device) == 0) {
        ip_addr_to_str(device.ip_addr, ip_str);
        mac_addr_to_str(device.mac_addr, mac_str);
        printf("Discovered device with IP: %s, MAC: %s\n", ip_str, mac_str);
    }

    close(sockfd_send);
    free(arg);
    return NULL;
}

int main(int argc, char *argv[]) {
    unsigned char base_ip[4];
    pthread_t threads[254];
    int i;
    char if_name[IFNAMSIZ];
    struct ifreq ifr_main_ip;
    int sock_main_ioctl;

    if (argc > 1) {
        strncpy(if_name, argv[1], IFNAMSIZ - 1);
        if_name[IFNAMSIZ - 1] = '\0';
    } else {
        strcpy(if_name, DEFAULT_INTERFACE);
    }

    sock_main_ioctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_main_ioctl < 0) {
        perror("socket (main ioctl)");
        return 1;
    }

    memset(&ifr_main_ip, 0, sizeof(ifr_main_ip));
    strncpy(ifr_main_ip.ifr_name, if_name, IFNAMSIZ - 1);
    ifr_main_ip.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock_main_ioctl, SIOCGIFADDR, &ifr_main_ip) < 0) {
        fprintf(stderr, "ioctl (SIOCGIFADDR for %s): %s. ", if_name, strerror(errno));
        fprintf(stderr, "Ensure interface is up and has an IP.\n");
        close(sock_main_ioctl);
        return 1;
    }
    struct sockaddr_in *main_sin = (struct sockaddr_in *)&ifr_main_ip.ifr_addr;
    memcpy(base_ip, &main_sin->sin_addr.s_addr, 4);
    close(sock_main_ioctl);

    printf("Scanning network using interface: %s, base IP: %d.%d.%d.%d/24\n",
            if_name, base_ip[0], base_ip[1], base_ip[2], base_ip[3]);

    for (i = 1; i <= 254; i++) {
        unsigned char *current_ip_ptr = (unsigned char *)malloc(4);
        if (!current_ip_ptr) {
            perror("malloc for thread IP");
            continue;
        }
        memcpy(current_ip_ptr, base_ip, 4);
        current_ip_ptr[3] = (unsigned char)i;

        if (pthread_create(&threads[i - 1], NULL, discover_device, (void *)current_ip_ptr) != 0) {
            perror("pthread_create");
            free(current_ip_ptr);
        }
    }

    for (i = 0; i < 254; i++) {
        if (threads[i] != 0) {
            if (pthread_join(threads[i], NULL) != 0) {
            }
        }
    }

    printf("Network scan complete.\n");
    return 0;
}
