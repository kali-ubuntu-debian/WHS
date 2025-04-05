#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;      /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, // IP header length
                       iph_ver:4;  // IP version
    unsigned char      iph_tos;    // Type of service
    unsigned short int iph_len;    // IP Packet length (data + header)
    unsigned short int iph_ident;  // Identification
    unsigned short int iph_flag:3, // Fragmentation flags
                       iph_offset:13; // Flags offset
    unsigned char      iph_ttl;    // Time to Live
    unsigned char      iph_protocol; // Protocol type
    unsigned short int iph_chksum;  // IP datagram checksum
    struct  in_addr    iph_sourceip; // Source IP address
    struct  in_addr    iph_destip;   // Destination IP address
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("Ethernet Header:\n");
        printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("IP Header:\n");
        printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

        /* determine protocol */
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

            printf("TCP Header:\n");
            printf("   Src Port: %u\n", ntohs(tcp->source));
            printf("   Dst Port: %u\n", ntohs(tcp->dest));

            // Assuming the TCP payload starts right after the TCP header
            const u_char *payload = packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcphdr);
            int payload_length = header->len - (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcphdr));

            // Print HTTP message if payload is long enough
            if (payload_length > 0) {
                printf("HTTP Message:\n");
                // Print a limited number of bytes for the HTTP message
                for (int i = 0; i < payload_length && i < 100; i++) {
                    putchar(payload[i]);
                }
                printf("\n");
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // Filter only TCP packets
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF pseudo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}
