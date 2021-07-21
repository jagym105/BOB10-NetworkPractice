#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <string.h>

struct payload
{
    u_int8_t  data[8];
};
int print_eth(struct libnet_ethernet_hdr* eth_header)
{

    printf("Ethernet Header src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header->ether_shost[0],eth_header->ether_shost[1],eth_header->ether_shost[2],
            eth_header->ether_shost[3],eth_header->ether_shost[4],eth_header->ether_shost[5]);
    printf("Ethernet Header dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header->ether_dhost[0],eth_header->ether_dhost[1],eth_header->ether_dhost[2],
            eth_header->ether_dhost[3],eth_header->ether_dhost[4],eth_header->ether_dhost[5]);

    return 0;
}

int print_ip(struct libnet_ipv4_hdr* ipv4_header)
{
    printf("IP src : %s\n",inet_ntoa(ipv4_header->ip_src));
    printf("IP dst : %s\n",inet_ntoa(ipv4_header->ip_dst));
    return 0;
}

int print_tcp(struct libnet_tcp_hdr* tcp_header)
{
    printf("TCP src port : %d \n", ntohs(tcp_header->th_sport));
    printf("TCP dst port : %d \n", ntohs(tcp_header->th_dport));
    return 0;
}

int print_payload(struct payload* payload_data)
{
    printf("8byte payload : %02x %02x %02x %02x %02x %02x %02x %02x\n", payload_data->data[0], payload_data->data[1], payload_data->data[2],
            payload_data->data[3], payload_data->data[4], payload_data->data[5], payload_data->data[6], payload_data->data[7]);
    return 0;
}



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();

        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {


        struct pcap_pkthdr* header;

        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }


        struct libnet_ethernet_hdr* eth_header;
        struct libnet_ipv4_hdr* ip_header;
        struct libnet_tcp_hdr* tcp_header;
        struct payload* payload_data;

        eth_header = (struct libnet_ethernet_hdr *)packet;
        print_eth(eth_header);
        if (eth_header->ether_type == 8)
        {
            ip_header = (struct libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
            print_ip(ip_header);
            if (ip_header->ip_p == IPPROTO_TCP)
            {
            tcp_header = (struct libnet_tcp_hdr *)(packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr));
            print_tcp(tcp_header);

            payload_data = (struct payload *)(packet + sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr)+ sizeof(libnet_tcp_hdr));
            print_payload(payload_data);
            }
        }
        printf("\n");
    }

    pcap_close(pcap);
}
