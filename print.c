#include "include/skel.h"
#include "include/print.h"

void printMAC(const unsigned char *mac) {
    printf("%x", mac[0]);
    for (int i = 1; i < 6; i++)
        printf(":%.2x", (unsigned short)mac[i]);
}

void printIP(unsigned int p) {
    printf("%d.%d.%d.%d   ", p << 24 >> 24, p << 16 >> 24, p << 8 >> 24, p >> 24);
}

char* stringMAC(const unsigned char *mac) {
    char *s = (char*)malloc(19);
    sprintf(s," %x", mac[0]);
    for (int i = 1; i < 6; i++)
        sprintf(s+3*i, ":%.2x", (unsigned short)mac[i]);
    return s;
}

char* stringIP(unsigned int ip) {
    char *s = (char*)malloc(16);
    sprintf(s,"%d.%d.%d.%d ", ip << 24 >> 24, ip << 16 >> 24, ip << 8 >> 24, ip >> 24);
    return s;
}

void printRouteTable(struct route_table_entry *rtable, int rtable_size) {
    for(int i = 0; i < rtable_size; i++){
        printIP(rtable[i].prefix);
        printIP(rtable[i].next_hop);
        printIP(rtable[i].mask);
        printf("%d\n", rtable[i].interface);
    }
    printf("Size: %d\n", rtable_size);
}

void printArpTable(struct arp_entry *arp_table, int arp_table_len) {
    for(int i = 0; i < arp_table_len; i++) {
        printIP(arp_table[i].ip);
        printMAC(arp_table[i].mac);
        printf("\n");
    }
    printf("Len: %d\n", arp_table_len);
}

void printBit(unsigned short i) {
    for (int j = 0; j < 16; j++) {
        printf("%d", i%2);
        i /= 2;
    }
    printf("  \n");
}

void printPacket(packet m) {
    printf("interface: %d\n", m.interface);
    struct ether_header *eth_hdr = (struct ether_header *)m.payload;
    printf("sendMAC:%s  destMAC:%s type: 0x%x\n",
           stringMAC(eth_hdr->ether_shost), stringMAC(eth_hdr->ether_dhost), ntohs(eth_hdr->ether_type));
    if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
        printf("ETHERTYPE_ARP\n");
        struct ether_arp *arp = (struct ether_arp *) (m.payload + IP_OFF);
        unsigned int s_addr, d_addr;
        memcpy((void*)&s_addr, arp->arp_spa, 4);
        memcpy((void*)&d_addr, arp->arp_tpa, 4);
        printf("send:%s  target:%s\nsend: %s  target: %s\nhwtype: %d  ptype: 0x%x  hwlen: %d  plen: %d  op: %d\n",
               stringMAC(arp->arp_sha), stringMAC(arp->arp_tha), stringIP(s_addr), stringIP(d_addr),
               htons(arp->ea_hdr.ar_hrd), ntohs(arp->ea_hdr.ar_pro), arp->ea_hdr.ar_hln, arp->ea_hdr.ar_pln,
               htons(arp->ea_hdr.ar_op));
    } else {
        printf("ETHERTYPE_IP\n");
        struct iphdr *ip_hdr2 = (struct iphdr *) (m.payload + IP_OFF);
        printf("Vers: %d  hdrLen: %d tos: %d Len: %d ID: %d frag: %d TTL: %d  protocol:%d\n sendIP: %s, destIP: %s\nchecksum: ",
               ip_hdr2->version, ip_hdr2->ihl, ip_hdr2->tos, htons(ip_hdr2->tot_len), htons(ip_hdr2->id),
               ip_hdr2->frag_off, ip_hdr2->ttl, ip_hdr2->protocol, stringIP(ip_hdr2->saddr), stringIP(ip_hdr2->daddr));
        printBit(ip_hdr2->check);
        if(ip_hdr2->protocol == 1) {
            printf("IPCMP\n");
            struct icmphdr *icmp_hdr = (struct icmphdr*)(m.payload + ICMP_OFF);
            printf("type: %d  code: %d  id: %d  seq: %d\nchecksum: ",
                   icmp_hdr->type, icmp_hdr->code, htons(icmp_hdr->un.echo.id), htons(icmp_hdr->un.echo.id));
            printBit(icmp_hdr->checksum);
        }
    }
}
