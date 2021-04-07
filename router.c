#include "include/skel.h"
#include "include/struct.h"
#include "include/print.h"
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>

struct route_table_entry *rtable;
int rtable_size;
struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(__u32 dest_ip) {
    int m, l = 1, r = rtable_size-1;
    while(l <= r) {
        m = (r + l) / 2;
//        printf("%d %d %d\n", l, m, r);
        if ((rtable[m].mask & dest_ip) == rtable[m].prefix) {
            while ((rtable[m].mask & dest_ip) == rtable[m].prefix) {
                m--;
//                printf("%d %d %d\n", l, m, r);
            }
            return &rtable[m + 1];
        }
        if (ntohl(rtable[m].prefix) > ntohl(rtable[m].mask & dest_ip)) {
            r = m - 1;
        } else {
            l = m + 1;
        }
    }
    return NULL;
}

struct arp_entry *get_arp_entry(__u32 ip) {
    int i;
    for (i = 0; i < arp_table_len; i++)
        if (ip == arp_table[i].ip)
            break;
    if (i == arp_table_len)
        return NULL;
    return &arp_table[i];
}

int comparator(const void *p, const void *q) {
    int mask1 = ((struct route_table_entry *)p)->mask;
    int mask2 = ((struct route_table_entry *)q)->mask;
    int prefix1 = ((struct route_table_entry *)p)->prefix;
    int prefix2 = ((struct route_table_entry *)q)->prefix;
    if (prefix1 == prefix2)
        return (int)(ntohl(mask2) - ntohl(mask1));
    return (int)(ntohl(prefix1) - ntohl(prefix2));
}

static unsigned short checksumIP(void *hdr, int len) {
    unsigned int sum = 0;
    unsigned short c;
    int i;//printf("%d  ",len);
    for (i = 0; i < len/2; i++) {
        c = *((unsigned short *)(hdr+2*i));
        sum += c;
    }
    if(len%2 == 1)
        sum += (unsigned short)*((unsigned char *)(hdr+2*i-1)) << 8;

    sum=(sum & 0xffff) + (sum >> 16);
    sum=(sum & 0xffff) + (sum >> 16);

    return (~sum);
}

void sendPacket(int i, packet *m, char *s) {
    printf("%s ", s);
    m->interface = i;
    printPacket(*m);
    send_packet(i, m);
}

void icmp(packet *m, uint8_t type, uint8_t code) {
    struct ether_header *eth_hdr = (struct ether_header *)m->payload;
    struct iphdr *ip_hdr = (struct iphdr*)(m->payload + IP_OFF);
    struct icmphdr *icmp_hdr = (struct icmphdr*)(m->payload + ICMP_OFF);

    unsigned int ip = inet_addr(get_interface_ip(m->interface));
    unsigned int tmp = ip_hdr->daddr;
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = tmp;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(sizeof(struct icmphdr) + ICMP_OFF);
    ip_hdr->id = htons(getpid());
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->ttl--;
    ip_hdr->check = 0;
    ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

    icmp_hdr->type = type;
    icmp_hdr->code = code;
    icmp_hdr->un.echo.id = 0;
    icmp_hdr->un.echo.sequence = htons(1);
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));
    m->len = ICMP_OFF + sizeof(struct icmphdr);
}

void arpRequest(packet *m, __u32 ip) {
    memset(m->payload, 0, sizeof(struct ether_arp) + IP_OFF);
    struct ether_header* eth_hdr = (struct ether_header *)m->payload;
    struct ether_arp *arp = (struct ether_arp*)(m->payload + IP_OFF);
    __u8 mac[6];
    __u32 my_ip;

    memset(eth_hdr->ether_dhost, 0xff, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memset(arp->arp_tha, 0x0, 6);
    memcpy(arp->arp_tpa, (void*) &(ip), 4);
    m->len = sizeof(struct ether_arp) + IP_OFF;
    printf("\nBROACAST");
    // Trimitem pachetul pe fiecare interfata in afara de cea pe care a venit
    for (int i = 0; i < 4; ++i) {
        // Completam datele sender ului in funtie de interfata pe care trimitem pachetul
        if (i != m->interface) {
            get_interface_mac(i, mac);
            my_ip = inet_addr(get_interface_ip(i));
            memcpy(eth_hdr->ether_shost, mac, 6);
            memcpy(arp->arp_sha, mac, 6);
            memcpy(arp->arp_spa, (void*) &my_ip, 4);
            m->interface = i;
            send_packet(i, m);
        }
    }
}

void arpReplay(packet *m) {
    struct ether_header* eth_hdr = (struct ether_header *)m->payload;
    struct ether_arp *arp = (struct ether_arp*)(m->payload + IP_OFF);
    __u8 mac[6];
    get_interface_mac(m->interface, mac);
    __u32 ip = inet_addr(get_interface_ip(m->interface));

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, mac, 6);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons((ARPOP_REPLY));

    memcpy(arp->arp_tha, arp->arp_sha, 6);
    memcpy(arp->arp_tpa, arp->arp_spa, 4);
    memcpy(arp->arp_sha, mac, 6);
    memcpy(arp->arp_spa, (void*) &ip, 4);

    m->len = sizeof(struct ether_header) + sizeof(struct ether_arp);

    sendPacket(m->interface, m, "REPLAY");
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);

	int rc, check, check1, count = 10000;

    init();
	rtable = (struct route_table_entry *)malloc(1e5 * sizeof(struct route_table_entry));
	arp_table = (struct arp_entry *)malloc(10 * sizeof(struct arp_entry));
    coada *c = (coada*)malloc(sizeof(coada));
	arp_table_len = 0;
	rtable_size = 1;

	parse_arp_table(arp_table, &arp_table_len);
	parse_route_table(rtable, &rtable_size);
    qsort((void*)rtable + sizeof(struct route_table_entry), rtable_size, sizeof(struct route_table_entry), comparator);
//    printRouteTable(rtable, rtable_size);

	while (1) {
        count--;
        if (!count) {
            break;
        }
	    packet m;
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

        /* Students will write code here */
        struct ether_header *eth_hdr = (struct ether_header *)m.payload;
        struct iphdr *ip_hdr = (struct iphdr *) (m.payload + IP_OFF);
        struct route_table_entry * best_route;
        __u32 ip = inet_addr(get_interface_ip(m.interface));
        __u8 mac[6];
        get_interface_mac(m.interface, mac);

        printf("Received: ");
        printPacket(m);
        if (eth_hdr->ether_type != htons(ETHERTYPE_IP)) {
            printf("NOT IP\n");
        }
        switch (ntohs(eth_hdr->ether_type)) {
            case ETHERTYPE_ARP:
                printf("ARP\n");
                struct ether_arp *arp = (struct ether_arp *) (m.payload + IP_OFF);
                if (arp->ea_hdr.ar_op == htons(ARPOP_REQUEST)) {
                    printf("Request for me\n");
                    arpReplay(&m);
                    printf("Replay send\n");
                } else if (arp->ea_hdr.ar_op == htons(ARPOP_REPLY)) {
                    memcpy((void *) &arp_table[arp_table_len].ip, arp->arp_spa, 4);
                    printf("ARPOP_REPLY for: %s\n", stringIP(arp_table[arp_table_len].ip));
                    struct arp_entry *tmp = get_arp_entry(arp_table[arp_table_len].ip);
                    if (!tmp) {
                        memcpy(arp_table[arp_table_len].mac, arp->arp_sha, 6);
                        arp_table_len++;
                        printArpTable(arp_table, arp_table_len);
                        m = pop(c);
                        if(m.len)
                            goto ip_protocol;
                    }
                }
                continue;
            case ETHERTYPE_IP:

                check = ip_hdr->check;
                ip_hdr->check = 0;
                if (check != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
                    printf("Checksum fail");
                    continue;
                }ip_hdr->check = check;

                if (ip_hdr->ttl <= 1) {
                    printf("Time exceeded\n");
                    icmp(&m, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
                    goto ip_protocol;
                }

                if (ip_hdr->protocol == ICMP_ECHO && ip_hdr->daddr == ip) {
                    icmp(&m, ICMP_ECHO, 0);
                }
            ip_protocol:
                best_route = get_best_route(ip_hdr->daddr);
                if (!best_route) {
                    printf("Dest unreachable");
                    icmp(&m, ICMP_DEST_UNREACH, ICMP_EXC_TTL);
                    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
                    memcpy(eth_hdr->ether_shost, mac, 6);
                    send_packet(m.interface, &m);
                }

                struct arp_entry *next_mac = get_arp_entry(best_route->next_hop);
                if (!next_mac) {
                    printf("No MAC => ARP request");
                    arpRequest(&m, best_route->next_hop);
                    continue;
                }
                ip_hdr->ttl--;
                ip_hdr->check = ~(~(ip_hdr->check) - 1);
//                ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

                get_interface_mac(best_route->interface, mac);
                memcpy(eth_hdr->ether_shost, mac, 6);
                memcpy(eth_hdr->ether_dhost, next_mac, 6);

                send_packet(best_route->interface, &m);
        }
    }
    printf("\n\n\n");
	free(rtable);
	free(arp_table);
}
