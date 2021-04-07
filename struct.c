//
// Created by adrian on 05.04.2020.
//
#include "include/skel.h"
#include "include/struct.h"

void push(coada *q, packet pkt) {
    if (!q->first) {
        q->first = (element*)malloc(sizeof(element));
        q->last = q->first;
        q->last->next = NULL;
        q->last->pkt = pkt;
    } else {
        q->last->next = (element *) malloc(sizeof(element));
        q->last->next->next = NULL;
        q->last->next->pkt = pkt;
        q->last = q->last->next;
    }
}

packet pop(coada *q) {
    packet m;
    if (!q->first){
        m.len = 0;
        return m;
    }
    m = q->first->pkt;
    element *tmp = q->first;
    q->first = q->first->next;
    free(tmp);
    return m;
}

void parse_arp_table(struct arp_entry *arp_table, int *arp_table_len) {
    FILE *f;
    fprintf(stderr, "Parsing ARP table\n");
    f = fopen("arp_table.txt", "r");
    DIE(f == NULL, "Failed to open arp_table.txt");
    char line[100];
    int i = 0;
    for(i = 0; fgets(line, sizeof(line), f); i++) {
        char ip_str[50], mac_str[50];
        sscanf(line, "%s %s", ip_str, mac_str);
        fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
        arp_table[i].ip = inet_addr(ip_str);
        int rc = hwaddr_aton(mac_str, arp_table[i].mac);
        DIE(rc < 0, "invalid MAC");
    }
    *arp_table_len = i;
    fclose(f);
    fprintf(stderr, "Done parsing ARP table.\n");
}

void parse_route_table(struct route_table_entry *rtable, int *rtable_size) {
    FILE *f;
    fprintf(stderr, "Parsing Route table\n");
    f = fopen("rtable.txt", "r");
    DIE(f == NULL, "Failed to open arp_table.txt");
    char line[100];
    int i = 0;
    *rtable_size = 1;
    for(i = 1; fgets(line, sizeof(line), f); i++) {
        char prefix[50], next[50], mask[50];
        int interface;
        sscanf(line, "%s %s %s %d", prefix, next, mask, &interface);
//        fprintf(stderr, "Prefix: %s Next: %s Mask: %s Interface: %d\n", prefix, next, mask, interface);
        rtable[i].interface = interface;
        rtable[i].next_hop = inet_addr(next);
        rtable[i].mask = inet_addr(mask);
        rtable[i].prefix = inet_addr(prefix);

    }
    *rtable_size = i;
    fprintf(stderr, "Done parsing Route table.\n");
}