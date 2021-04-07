#ifndef LAB5_STRUCT_H
#define LAB5_STRUCT_H

#include "skel.h"
#include "struct.h"

struct route_table_entry {
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
    int interface;
} __attribute__((packed));

struct arp_entry {
    __u32 ip;
    uint8_t mac[6];
};

typedef struct el element ;
struct el{
    packet pkt;
    element *next;
};

typedef struct c coada;
struct c {
    element *first;
    element *last;
};

void push(coada *q, packet pkt);
packet pop(coada *q);

void parse_route_table(struct route_table_entry *rtable, int *rtable_size);
void parse_arp_table(struct arp_entry *arp_table, int *arp_table_len);
#endif //LAB5_STRUCT_H
