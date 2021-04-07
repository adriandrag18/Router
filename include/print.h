#ifndef LAB5_PRINT_H
#define LAB5_PRINT_H

#include "skel.h"
#include "struct.h"
void printMAC(const unsigned char *mac);
void printIP(unsigned int p);
char* stringMAC(const unsigned char *mac);
char* stringIP(unsigned int ip);
void printRouteTable(struct route_table_entry *rtable, int rtable_size);
void printArpTable(struct arp_entry *arp_table, int arp_table_len);
void printBit(unsigned short i);
void printPacket(packet m);
#endif //LAB5_PRINT_H
