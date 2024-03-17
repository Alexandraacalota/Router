#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define RTABLE_LEN 100000

#define ETHERTYPE_IP		0x0800	// IP

#define ETHERTYPE_ARP		0x0806	// ARP

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best_route = NULL;
	for (int i = 0; i < rtable_len; i++) {
		// checks if the prefix from the current route table entry matches the
		// destination ip address' first mask number of bits
		if ((rtable[i].prefix == (ip_dest & rtable[i].mask)) && ((best_route == NULL) ||
		// checks if the mask of the current route table entry is bigger than the one of
		// the previously best route found
		(ntohl(best_route->mask) < ntohl(rtable[i].mask)))) {
			best_route = &rtable[i];
		}
	}
	return best_route;
}

// Function that returns an entry of a given ip to the arp table
struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	struct queue *q = queue_create();
	struct queue *q_len = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * RTABLE_LEN);
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_entry) * RTABLE_LEN);
	DIE(arp_table == NULL, "memory");
	
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// if the packet is of type IP
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			uint16_t check = ip_hdr->check;
			ip_hdr->check = 0;
			// detect if there is any corruption in the ipv4 packet
			if (htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) != check) {
				continue;
			}
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				continue;
			}

			// check ttl and decrement it
			if (ip_hdr->ttl >= 1) {
				ip_hdr->ttl = ip_hdr->ttl - 1;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			}
			else {
				continue;
			}

			// if next_hop's address is not found in cache
			if (get_arp_entry(best_route->next_hop) == NULL) {

				struct ether_header *eth = malloc(sizeof(struct ether_header ));
				struct arp_header *arp = malloc(sizeof(struct arp_header));

				// complete the ethernet header with data for broadcast
				eth->ether_type = htons(ETHERTYPE_ARP);
				get_interface_mac(best_route->interface, eth->ether_shost);
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				hwaddr_aton("ff:ff:ff:ff:ff:ff", eth->ether_dhost);

				// complete the arp header with data for broadcast
				arp->htype = htons(1);
				arp->ptype = htons(ETHERTYPE_IP);
				arp->hlen = 6;
				arp->plen = 4;
				arp->op = htons(1);
				memcpy(arp->sha, eth->ether_shost, arp->hlen);
				uint32_t ip_interface = inet_addr(get_interface_ip(best_route->interface));
				memcpy(&arp->spa, &ip_interface, arp->plen);
				hwaddr_aton("00:00:00:00:00:00", arp->tha);
				memcpy(&arp->tpa, &best_route->next_hop, arp->plen);

				// add the initial packet to the queue q
				// and its length to queue q_len
				char packet[MAX_PACKET_LEN];
				memcpy(packet, buf, MAX_PACKET_LEN);
				size_t len_packet = len;
				queue_enq(q, packet);
				queue_enq(q_len, &len_packet);

				// reset the buffer
				memset(buf, 0, sizeof(buf));

				// copy the ethernet and arp headers to the buffer and send it for an arp request
				memcpy(buf, eth, sizeof(struct ether_header));
				memcpy(buf + sizeof(struct ether_header), arp, sizeof(struct arp_header));
				send_to_link(best_route->interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));

				continue;
			}

			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memcpy(&eth_hdr->ether_dhost, get_arp_entry(best_route->next_hop)->mac, 6);
			send_to_link(best_route->interface, buf, len);

		// if the packet is of type ARP
		} else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			// if the packet op code is 1 (arp request)
			if (arp_hdr->op == htons (1)) {
				struct ether_header *eth = malloc(sizeof(struct ether_header ));
				struct arp_header *arp = malloc(sizeof(struct arp_header));

				// write data in the arp packet's ethernet header
				eth->ether_type = htons(ETHERTYPE_ARP);
				get_interface_mac(interface, eth->ether_shost);
				memcpy(eth->ether_dhost, arp_hdr->sha, 6);

				// write data in the arp packet's arp header
				arp->htype = htons(1);
				arp->ptype = htons(ETHERTYPE_IP);
				arp->hlen = 6;
				arp->plen = 4;
				arp->op = htons(2);
				memcpy(arp->sha, eth->ether_shost, arp->hlen);
				memcpy(arp->tha, arp_hdr->sha, arp->hlen);
				arp->tpa = arp_hdr->spa;
				arp->spa = arp_hdr->tpa;

				// reset the buffer
				memset(buf, 0, sizeof(buf));

				// copy the headers in the buffer
				memcpy(buf, eth, sizeof(struct ether_header));
				memcpy(buf + sizeof(struct ether_header), arp, sizeof(struct arp_header));
				
				// send the arp reply
				send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));

			// if the packet op code is 2 (arp reply)
			} else {
				if(!queue_empty(q)) {
					// get the packet and its length out of the queues
					char *packet = (char *) queue_deq(q);
					int len = *((int *) queue_deq(q_len));

					struct ether_header *eth = (struct ether_header *) packet;
					
					// write the destination mac address from the reply sender
					// in the packet and send it further on the interface
					memcpy(eth->ether_dhost, arp_hdr->sha, 6);
					send_to_link(interface, packet, len);
				}

				struct arp_entry *arp_entry = malloc(sizeof(struct arp_entry));
				arp_entry->ip = arp_hdr->spa;
				memcpy(arp_entry->mac, arp_hdr->sha, 6);
				memcpy(&arp_table[arp_table_len], arp_entry, sizeof(struct arp_entry));
				arp_table_len++;
			}
		// if the packet is neither ipv4 or arp
		} else {
			continue;
		}
	}
}