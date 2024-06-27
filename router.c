#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define DESTINATION_UNREACHABLE 3
#define TTL_EXCEEDED 11
#define ECHO_REPLY 0
#define ECHO_REQUEST 8

struct route_table_entry *rtable;
int rtable_len;
struct arp_table_entry *arp;
int arp_len;

/**
 * Efficient search in the routing table to find the best match
 * for the destination IP address.
 * The function modifies idx_match to reflect the position of the found entry
 * or -1 if no match exists.
 */
void binary_search(struct iphdr *ip_header, int left, int right,  int *idx_match)
{
	uint32_t addr_dest = ip_header->daddr;
	while (left <= right) {
        int middle = ((right - left) / 2) + left;
        if (ntohl(rtable[middle].prefix) == ntohl(rtable[middle].mask & addr_dest)) {
            left = middle + 1;
			*idx_match = middle;
        } else if (ntohl(rtable[middle].prefix) < ntohl(rtable[middle].mask & addr_dest)) {
            left = middle + 1;
        } else {
            right = middle - 1;
        }
    }
}

/**
 * Searches for an IP address in the ARP table.
 * Returns: The index of the entry in the ARP table, or -1 if no match is found.
 */
int get_mac_entry(uint32_t ip_dest)
{
    struct arp_table_entry *end_arp_table = arp + arp_len;
    for (struct arp_table_entry *entry = arp; entry < end_arp_table; ++entry) {
        if (entry->ip == ip_dest) {
            return entry - arp; 
        }
    }
    return -1;
}

/**
 * Compares two entries in the routing table for qsort.
 * Sorting is done in ascending order by prefix and mask.
 */
int compare_entries(const void *first, const void *second)
{
	uint32_t first_prefix = ntohl(((struct route_table_entry *) first)->prefix);
	uint32_t first_mask = ntohl(((struct route_table_entry *) first)->mask);

    uint32_t second_prefix = ntohl(((struct route_table_entry *) second)->prefix);
    uint32_t second_mask = ntohl(((struct route_table_entry *) second)->mask);
	
	if (first_prefix == second_prefix && first_mask == second_mask)
		return 0; 

	if ((first_prefix & first_mask) == (second_prefix & second_mask) && first_mask != second_mask)
		return first_mask - second_mask;

	return (first_prefix & first_mask) - (second_prefix & second_mask);
	
}

void init_ip_header(struct iphdr *ip_header, int tot_len)
{
    ip_header->protocol = 1;
    ip_header->tot_len = htons(tot_len);
}

void init_icmp_header(struct icmphdr *icmp, int type)
{
    icmp->type = type;
    icmp->checksum = checksum((uint16_t *)icmp, sizeof(struct iphdr) + sizeof(*icmp) + 8);
}

void swap_addr(uint8_t *src_mac, uint8_t *dst_mac)
{
    uint8_t tmp_mac[6];
    memcpy(tmp_mac, src_mac, 6);
    memcpy(src_mac, dst_mac, 6);
    memcpy(dst_mac, tmp_mac, 6);
}

void swap_ip(uint32_t saddr, uint32_t daddr)
{
	uint32_t tmp_ip = saddr;
	saddr = daddr;
	daddr = tmp_ip;
}

/**
 * Swaps Ethernet and IP addresses between source and destination for a packet.
 */
void swap_eth_and_ip_addresses(struct ether_header *eth_hdr, struct iphdr *ip_header)
{
    swap_addr(eth_hdr->ether_shost, eth_hdr->ether_dhost);
    swap_ip(ip_header->saddr, ip_header->daddr);
}

/**
 * Allocates and copies the IP header of a received packet into a new iphdr structure.
 * Returns: Pointer to the newly allocated iphdr structure.
 */
struct iphdr* allocate_and_copy_ip_header(struct iphdr *ip_header)
{
    struct iphdr *new_ip = (struct iphdr*)malloc(sizeof(struct iphdr));
    memcpy(new_ip, ip_header, sizeof(*ip_header));
	
    return new_ip;
}

/**
 * Constructs an ICMP packet for error responses.
 */
void build_packet(char* buf, struct ether_header *eth_hdr, struct iphdr *ip_header, struct iphdr *received_ip, int type)
{
    int len_ip_and_data = sizeof(struct iphdr) + 64;
    init_ip_header(ip_header, len_ip_and_data);

	size_t offset = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	char *start_point = buf + offset;
	memcpy(start_point, received_ip, 64);

    struct icmphdr *icmp = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    init_icmp_header(icmp, type);
}

/**
 * Constructs and sends an ICMP error packet in response to a received packet.
 */
void error(int type, struct ether_header *eth_hdr, struct iphdr *ip_header, int interface, char *buf)
{
	struct iphdr *received_ip = allocate_and_copy_ip_header(ip_header);

	swap_eth_and_ip_addresses(eth_hdr, ip_header);

	int len_ip_and_data = sizeof(struct iphdr) + 64;
	build_packet(buf, eth_hdr, ip_header, received_ip, type);

	int length = sizeof(struct ether_header) + len_ip_and_data;
	send_to_link(interface, buf, length);

	free(received_ip);
}

/**
 * Processes an ICMP Echo Request and sends an Echo Reply response.
 */
void handle_icmp_echo_request(struct icmphdr *icmp_header, char *buf, size_t len, int interface, struct ether_header *eth_hdr, struct iphdr *ip_header)
{
	swap_eth_and_ip_addresses(eth_hdr, ip_header);

	icmp_header->type = ECHO_REPLY;

	ip_header->tot_len = sizeof(struct iphdr);
	send_to_link(interface, buf, len);
}

/**
 * Checks the TTL and checksum of the IP packet, sending an error packet if necessary.
 * Returns: true if the packet is valid, false otherwise.
 */
bool verify_ip_packet(struct iphdr *ip_header, int interface, char *buf, struct ether_header *eth_hdr)
{
	if (ip_header->ttl == 0 || ip_header->ttl == 1) {
		error(TTL_EXCEEDED, eth_hdr, ip_header, interface, buf);
        return false;
    }

    uint16_t old_check = ip_header->check;
    ip_header->check = 0;
    if (ntohs(checksum((uint16_t *)ip_header, sizeof(struct iphdr))) != old_check) {
        return false;
    }

    ip_header->ttl--;
    ip_header->check = ntohs(checksum((uint16_t *)ip_header, sizeof(*ip_header)));
    return true;
}

/**
 * Routes a received IP packet towards its final destination,
 * searching for the best route, updating Ethernet headers, and sending the packet.
 */
void route_packet(char *buf, size_t len, int interface, struct ether_header *eth_hdr, struct iphdr *ip_header)
{
	int index_match = -1;
	int right = rtable_len - 1, left = 0;

	binary_search(ip_header, left, right, &index_match);

	if (index_match == -1) {
		error(DESTINATION_UNREACHABLE, eth_hdr, ip_header, interface, buf);
	} else {
		struct route_table_entry elem_rtable = rtable[index_match];
		get_interface_mac(elem_rtable.interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, arp[get_mac_entry(elem_rtable.next_hop)].mac, 6);
		send_to_link(elem_rtable.interface, buf, len);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 100000);
	DIE(!rtable, "memory");

	rtable_len = read_rtable(argv[1], rtable);

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_entries);	

	arp = (struct arp_table_entry *)malloc(sizeof(struct arp_table_entry) * 100);
	DIE(!arp, "memory");

	arp_len = parse_arp_table("arp_table.txt", arp);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
		
		if (ntohs(eth_hdr->ether_type) == 0x0800) { // IPv4 packet
			struct in_addr* ip = (struct in_addr*)malloc(sizeof(struct in_addr));
			inet_aton(get_interface_ip(interface), ip);

			if (ip->s_addr == ip_header->daddr) {
				struct icmphdr *icmp_header = (struct icmphdr *) ((void*)ip_header + sizeof(struct iphdr));
				
				if(icmp_header &&  icmp_header->type == ECHO_REQUEST) {
					handle_icmp_echo_request(icmp_header, buf, len, interface, eth_hdr, ip_header);
				}
			}

			free(ip);
		}

		if (!verify_ip_packet(ip_header, interface, buf, eth_hdr)) {
        	continue;
    	}

     	route_packet(buf, len, interface, eth_hdr, ip_header);
	}

	free(rtable);
	free(arp);
	
	return 0;
}

