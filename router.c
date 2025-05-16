#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

//////////////////
/*pt trie*/
struct trie_node {
    struct trie_node *left;  //0
    struct trie_node *right; //1
    struct route_table_entry *route; //ruta asociata
};

int get_bit(uint32_t value, int pos) {
	return (value >> pos) & 1;
}

void insert_route(struct trie_node *root, struct route_table_entry *entry) {
	uint32_t prefix = ntohl(entry->prefix);
	int prefix_len = 0;
	uint32_t mask = ntohl(entry->mask);
	while (mask & (1 << 31)) {
		prefix_len++;
		mask <<= 1;
	}
	struct trie_node *node = root;
	for (int i = 31; i >= 32 - prefix_len; i--) {
		int bit = get_bit(prefix, i);
		struct trie_node **next = (bit == 0) ? &node->left : &node->right;
		if (!*next) *next = calloc(1, sizeof(struct trie_node));
		node = *next;
	}
	node->route = entry;
}

struct route_table_entry *get_best_route(struct trie_node *root, uint32_t ip) {
	ip = ntohl(ip);
    struct trie_node *node = root;
    struct route_table_entry *best = NULL;
    for (int i = 31; i >= 0; i--) {
        if (node->route) best = node->route;
        int bit = get_bit(ip, i);
        if (bit == 0) {
            if (!node->left) break;
            node = node->left;
        } else {
            if (!node->right) break;
            node = node->right;
        }
    }
    return best;
}
/////////////////
struct packet {
	char *payload;
	size_t len;
	int interface;
	uint32_t next_hop;
}; //structura pt packete in coada

struct arp_table_entry *get_arp_entry(uint32_t ip,
                                      struct arp_table_entry *arp_table,
                                      int arp_len) {
    for (int i = 0; i < arp_len; i++) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	// Do not modify this line
	init(argv + 2, argc - 2);

	queue waiting_packets;
	waiting_packets = create_queue();

	struct arp_table_entry arp_table[100];
	int arp_table_len = 0;

	struct route_table_entry rtable[100000];
	int rtable_len = read_rtable(argv[1], rtable); //argv[1] - rtable0 sau rtable1, din makefile se ruleaaza argumentul

	struct trie_node *trie_root = calloc(1, sizeof(struct trie_node));
	for (int i = 0; i < rtable_len; i++) {
		insert_route(trie_root, &rtable[i]);
	}


	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		if (ntohs(eth_hdr->ethr_type) == 0x0800) {

			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			int is_for_us = 0;
			for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
				if (ip_hdr->dest_addr == inet_addr(get_interface_ip(i))) {
					is_for_us = 1;
					break;
				}
			}

			if (is_for_us && ip_hdr->proto == 1) {
				//verifica daca e pentru router pachetul pentru fiecare interfata:
				int replied = 0;
				for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
					if (ip_hdr->dest_addr == inet_addr(get_interface_ip(i))) {
						struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
						int icmp_len = ntohs(ip_hdr->tot_len) - sizeof(struct ip_hdr);
						//echo reply
						if (icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0) {
							char reply_buf[MAX_PACKET_LEN];
							struct ether_hdr *eth_reply = (struct ether_hdr *)reply_buf;
							struct ip_hdr *ip_reply = (struct ip_hdr *)(reply_buf + sizeof(struct ether_hdr));
							struct icmp_hdr *icmp_reply = (struct icmp_hdr *)(reply_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

							//inversam MAC
							memcpy(eth_reply->ethr_dhost, eth_hdr->ethr_shost, 6);
							memcpy(eth_reply->ethr_shost, eth_hdr->ethr_dhost, 6);
							eth_reply->ethr_type = htons(0x0800);

							//facem ip_reply
							ip_reply->ihl = 5;
							ip_reply->ver = 4;
							ip_reply->tos = 0;
							ip_reply->tot_len = htons(sizeof(struct ip_hdr) + icmp_len);
							ip_reply->id = 4;
							ip_reply->frag = 0;
							ip_reply->ttl = 64;
							ip_reply->proto = 1; //ICMP
							ip_reply->source_addr = ip_hdr->dest_addr;
							ip_reply->dest_addr = ip_hdr->source_addr;
							ip_reply->checksum = 0;
							ip_reply->checksum = htons(checksum((uint16_t *)ip_reply, sizeof(struct ip_hdr)));


							//setam ICMP
							memcpy(icmp_reply, icmp_hdr, icmp_len); // copiem tot request-ul
							icmp_reply->mtype = 0;
							icmp_reply->mcode = 0;
							icmp_reply->check = 0;
							icmp_reply->check = htons(checksum((uint16_t *)icmp_reply, icmp_len));

							send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len, reply_buf, i);
							replied = 1;
							break;
						} else {
							continue;
						}
					}
				}
				if (replied) {
					continue;
				}

			}
			//verificam checksum
			if (checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)) != 0) {
				continue; //checksum invalid
			}

			//verificam time to live
			ip_hdr->ttl--;
			if (ip_hdr->ttl <= 1) {
				//trimitem ICMP time exceeded
				char reply_buf[MAX_PACKET_LEN];
				struct ether_hdr *eth_reply = (struct ether_hdr *)reply_buf;
				struct ip_hdr *ip_reply = (struct ip_hdr *)(reply_buf + sizeof(struct ether_hdr));
				struct icmp_hdr *icmp_reply = (struct icmp_hdr *)(reply_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

				//inversam macurile
				memcpy(eth_reply->ethr_dhost, eth_hdr->ethr_shost, 6);
				memcpy(eth_reply->ethr_shost, eth_hdr->ethr_dhost, 6);
				eth_reply->ethr_type = htons(0x0800);

				//IP header
				ip_reply->ihl = 5;
				ip_reply->ver = 4;
				ip_reply->tos = 0;
				ip_reply->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
				ip_reply->id = htons(0);
				ip_reply->frag = 0;
				ip_reply->ttl = 64;
				ip_reply->proto = 1;
				ip_reply->source_addr = ip_hdr->dest_addr;
				ip_reply->dest_addr = ip_hdr->source_addr;
				ip_reply->checksum = 0;
				ip_reply->checksum = htons(checksum((uint16_t *)ip_reply, sizeof(struct ip_hdr)));

				//ICMP
				memcpy((char *)icmp_reply + sizeof(struct icmp_hdr), ip_hdr, sizeof(struct ip_hdr) + 8);
				icmp_reply->mtype = 11;
				icmp_reply->mcode = 0;
				icmp_reply->check = 0;
				icmp_reply->check = htons(checksum((uint16_t *)icmp_reply, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));

				send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8, reply_buf, interface);
				continue;
			}

			//logest prefix match, cautam in tabela de rutare

			struct route_table_entry *best_route = get_best_route(trie_root, ip_hdr->dest_addr);

			//ICMP Destination Unreachable (type 3, code 0)
			if (best_route == NULL) {

				char reply_buf[MAX_PACKET_LEN];
				struct ether_hdr *eth_reply = (struct ether_hdr *)reply_buf;
				struct ip_hdr *ip_reply = (struct ip_hdr *)(reply_buf + sizeof(struct ether_hdr));
				struct icmp_hdr *icmp_reply = (struct icmp_hdr *)(reply_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

				// inversam MAC-urile
				memcpy(eth_reply->ethr_dhost, eth_hdr->ethr_shost, 6);
				memcpy(eth_reply->ethr_shost, eth_hdr->ethr_dhost, 6);
				eth_reply->ethr_type = htons(0x0800);

				// IP header
				ip_reply->ihl = 5;
				ip_reply->ver = 4;
				ip_reply->tos = 0;
				ip_reply->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
				ip_reply->id = htons(0);
				ip_reply->frag = 0;
				ip_reply->ttl = 64;
				ip_reply->proto = 1;
				ip_reply->source_addr = ip_hdr->dest_addr;
				ip_reply->dest_addr = ip_hdr->source_addr;
				ip_reply->checksum = 0;
				ip_reply->checksum = htons(checksum((uint16_t *)ip_reply, sizeof(struct ip_hdr)));

				// ICMP
				icmp_reply->mtype = 3;
				icmp_reply->mcode = 0;
				icmp_reply->check = 0;

				memcpy((char *)icmp_reply + sizeof(struct icmp_hdr), ip_hdr, sizeof(struct ip_hdr) + 8);

				icmp_reply->check = htons(checksum((uint16_t *)icmp_reply, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));
				send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8, reply_buf, interface);
				continue;
			}
			//recalculam checksum
			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			//adresa MAC sursa = MAC routerului (pe interfata din best_route)
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);

			struct arp_table_entry *entry = get_arp_entry(best_route->next_hop, arp_table, arp_table_len);
			//daca nu gasim next hop facem arp request.
			if (!entry) {
				char *copy = malloc(len);//len vine de la recv_from_any_link
				memcpy(copy, buf, len);//copiem pachetul original

				struct packet *p = malloc(sizeof(struct packet));
				p->payload = copy;
				p->len = len;
				p->interface = best_route->interface;
				p->next_hop = best_route->next_hop;

				queue_enq(waiting_packets, p);

				//construim arp_request
				char arp_buf[MAX_PACKET_LEN];
				struct ether_hdr *eth_req = (struct ether_hdr *)arp_buf;
				struct arp_hdr *arp_req = (struct arp_hdr* )(arp_buf + sizeof(struct ether_hdr));

				//completare ethernet
				memset(eth_req->ethr_dhost, 0xff, 6);// broadcast
				get_interface_mac(best_route->interface, eth_req->ethr_shost);
				eth_req->ethr_type = htons(0x0806);

				// completare ARP header
				arp_req->hw_type = htons(1);//ethernet
				arp_req->proto_type = htons(0x0800);//ip
				arp_req->hw_len = 6;
				arp_req->proto_len = 4;
				arp_req->opcode = htons(1);//ARP request

				get_interface_mac(best_route->interface, arp_req->shwa);
				arp_req->sprotoa = inet_addr(get_interface_ip(best_route->interface));
				memset(arp_req->thwa, 0, 6);
				arp_req->tprotoa = best_route->next_hop;

				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_buf, best_route->interface);
				continue;
			}
			memcpy(eth_hdr->ethr_dhost, entry->mac, 6);
			send_to_link(len, buf, best_route->interface);
		} else {
			//ARP REPLY
			if (ntohs(eth_hdr->ethr_type) == 0x0806) {
				struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
				//daca e request -> raspundem cu un reply
				if (ntohs(arp_hdr->opcode) == 1) {
					// construim ARP reply
					struct ether_hdr *eth_resp = (struct ether_hdr *)buf;
					struct arp_hdr *arp_resp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

					//setam ethernet header
					memcpy(eth_resp->ethr_dhost, eth_hdr->ethr_shost, 6);
					get_interface_mac(interface, eth_resp->ethr_shost);
					eth_resp->ethr_type = htons(0x0806);

					// setam arp header
					arp_resp->hw_type = htons(1);
					arp_resp->proto_type = htons(0x0800);
					arp_resp->hw_len = 6;
					arp_resp->proto_len = 4;
					arp_resp->opcode = htons(2);//arp rreply
					arp_resp->tprotoa = arp_hdr->sprotoa;
					memcpy(arp_resp->thwa, arp_hdr->shwa, 6);
					arp_resp->sprotoa = inet_addr(get_interface_ip(interface));
					get_interface_mac(interface, arp_resp->shwa);

					//trimitem inapoi
					send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
				//daca e reply -> il adaugam in tabela,
				} else if (ntohs(arp_hdr->opcode) == 2) {
					//adaugam in arp table
					if (arp_table_len < 10000) {
						arp_table[arp_table_len].ip = arp_hdr->sprotoa;
						memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
						arp_table_len++;
					}

					//verificam coada pt pachete in asteptare
					int qsize = queue_size(waiting_packets);
					for (int i = 0; i < qsize; i++) {
						struct packet *p = (struct packet *)queue_deq(waiting_packets);

						if (p->next_hop == arp_hdr->sprotoa) {
							struct ether_hdr *eth_hdr = (struct ether_hdr *)p->payload;

							memcpy(eth_hdr->ethr_dhost, arp_hdr->shwa, 6);//seteaza MAC destinatie
							get_interface_mac(p->interface, eth_hdr->ethr_shost); //mac sursa = mac router

							send_to_link(p->len, p->payload, p->interface);

							free(p->payload);
							free(p);
						} else {
							queue_enq(waiting_packets, p); //punem inapoi in coada.
						}
					}
				}
			}
		}
	}
}