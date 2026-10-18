#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"
#include "protocols.h"
#include "queue.h"

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806

#define ARP_REQUEST 1
#define ARP_REPLY   2

#define ICMP_ECHO_REPLY    0
#define ICMP_DEST_UNREACH  3
#define ICMP_ECHO_REQUEST  8
#define ICMP_TIME_EXCEEDED 11

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len = 0; // numarul de intrari arp salvate

queue waiting_queue; // coada pentru pachetele care asteapta un arp reply

// comparator pentru qsort care ajuta functia de cautare binara sa gaseasca mai usor ruta pentru destinatie
int compare_routes(const void *a, const void *b) {
    const struct route_table_entry *e1 = (const struct route_table_entry *)a;
    const struct route_table_entry *e2 = (const struct route_table_entry *)b;

    uint32_t p1 = ntohl(e1->prefix & e1->mask);
    uint32_t p2 = ntohl(e2->prefix & e2->mask);

    if(p1 < p2) return -1;

    if(p1 > p2) return 1;

    uint32_t m1 = ntohl(e1->mask);
    uint32_t m2 = ntohl(e2->mask);

    if(m1 < m2) return -1;

    if(m1 > m2) return 1;

    return 0;
}

// cea mai buna ruta pentru ip destinatie
struct route_table_entry *get_best_route(uint32_t dest_ip) {
    int low = 0;
    int high = rtable_len - 1;
    struct route_table_entry *res = NULL;

    while(low <= high) {
        int mid = low + (high - low) / 2;

        if(ntohl(rtable[mid].prefix & rtable[mid].mask) == ntohl(dest_ip & rtable[mid].mask)) {
            res = &rtable[mid];
            low = mid + 1;
        } else if(ntohl(rtable[mid].prefix & rtable[mid].mask) < ntohl(dest_ip & rtable[mid].mask)) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    return res;
}

// cauta in tabela arp o intrare pentru ip-ul primit
struct arp_table_entry *get_arp_entry(uint32_t ip) {
    for(int i = 0; i < arp_table_len; i++) {
        if(arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

// construieste si trimite un arp request
void send_arp_request(uint32_t next_hop, int out_interface) {
    char arp_buf[MAX_PACKET_LEN];
    memset(arp_buf, 0, sizeof(arp_buf));

    struct ether_hdr *eth = (struct ether_hdr *)arp_buf;
    struct arp_hdr *arp = (struct arp_hdr *)(arp_buf + sizeof(struct ether_hdr));

    // header ethernet
    eth->ethr_type = htons(ETHERTYPE_ARP);
    get_interface_mac(out_interface, eth->ethr_shost);
    memset(eth->ethr_dhost, 0xFF, 6); // broadcast

    // header arp
    arp->opcode = htons(ARP_REQUEST);
    arp->hw_type = htons(1); // ethernet
    arp->proto_type = htons(ETHERTYPE_IP);
    arp->hw_len = 6; // mac
    arp->proto_len = 4; // ipv4

    arp->tprotoa = next_hop; // ip ul cautat
    memset(arp->thwa, 0, 6); // mac necunoscut
    get_interface_mac(out_interface, arp->shwa);
    arp->sprotoa = inet_addr(get_interface_ip(out_interface));

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_buf, out_interface);
}

// transform un arp request intr-un arp reply si il trimit inapoi
void send_arp_reply(char *buf, size_t len, int interface) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    arp->opcode = htons(ARP_REPLY);

    // inversez ip urile
    uint32_t aux_ip = arp->sprotoa;
    arp->sprotoa = arp->tprotoa;
    arp->tprotoa = aux_ip;

    // destinatia reply ului devine cel care a trimis request ul
    memcpy(arp->thwa, arp->shwa, 6);
    get_interface_mac(interface, arp->shwa);
    memcpy(eth->ethr_dhost, eth->ethr_shost, 6);
    get_interface_mac(interface, eth->ethr_shost);
    send_to_link(len, buf, interface);
}

// construiesc si trimit un mesaj icmp
void send_icmp_packet(char *old_buf, int type, int code, int interface) {
    char buf[MAX_PACKET_LEN];
    memset(buf, 0, sizeof(buf));

    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    struct ether_hdr *old_eth = (struct ether_hdr *)old_buf;
    struct ip_hdr *old_ip = (struct ip_hdr *)(old_buf + sizeof(struct ether_hdr));

    // header ethernet pentru reply
    eth->ethr_type = htons(ETHERTYPE_IP);
    memcpy(eth->ethr_dhost, old_eth->ethr_shost, 6);
    get_interface_mac(interface, eth->ethr_shost);

    // header ip pentru mesajul icmp
    memcpy(ip, old_ip, sizeof(struct ip_hdr));
    ip->proto = 1; /* ICMP */
    ip->ttl = 64;
    ip->dest_addr = old_ip->source_addr;
    ip->source_addr = inet_addr(get_interface_ip(interface));

    int icmp_len;

    // daca raspunde la ping pastrez payload ul original
    if(type == ICMP_ECHO_REPLY) {
        icmp_len = ntohs(old_ip->tot_len) - sizeof(struct ip_hdr);
    } else {
        icmp_len = sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;  // daca e eroare atunci trimit headerul ip original si primii 8 bytes din payload
    }

    icmp->mtype = type;
    icmp->mcode = code;
    icmp->check = 0;

    if (type == ICMP_ECHO_REPLY) {
        struct icmp_hdr *old_icmp = (struct icmp_hdr *)(old_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
        icmp->un_t.echo_t.id = old_icmp->un_t.echo_t.id;
        icmp->un_t.echo_t.seq = old_icmp->un_t.echo_t.seq;
        memcpy(icmp + 1, old_icmp + 1, icmp_len - sizeof(struct icmp_hdr));
    } else {
        memcpy(icmp + 1, old_ip, sizeof(struct ip_hdr) + 8);
    }

    // recalculez checksum
    ip->tot_len = htons(sizeof(struct ip_hdr) + icmp_len);
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
    icmp->check = htons(checksum((uint16_t *)icmp, icmp_len));
    send_to_link(ntohs(ip->tot_len) + sizeof(struct ether_hdr), buf, interface);
}

// proceseaza un pachet ip primit
void process_ip_packet(char *buf, size_t len, int interface) {
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    // salvez checksum ul primit si recalculez
    uint16_t old_checksum = ip->checksum;
    ip->checksum = 0;
    if(checksum((uint16_t *)ip, sizeof(struct ip_hdr)) != ntohs(old_checksum)) {
        return;
    }

    // daca routerul este destinatia extrag headerul icmp
    if(ip->dest_addr == inet_addr(get_interface_ip(interface))) {
        struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
        if(icmp->mtype == ICMP_ECHO_REQUEST) {
            send_icmp_packet(buf, ICMP_ECHO_REPLY, 0, interface); // daca e ping raspund cu echo reply
        }
        return;
    }

    // ttl a expirat trimit time exceeded
    if(ip->ttl <= 1) {
        send_icmp_packet(buf, ICMP_TIME_EXCEEDED, 0, interface);
        return;
    }

    // caut ruta daca nu exista trimit Destination Unreachable
    struct route_table_entry *best_route = get_best_route(ip->dest_addr);
    if (!best_route) {
        send_icmp_packet(buf, ICMP_DEST_UNREACH, 0, interface);
        return;
    }

    ip->ttl--;
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
    struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);

    // daca am gasit mac ul in tabela arp
    if(arp_entry != NULL) {
        memcpy(eth->ethr_dhost, arp_entry->mac, 6); // rescriu mac ul destinatie
        get_interface_mac(best_route->interface, eth->ethr_shost); // mac sursa este mac ul interfetei de iesire
        send_to_link(len, buf, best_route->interface); // forwardez pachetul
    } else {
        char *queued_packet = malloc(len); // fac copie a pachetului
        memcpy(queued_packet, buf, len); // copiez pachetul
        queue_enq(waiting_queue, queued_packet); // il pun in coada
        send_arp_request(best_route->next_hop, best_route->interface); // trimit arp request
    }
}

// proceseaza un pachet arp primit
void process_arp_packet(char *buf, size_t len, int interface) {
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr)); // extrag headerul arp

    // daca este arp request si este pentru router raspund cu arp reply
    if(ntohs(arp->opcode) == ARP_REQUEST) {
        if(arp->tprotoa == inet_addr(get_interface_ip(interface))) {
            send_arp_reply(buf, len, interface);
        }
    } else if(ntohs(arp->opcode) == ARP_REPLY) {
        // daca este arp reply
        memcpy(arp_table[arp_table_len].mac, arp->shwa, 6);
        arp_table[arp_table_len].ip = arp->sprotoa;
        arp_table_len++;
        queue remaining_packets = create_queue(); // coada temporara pentru pachetele care raman in asteptare

        // cat timp mai am pachete in coada
        while(!queue_empty(waiting_queue)) {
            char *packet = queue_deq(waiting_queue); // scot un pachet
            struct ip_hdr *queued_ip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr)); // extrag headerul ip
            struct route_table_entry *queued_route = get_best_route(queued_ip->dest_addr); // gasesc ruta lui

            // daca acest astepta exact acest arp reply
            if(queued_route && queued_route->next_hop == arp->sprotoa) {
                memcpy(((struct ether_hdr *)packet)->ethr_dhost, arp->shwa, 6); // completez mac ul destinatie
                get_interface_mac(queued_route->interface, ((struct ether_hdr *)packet)->ethr_shost); // completez mac ul sursa
                send_to_link(ntohs(queued_ip->tot_len) + sizeof(struct ether_hdr), packet, queued_route->interface); // trimit pachetul
                free(packet); // eliberez copia din coada
            } else {
                queue_enq(remaining_packets, packet); // daca inca nu poate fi trimis il mut in coada temporara
            }
        }

        // reconstruiesc coada temporara
        while(!queue_empty(remaining_packets)) {
            queue_enq(waiting_queue, queue_deq(remaining_packets));
        }
    }
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    init(argv + 2, argc - 2);

    rtable = malloc(100000 * sizeof(struct route_table_entry));
    rtable_len = read_rtable(argv[1], rtable);
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_routes);

    arp_table = malloc(1000 * sizeof(struct arp_table_entry));
    waiting_queue = create_queue();

    // bucla infinita pentru router pentru ca primeste permanent
    while (1) {
        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len); // primesc pachet de pe oricare interfata
        DIE(interface < 0, "recv_from_any_link");

        struct ether_hdr *eth = (struct ether_hdr *)buf; // extrag headerul ethernet
        uint16_t ethertype = ntohs(eth->ethr_type); // aflu tipul de payload

        // daca pachetul contine ipv4
        if(ethertype == ETHERTYPE_IP) {
            process_ip_packet(buf, len, interface);
        } else if(ethertype == ETHERTYPE_ARP) { // daca pachetul contine arp
            process_arp_packet(buf, len, interface);
        }
    }

    return 0;
}
