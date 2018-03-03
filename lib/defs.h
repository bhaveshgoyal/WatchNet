#ifndef _DEFS_H
#define _DEFS_H
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN 4
#define ETHER_SIZE 14

#define ETHERTYPE_ARP		0x0806
#define ETHERTYPE_IP		0x0800

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_arp {
	u_int16_t arp_htype;				/* hardware type: ethernet, frame-relay, ... */
	u_int16_t arp_ptype;				/* protocol type: ip, ipx, ... */
	u_char arp_hlen;				/* harware address length: eth-0x06, ... */
	u_char arp_plen;				/* protocol address length: ip-0x04, ... */
	u_int16_t arp_oper;				/* operation: request:0x01, reply:0x02, ... */
	u_char arp_sha[ETHER_ADDR_LEN];			/* source hardware address */
	u_char arp_sip[IP_ADDR_LEN];			/* source protocol address */
	u_char arp_dha[ETHER_ADDR_LEN];			/* destination hardware address */
	u_char arp_dip[IP_ADDR_LEN];			/* destination protocol address */
};

struct sniff_udp {
	u_short udp_sport;
	u_short udp_dport;
	short len;
	u_short udp_sum;
};
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
#endif
