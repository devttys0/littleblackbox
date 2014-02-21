#include <netinet/in.h>
#include <pcap.h>

#define IFACE                   0
#define PFILE                   1
#define PCAP_READ_TIMEOUT       0
#define PROMISC                 1
#define DEFAULT_FILTER          "tcp src port 443"
#define ETHER_ADDR_LEN		6

/* Ethernet header */
struct sniff_ethernet {
	char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	char ip_vhl;		/* version << 4 | header length >> 2 */
	char ip_tos;		/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;		/* identification */
	uint16_t ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	char ip_ttl;		/* time to live */
	char ip_p;		/* protocol */
	uint16_t ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
	uint16_t th_sport;	/* source port */
	uint16_t th_dport;	/* destination port */
	uint32_t th_seq;		/* sequence number */
	uint32_t th_ack;		/* acknowledgement number */

	char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	uint16_t th_win;		/* window */
	uint16_t th_sum;		/* checksum */
	uint16_t th_urp;		/* urgent pointer */
};


#define TLS_CONTENT_TYPE_HANDSHAKE	22
#define TLS_HANDSHAKE_TYPE_CERTIFICATE	11

#define TLS_TYPE			0
#define TLS_LENGTH			3
#define TLS_RECORD_HEADER_SIZE		5
#define CERT_LEN_OFFSET			7
#define CERT_OFFSET			10

char *sniff(char *iface, char *filter, int type);
char *process_packet(const u_char *packet, struct pcap_pkthdr *header);
pcap_t *initialize_network(char *iface, char *filter, int type);
