
/** BoB 7기 원혜린 */
/** 제출 일자: 2018년 07월 30일 */
/** params sample: ./pcap_test any */

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPPROTO_TCP 0x06
#define IPPROTO_UDP 0x11
#define IPPROTO_ICMP 0x01


#define ETH_ALEN 6
#define ETH_SIZE 14


void usage() {
	printf("params: pcap_test <interface> \n");
}

struct ethhdr {
	u_char ethdest[ETH_ALEN];	// Destination MAC Address
	u_char ethsrc[ETH_ALEN];	// Source MAC Address
	u_short e_type;
};

struct iphdr {
	u_int8_t ip_vhl; /* version and header length */
	u_int8_t ip_tos;  /* type of service */
	u_int16_t ip_len; /* total length */
	u_int16_t ip_id; /* identification */
	u_int16_t ip_off; /* fragment offset field */
	#define IP_RF 0x8000 /* reserved fragment flag */
	#define IP_DF 0x4000 /* dont fragment flag */
	#define IP_MF 0x2000 /* more fragments flag */
	#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
	u_int8_t ip_ttl; /* time to live */
	u_int8_t ip_p; /* protocol */
	u_int16_t ip_sum; /* checksum */
	struct in_addr ip_source;	/* source ip address */
	struct in_addr ip_destination; /* dest ip address */
};

	
struct tcphdr {
	u_int16_t th_sport; /* source port */
	u_int16_t th_dport; /* destination port */
	u_int32_t th_seq; /* sequence number */
	u_int32_t th_ack; /* acknowledgement number */
	u_int8_t th_off_x2; /* data offset & (unused) */
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	u_int16_t th_win; /* window */
	u_int16_t th_sum; /* checksum */
	u_int16_t th_urp; /* urgent pointer */
};

int main(int argc, char* argv[]) {
	if (argc != 2) {
    		usage();
    		return -1;
	}

  	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	unsigned short e_type;

	struct ethhdr *ethernet;
	struct iphdr *iphdrs;
	struct tcphdr *tcphdrs;


	char *data;
	int data_length;
	printf("\n");
  	while (true) {
   		struct pcap_pkthdr* header;
	    const u_char* packet;
	    int res = pcap_next_ex(handle, &header, &packet); //handle, header pointer, buffer start address
    		
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("%u bytes captured\n\n", header->caplen);

		ethernet = (struct ethhdr *)(packet);
		e_type = ntohs(ethernet->e_type);
		const u_int8_t *dst_mac = ethernet->ethdest;
		const u_int8_t *src_mac = ethernet->ethsrc;

		printf("Source MAC: ");
		for (int i=0; i<ETH_ALEN; i++) {
			printf("%02x ", src_mac[i]);
		}
		printf("\nDestination MAC: ");
		for (int i=0; i<ETH_ALEN; i++) {
			printf("%02x ", dst_mac[i]);
		}
		printf("\n");

		if (e_type == ETHERTYPE_IP) {
			printf("==IP==\n");
			iphdrs = (struct iphdr*)(packet + ETH_SIZE);
			printf("Source IP: %s\n", inet_ntoa(iphdrs->ip_source));
			printf("Destination IP: %s\n", inet_ntoa(iphdrs->ip_destination));

			if (iphdrs->ip_p == IPPROTO_TCP) {
				printf("==TCP==\n");
				tcphdrs = (struct tcphdr *)(packet + ETH_SIZE + ((((iphdrs)->ip_vhl) & 0x0f)*4));

				printf("Source Port: %d\n", ntohs(tcphdrs->th_sport));
				printf("Destination Port: %d\n", ntohs(tcphdrs->th_dport));
				
				data = (char *)(packet + ETH_SIZE + ((((iphdrs)->ip_vhl) & 0x0f)*4) + ((((tcphdrs)->th_off_x2 & 0xf0) >> 4)*4));
				data_length = ntohs(iphdrs->ip_len)-(((((iphdrs)->ip_vhl) & 0x0f)*4) + ((((tcphdrs)->th_off_x2 & 0xf0) >> 4)*4));

				if (data_length != 0) {
					printf("data: ");(((tcphdrs)->th_off_x2 & 0xf0) >> 4);
					for (int i=1; i<data_length; i++) {
						printf("%02x ", data[i-1]);
						if (i == 16) {
							break;
						}
					}
					printf("\n\n");
				}
			}
		}
		printf("--------------------------------------\n\n");
	}
  	pcap_close(handle);
  	return 0;
}

