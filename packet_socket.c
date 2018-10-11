#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>


/*
* @author Hunter Hubers
*
* 6. Upon recieving a (incoming) packet, parse out and print the Ethernet header information (destination, source, and type). 
* You should not do this byte by byte, instead you should use struct ether_header from /usr/include/net/ethernet.h. (3 points)
*
* 7. For packets where the type is IPv4 (0x800), print the source and destination addresses from the IP header 
* (once again, do not parse byte by byte, use struct iphdr from /usr/include/netinet/ip.h). (2 points)
*/

int main(int argc, char const *argv[]) {
	int packet_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if (packet_socket<0){
		perror("socket");
		return 1;
	}

	struct ether_header *eptr;
	struct iphdr *ipptr; 
	struct sockaddr_ll serveraddr, clientaddr; // sockaddr_11 <- useful documentation for next project
	serveraddr.sll_family=AF_PACKET;
	serveraddr.sll_protocol=htons(ETH_P_ALL);
	serveraddr.sll_ifindex=if_nametoindex("h2-eth0"); // h2 is hard coded for mininet

	int e = bind(packet_socket, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if (e<0){
		perror("bind");
		return 2;
	}

	while(1){
		char buf[1514];
		int len = sizeof(clientaddr);
		int n = recvfrom(packet_socket, buf, 1514, 0, (struct sockaddr*)&clientaddr, &len);

		if (clientaddr.sll_pkttype==PACKET_OUTGOING){
			continue;
		}

		eptr = (struct ether_header*) buf;
		printf("Destination: ");
		for(int i=0;i<sizeof(eptr->ether_dhost);i++){
 			if (i == sizeof(eptr->ether_dhost) - 1) {
 				printf("%x",eptr->ether_dhost[i]);
 			} else {
 				printf("%x:",eptr->ether_dhost[i]);
 			}
		}
		printf("\nSource: ");
		for(int i=0;i<sizeof(eptr->ether_shost);i++){
			if (i == sizeof(eptr->ether_shost) - 1) {
				printf("%x",eptr->ether_shost[i]);
			} else {
				printf("%x:",eptr->ether_shost[i]);
			}
		}
		printf("\nType: %x\n", ntohs(eptr->ether_type));

		if(ntohs(eptr->ether_type) == 0x800){
						
			ipptr = (struct iphdr *) &buf[14];
			char a[4];
			memcpy(a,&(ipptr->saddr),4);
			
			printf("\nIPv4 Source: ");			
			for(int i=0;i<sizeof(a);i++){
				if (i == sizeof(a)-1) {
					printf("%d", a[i]);
				} else {
					printf("%d.",a[i]);			
				}
			}

			char b[4];
			memcpy(b,&(ipptr->daddr),4);
			
			printf("\nIPv4 Destination: ");			
			for(int i=0;i<sizeof(b);i++){
				if (i == sizeof(b)-1) {
					printf("%d", b[i]);
				} else {
					printf("%d.",b[i]);			
				}			
			}
			printf("\n\n------\n\n");
		}
	}
	return 0;
}
