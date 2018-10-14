#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

/*
 * ARP header.
 * http://www.networksorcery.com/enp/protocol/arp.htm
 */
struct arpheader {
  unsigned short int hardware; // Hardware address.
  unsigned short int protocol; // Protocol address.
  unsigned char hardware_length; // Hardware address length.
  unsigned char protocol_length; // Protocol address length.
  unsigned short int opcode; // Op code: 1=request 2=reply.
  unsigned char sender_addr[6]; // Sender MAC address.
  unsigned char sender_ip[4]; // Sender IP address.
  unsigned char target_addr[6]; // Target MAC address.
  unsigned char target_ip[4]; // Target IP address.
};

/*
 * Ethernet header.
 * http://www.networksorcery.com/enp/protocol/ethernet.htm
 */
 struct ethheader {
   unsigned char eth_dest[6]; // Destination address.
   unsigned char eth_src[6]; // Source address.
   unsigned short eth_type; // Type: ARP=0x0806 IP=0x0800.
 };

int main(){
  int packet_socket;
  unsigned char local_addr[6];
  // Get list of interface addresses.
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
  // Have the list, loop over the list.
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
    //Check if this is a packet address, there will be one per
    //interface.  There are IPv4 and IPv6 as well, but we don't care
    //about those for the purpose of enumerating interfaces. We can
    //use the AF_INET addresses in this list for example to get a list
    //of our own IP addresses
    if(tmp->ifa_addr->sa_family==AF_PACKET){
      printf("Interface: %s\n",tmp->ifa_name);
      // create a packet socket on interface r?-eth1
      if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
	       printf("Creating Socket on interface %s\n",tmp->ifa_name);

         // get our MAC address and store it.
         struct sockaddr_ll *pAddr = (struct sockaddr_ll *)tmp->ifa_addr;
         printf("MAC: ");
			   for(int i = 0; i < 5; i++) {
           local_addr[i] = pAddr->sll_addr[i];
           printf("%i:", local_addr[i]);
         }
         printf("%i\n", local_addr[5]);

         //create a packet socket
	       //AF_PACKET makes it a packet socket
	       //SOCK_RAW makes it so we get the entire packet
	       //could also use SOCK_DGRAM to cut off link layer header
         //ETH_P_ALL indicates we want all (upper layer) protocols
	       //we could specify just a specific one
	       packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	       if(packet_socket<0){
           perror("socket");
           return 2;
         }
	        //Bind the socket to the address, so we only get packets
	        //recieved on this specific interface. For packet sockets, the
	        //address structure is a struct sockaddr_ll (see the man page
	        //for "packet"), but of course bind takes a struct sockaddr.
	        //Here, we can use the sockaddr we got from getifaddrs (which
	        //we could convert to sockaddr_ll if we needed to)
	        if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
	           perror("bind");
          }
        }
      }
    }
    //loop and recieve packets. We are only looking at one interface,
    //for the project you will probably want to look at more (to do so,
    //a good way is to have one socket per interface and use select to
    //see which ones have data)
    printf("Ready to recieve now\n");
    while(1){
      char buf[1500], sendbuf[1500];
      struct sockaddr_ll recvaddr;
      int recvaddrlen=sizeof(struct sockaddr_ll);
      //we can use recv, since the addresses are in the packet, but we
      //use recvfrom because it gives us an easy way to determine if
      //this packet is incoming or outgoing (when using ETH_P_ALL, we
      //see packets in both directions. Only outgoing can be seen when
      //using a packet socket with some specific protocol)
      int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
      //ignore outgoing packets (we can't disable some from being sent
      //by the OS automatically, for example ICMP port unreachable
      //messages, so we will just ignore them here)
      if(recvaddr.sll_pkttype==PACKET_OUTGOING) continue;
      //start processing all others
      printf("Got a %d byte packet\n", n);

      //what else to do is up to you, you can send packets with send,
      //just like we used for TCP sockets (or you can use sendto, but it
      //is not necessary, since the headers, including all addresses,
      //need to be in the buffer you are sending)

    }
    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}
