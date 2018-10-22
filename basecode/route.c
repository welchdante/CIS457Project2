#define _GNU_SOURCE

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>

/*
 * ARP header.
 * http://www.networksorcery.com/enp/protocol/arp.htm
 */
struct arpheader {
  unsigned short hardware; // Hardware address.
  unsigned short protocol; // Protocol address.
  unsigned char hardware_length; // Hardware address length.
  unsigned char protocol_length; // Protocol address length.
  unsigned short opcode; // Op code: 1=request 2=reply.
  unsigned char sender_addr[6]; // Sender MAC address.
  unsigned char sender_ip[4]; // Sender IP address.
  unsigned char target_addr[6]; // Target MAC address.
  unsigned char target_ip[4]; // Target IP address.
};

/*
 * IP header.
 * http://www.networksorcery.com/enp/protocol/ip.htm
 */
struct ipheader {
  uint8_t ihl:4, version:4; // Version=format of IP packet header, IHL=length
  uint8_t tos; // http://www.networksorcery.com/enp/rfc/rfc2474.txt
  uint16_t len; // Datagram length.
  uint16_t id; // Datagram identity.
  uint16_t flag_offset; // Either: (R) reserved, (DF) don't fragment, or (MF) more fragments.
  uint8_t ttl; // Time to live.
  uint8_t protocol; // Protocol type.
  uint16_t checksum; // One's compliment checksum of the IP header.
  unsigned char src_ip[4]; // Sender IP address.
  unsigned char dest_ip[4]; // Target IP address.
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

 /*
  * ICMP header.
  * http://www.networksorcery.com/enp/protocol/icmp.htm
  */
struct icmpheader {
  uint8_t type; // ICMP message format.
  uint8_t code; // Qualifies ICMP message.
  uint16_t checksum; // Checksum for the ICMP message.
  uint16_t id; //random number
  uint16_t seq; //seq #
  uint32_t data; //data sent in icmp
};

/*
 * Hold the routing table information.
 */
struct routingTable {
  char ipAddress[15];
  char ipHopper[15];
  char name[10];
};

/* Hold IP Addresses */
struct ip_addr{
  char interface_name[8];
  int ip;
};

/* Hold MAC Addresses */
struct mac_addr {
  char interface_name[8];
  int sockid;
  struct sockaddr_ll* socket;
};

/* Fills routing table with values. */
void loadTable(struct routingTable *arrRoutingTable, int arrLength);

/* Checksum for ICMP. */
uint16_t checksum(unsigned char *addr, int len);

/* Main program... duh */
int main(){
  int packet_socket;
  unsigned char local_addr[6]; // >>> might delete later

  // Load routing table in.
  struct routingTable myRoutingTable[6];
  loadTable(myRoutingTable, 6);

  printf("Testing everything loaded correctly...\n");
  int test;
  for(test = 0; test < 3; test++) {
    printf("IP Address: %s IP Hop: %s Name: %s\n", myRoutingTable[test].ipAddress, myRoutingTable[test].ipHopper, myRoutingTable[test].name);
  }

  //int numip = 0;

  // file descriptor set and set all to zero
  fd_set sockets;
  FD_ZERO(&sockets);

  //need array of ints, (a vector would be nice lol) for interfaces
  //need array of chars for addresses
  struct ip_addr ips[10]; // all of my IPS
  int num_ip = 0;
  struct mac_addr macs[10]; // all of my MACS
  int num_mac = 0;

  int numRouter = 1; // router identifier ASSUMING 1 FOR NOW... not gonna check

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

    // Get this IP if it is IPv4 
    if (tmp->ifa_addr->sa_family==AF_INET) {
      struct sockaddr_in *sockaddr;
      struct ip_addr address;
      sockaddr = (struct sockaddr_in*)tmp->ifa_addr;
      printf("IP added to list: %d\n", sockaddr->sin_addr.s_addr);
      strcpy(address.interface_name, tmp->ifa_name);
      address.ip = sockaddr->sin_addr.s_addr;
      ips[num_ip] = address;
      num_ip++;
    }

    if(tmp->ifa_addr->sa_family==AF_PACKET){
      printf("Interface: %s\n",tmp->ifa_name);

      // create a packet socket on interface r?-eth1
      if(!strncmp(&(tmp->ifa_name[3]),"eth",3)){
        printf("Creating Socket on interface %s\n",tmp->ifa_name);
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

        // add local_mac->sll_addr to addresses
        // get our MAC address and store it.
        struct mac_addr mac;
        mac.sockid = packet_socket;
        mac.socket = (struct sockaddr_ll *)tmp->ifa_addr;
        strcpy(mac.interface_name, tmp->ifa_name);
        macs[num_mac] = mac;
        num_mac++;
        // struct sockaddr_ll *pAddr = (struct sockaddr_ll *)tmp->ifa_addr;
        // memcpy(local_addr, pAddr->sll_addr, 6);
        // printf("MAC: ");
        // int macs;
        // for(macs = 0; macs < 5; macs++) {
        //   //local_addr[i] = pAddr->sll_addr[i];
        //   printf("%i:", local_addr[macs]);
        // }
        // printf("%i\n", local_addr[5]);

        // add packet_socket to interfaces
        // put the socket in file descriptor.
        FD_SET(packet_socket, &sockets);
      }
    }
  }
  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);

  //loop and recieve packets. We are only looking at one interface,
  //for the project you will probably want to look at more (to do so,
  //a good way is to have one socket per interface and use select to
  //see which ones have data)
  printf("Ready to recieve now\n");
  while(1) {
    struct sockaddr_ll recvaddr;
    int recvaddrlen=sizeof(struct sockaddr_ll);

    fd_set tmp_set = sockets; // copy of set
    // take any file descriptors in the set in second parameter and check if capable of reading from those file descriptors (is there data?)
    // modifies parameter so that all that is left in the set is anything with data
    select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);

    int i;
    for (i = 0; i < FD_SETSIZE; i++) {
      char buf[1500], bufsend[1500];
      struct ethheader *eh_incoming, *eh_outgoing;
      struct arpheader *ah_incoming, *ah_outgoing;
      struct ipheader *ih_incoming, *ih_outgoing;
      struct icmpheader *icmph_incoming, *icmph_outgoing;

      if (FD_ISSET(i, &tmp_set)) { // is this in the set?
        //we can use recv, since the addresses are in the packet, but we
        //use recvfrom because it gives us an easy way to determine if
        //this packet is incoming or outgoing (when using ETH_P_ALL, we
        //see packets in both directions. Only outgoing can be seen when
        //using a packet socket with some specific protocol)
        int n = recvfrom(i, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
        
        //ignore outgoing packets (we can't disable some from being sent
        //by the OS automatically, for example ICMP port unreachable
        //messages, so we will just ignore them here)
        if(recvaddr.sll_pkttype==PACKET_OUTGOING) continue;

        //start processing all others
        printf("Got a %d byte packet\n", n);

        // Store data in the structs.
        eh_incoming = (struct ethheader*) buf;
        ah_incoming = (struct arpheader*) (buf + sizeof(struct ethheader));
        ih_incoming = (struct ipheader*) (buf + sizeof(struct ethheader));

        char packet_ip[20];
        // build IP string for comparing later
        snprintf(packet_ip, sizeof(packet_ip), "%d.%d.%d.%d", ih_incoming->dest_ip[0], 
                                                              ih_incoming->dest_ip[1], 
                                                              ih_incoming->dest_ip[2], 
                                                              ih_incoming->dest_ip[3]);                                   

        // Find out what type this is!
        eh_incoming->eth_type = ntohs(eh_incoming->eth_type);
        printf("Type: %x\n", eh_incoming->eth_type);

        if (eh_incoming->eth_type == ETHERTYPE_ARP) {
          printf("I think its ARP!\n");

          // Is this an ARP reply?
          if (ah_incoming->opcode == 2) {
            printf("Got an ARP REPLY\n");
            // forward packet to corresponding MAC address
          }
          if (ah_incoming->opcode == 1) {

          }

          // Copy data into an ARP struct.
          printf("Building the ARP header right now...\n");
          ah_outgoing = (struct arpheader*) (bufsend + sizeof(struct ethheader));
          ah_outgoing->hardware = htons(1);
          ah_outgoing->protocol = htons(ETH_P_IP);
          ah_outgoing->hardware_length = 6;
          ah_outgoing->protocol_length = 4;
          ah_outgoing->opcode = htons(2);
          memcpy(ah_outgoing->sender_addr, local_addr, 6);
          memcpy(ah_outgoing->sender_ip, ah_incoming->target_ip, 4);
          memcpy(ah_outgoing->target_addr, ah_incoming->sender_addr, 6);
          memcpy(ah_outgoing->target_ip, ah_incoming->sender_ip, 4);

          // Copy data into an Ethernet Struct.
          printf("Building the ethernet header right now...\n");
          eh_outgoing = (struct ethheader*) bufsend;
          memcpy(eh_outgoing->eth_dest, eh_incoming->eth_src, 6);
          memcpy(eh_outgoing->eth_src, eh_incoming->eth_dest, 6);
          eh_outgoing->eth_type = htons(0x0806);

          // Send the reply.
          printf("Now sending the ARP reply...\n");
          send(i, bufsend, 42, 0);
        } else if (eh_incoming->eth_type == ETHERTYPE_IP) {
          printf("I think its IP/ICMP!\n");
          icmph_incoming = (struct icmpheader*) (buf + sizeof(struct ethheader) + sizeof(struct ipheader));

          // Check if echo request.
          if (icmph_incoming->type == 8) {
            printf("This is an ICMP ECHO request! Let's forward it!\n");
            printf("Packet ip: %s \n", packet_ip);

            for (int table=0; table<sizeof myRoutingTable / sizeof myRoutingTable[0]; table++) {
              if (strcmp(packet_ip, myRoutingTable[table].ipAddress)) {
                printf("This packet belongs to router %d, forwarding.\n", table);
                memcpy(bufsend, buf, 1500);
                icmph_outgoing = (struct icmpheader*) (bufsend + sizeof(struct ethheader) + sizeof(struct ipheader));
                icmph_outgoing->type = 0;
                icmph_outgoing->checksum = 0;
                icmph_outgoing->checksum = checksum((char*) icmph_outgoing, (1500 - sizeof(struct ethheader) - sizeof(struct ipheader)));

                //copy data into ip header
                ih_outgoing = (struct ipheader*) (bufsend + sizeof(struct ethheader));
                memcpy(ih_outgoing->src_ip, ih_incoming->dest_ip, 4);
                memcpy(ih_outgoing->dest_ip, myRoutingTable[table].ipAddress, 4); 
                send(i, bufsend, n, 0);
              }
            }

            // Copy the packet.
            memcpy(bufsend, buf, 1500);

            // Copy data into ICMP header.
            printf("Building the ICMP header right now...\n");
            icmph_outgoing = (struct icmpheader*) (bufsend + sizeof(struct ethheader) + sizeof(struct ipheader));
            icmph_outgoing->type = 0;
            icmph_outgoing->checksum = 0;
            icmph_outgoing->checksum = checksum((char*) icmph_outgoing, (1500 - sizeof(struct ethheader) - sizeof(struct ipheader)));

            // Copy data into IP header.
            ih_outgoing = (struct ipheader*) (bufsend + sizeof(struct ethheader));
            memcpy(ih_outgoing->src_ip, ih_incoming->dest_ip, 4);
            memcpy(ih_outgoing->dest_ip, ih_incoming->src_ip, 4);

            // Copy data into ethernet header.
            printf("Building the ethernet header right now...\n");
            eh_outgoing = (struct ethheader*) bufsend;
            memcpy(eh_outgoing->eth_dest, eh_incoming->eth_src, 6);
            memcpy(eh_outgoing->eth_src, eh_incoming->eth_dest, 6);
            eh_outgoing->eth_type = htons(0x0800);

            // Sending an ICMP response packet.
            printf("Sending ICMP response...\n");
            send(i, bufsend, 98, 0);
          }
        }
      }
    }
  }
  //exit
  return 0;
}

/*
 * Checksum calculation.
 * Taken from: https://github.com/kohler/ipsumdump/blob/master/libclick-2.1/libsrc/in_cksum.c
 */
uint16_t checksum(unsigned char *addr, int len) {
  int nleft = len;
  const uint16_t *w = (const uint16_t *)addr;
  uint32_t sum = 0;
  uint16_t answer = 0;

  /*
  * Our algorithm is simple, using a 32 bit accumulator (sum), we add
  * sequential 16 bit words to it, and at the end, fold back all the
  * carry bits from the top 16 bits into the lower 16 bits.
  */
  while (nleft > 1)  {
  sum += *w++;
  nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
  *(unsigned char *)(&answer) = *(const unsigned char *)w ;
  sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum;              /* truncate to 16 bits */
  return answer;
}


/*
 * Fills routing table with values.
 */
void loadTable(struct routingTable *arrRoutingTable, int arrLength) {
  //struct routingTable myRoutingTable[6];
  FILE* fp;
  fp = fopen("r1-table.txt", "r"); // open read only.
  if (fp == NULL) {
    perror("Error opening the file. Now shutting down...\n");
    exit(1);
  }

  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  char string[50];

  int i = 0;
  while (((read = getline(&line, &len, fp)) != -1) && i < arrLength) {
    //printf("%s", line);
    strcpy(string, line);
    string[read]  = '\0';
    strcpy(arrRoutingTable[i].ipAddress, (char *) strtok(string, " "));
    strcpy(arrRoutingTable[i].ipHopper, (char *) strtok(NULL, " "));
    strcpy(arrRoutingTable[i].name, (char *) strtok(NULL, "\n"));

    printf("IP Address: %s IP Hop: %s Name: %s\n", arrRoutingTable[i].ipAddress, arrRoutingTable[i].ipHopper, arrRoutingTable[i].name);
    i++;
  }
  free(line);
  fclose(fp);
}


