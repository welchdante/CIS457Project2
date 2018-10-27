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
  uint8_t v_ihl[8]; // Version=format of IP packet header, IHL=length
  //uint8_t tos; // http://www.networksorcery.com/enp/rfc/rfc2474.txt
  //uint16_t len; // Datagram length.
  //uint16_t id; // Datagram identity.
  //uint16_t flag_offset; // Either: (R) reserved, (DF) don't fragment, or (MF) more fragments.
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

struct icmperror {
  uint8_t type;
  uint8_t code;
  uint8_t checksum;
  union {
    struct {
      uint16_t unused;
      uint16_t nextHop;
    } dest;
    struct {
      uint32_t unused;
    } ttl;
  } un;
};

/*
 * Hold the routing table information.
 */
struct routingTable {
  char ipAddress[9];
  char ipBits[3];
  char ipHopper[9];
  char name[8];
};

struct interface {
  char* name;
  int sockNum;
  unsigned char mac[6];
  unsigned char ip[4];
};

/* Fills routing table with values. */
int loadTable(struct routingTable *arrRoutingTable);

/* Checksum for ICMP. */
uint16_t checksum(unsigned char *addr, int len);

void icmpError(char buf[1500], int interNum, struct interface *interfaces, int errorType, int errorCode);

/* Main program... duh */
int main(){
  int packet_socket;
  // store how many interfaces we actually have.
  int num_interfaces = 0;
  struct interface interfaces[6];

  // file descriptor set and set all to zero
  fd_set sockets;
  FD_ZERO(&sockets);

  // Load routing table in.
  struct routingTable myRoutingTable[5];
  int num_tablerows = loadTable(myRoutingTable);

  printf("Testing everything loaded correctly...\n");
  int test;
  for(test = 0; test < 4; test++) {
    printf("IP Address: %s Bits: %s IP Hop: %s Name: %s\n", myRoutingTable[test].ipAddress, myRoutingTable[test].ipBits, myRoutingTable[test].ipHopper, myRoutingTable[test].name);
  }

  // Get list of interface addresses.
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
  
  int k = 0;
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

        
        struct sockaddr_ll *pAddr = (struct sockaddr_ll *)tmp->ifa_addr;
        memcpy(&interfaces[num_interfaces].mac, pAddr->sll_addr, 6);


        interfaces[num_interfaces].sockNum = packet_socket;
        interfaces[num_interfaces].name = tmp->ifa_name;
        printf("Got interface socket: %d\n", interfaces[num_interfaces].sockNum);
        // add packet_socket to interfaces
        // put the socket in file descriptor.
        FD_SET(packet_socket, &sockets);
        num_interfaces++;
      }
    }

    // Get this IP if it is IPv4 
    if (tmp->ifa_addr->sa_family == AF_INET) {
      if (!strncmp(&(tmp->ifa_name[3]), "eth", 3)) {
        struct sockaddr_in *sockaddr = (struct sockaddr_in*)tmp->ifa_addr;
        unsigned char *ipaddr = (unsigned char *) &(sockaddr->sin_addr.s_addr);
        u_int32_t in;
        memcpy(&interfaces[k].ip, &(sockaddr->sin_addr.s_addr), 4);
        printf("Interface %s with IP %d.%d.%d.%d\n", tmp->ifa_name, interfaces[k].ip[0], interfaces[k].ip[1], interfaces[k].ip[2], interfaces[k].ip[3]);
        k++;
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

        // Get the socket number so I have the proper interface information.
        for (k = 0; k < 6; k++) {
          if (interfaces[k].sockNum == i) break;
        }

        //start processing all others
        printf("Got a %d byte packet\n", n);

        // Store data in the structs.
        eh_incoming = (struct ethheader*) buf;
        ah_incoming = (struct arpheader*) (buf + sizeof(struct ethheader));
        ih_incoming = (struct ipheader*) (buf + sizeof(struct ethheader));

        // Find out what type this is!
        eh_incoming->eth_type = ntohs(eh_incoming->eth_type);
        printf("Type: %x\n", eh_incoming->eth_type);

        // Is this an ARP?
        if (eh_incoming->eth_type == ETHERTYPE_ARP) {
          printf("I think its ARP!\n");

          // Is this an ARP reply?
          if (ntohs(ah_incoming->opcode) == 2) {
            printf("I think this is an ARP reply.\n");
          } 

          // Is this an ARP request?
          else if (ntohs(ah_incoming->opcode) == 1) {
            printf("I think this is an ARP request.\n");
            printf("Destination IP: %d.%d.%d.%d\n", ah_incoming->target_ip[0], ah_incoming->target_ip[1], ah_incoming->target_ip[2], ah_incoming->target_ip[3]);
            printf("My IP for eth%d: %d.%d.%d.%d\n", k, interfaces[k].ip[0], interfaces[k].ip[1], interfaces[k].ip[2], interfaces[k].ip[3]);

            // am I the destination?
            if (memcmp(ah_incoming->target_ip, interfaces[k].ip, 4) == 0) {
              printf("I think this ARP request is for me! Gosh gee willy. (~u_u~)\n");
              
              // send a reply!
              printf("Building the ARP header right now...\n");

              // Copy data into an ARP struct.
              ah_outgoing = (struct arpheader*) (bufsend + sizeof(struct ethheader));
              ah_outgoing->hardware = htons(1);
              ah_outgoing->protocol = htons(ETH_P_IP);
              ah_outgoing->hardware_length = 6;
              ah_outgoing->protocol_length = 4;
              ah_outgoing->opcode = (unsigned short) htons(2); // reply code
              memcpy(ah_outgoing->sender_addr, interfaces[k].mac, 6);
              memcpy(ah_outgoing->sender_ip, interfaces[k].ip, 4);
              memcpy(ah_outgoing->target_addr, ah_incoming->sender_addr, 6);
              memcpy(ah_outgoing->target_ip, ah_incoming->sender_ip, 4);

              printf("Building the ethernet header right now...\n");

              // Copy data into an Ethernet Struct.
              eh_outgoing = (struct ethheader*) bufsend;
              memcpy(eh_outgoing->eth_dest, eh_incoming->eth_src, 6);
              memcpy(eh_outgoing->eth_src, interfaces[k].mac, 6);
              eh_outgoing->eth_type = htons(0x0806);

              // test.....
                printf("My MAC being sent out: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       eh_outgoing->eth_src[0],
                       eh_outgoing->eth_src[1],
                       eh_outgoing->eth_src[2],
                       eh_outgoing->eth_src[3],
                       eh_outgoing->eth_src[4],
                       eh_outgoing->eth_src[5]
                );

              // Send the reply.
              printf("Now sending the ARP reply...\n");
              send(i, bufsend, 42, 0);
            }
          }
        } 
        // Is this an ICMP?
        else if (eh_incoming->eth_type == ETHERTYPE_IP) {
          printf("I think its IP/ICMP!\n");
          icmph_incoming = (struct icmpheader*) (buf + sizeof(struct ethheader) + sizeof(struct ipheader));
          printf("TYPE OF IP ICMP: %d\n", icmph_incoming->type);

          printf("This is an ICMP ECHO request!\n");
          int matched = 1;

          // Copy the packet.
          memcpy(bufsend, buf, 1500);

          printf("Destination IP: %d.%d.%d.%d\n", ih_incoming->dest_ip[0], ih_incoming->dest_ip[1], ih_incoming->dest_ip[2], ih_incoming->dest_ip[3]);
          printf("My IP for eth%d: %d.%d.%d.%d\n", k, interfaces[k].ip[0], interfaces[k].ip[1], interfaces[k].ip[2], interfaces[k].ip[3]);

          int mine = 0;
          int j;
          // check if this packet is one of my interface IP addresses.
          for (j = 0; j < num_interfaces; j++) {
            if (memcmp(ih_incoming->dest_ip, &interfaces[j].ip, 4) == 0) {
              mine = 1;
              break;
            }
          }

          if (mine) {
            printf("I think this ICMP packet is for me! Gosh gee willy. (~u_u~)\n");

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
            memcpy(eh_outgoing->eth_src, interfaces[k].mac, 6);
            eh_outgoing->eth_type = htons(0x0800);

            // Sending an ICMP response packet.
            printf("Sending ICMP response...\n");
            send(i, bufsend, 98, 0);
          }
          // This isn't for me.. lets forward?
          else {
            printf("I think this ICMP packet is for someone else...\n");
            // Reduce the time to live.
            ih_incoming->ttl --;
            ih_incoming->checksum = 0;
            ih_incoming->checksum = checksum((char*) ih_incoming, sizeof(struct ipheader));
            //ih_incoming->ttl = ih_incoming->ttl - 1;
            if (ih_incoming->ttl == 1) {
               printf("The TTL is zero. Now sending an error...");
               // send ICMP TTL exceeded error
               ///// do error stuff here
               icmpError(buf, k, interfaces, 11, 0);
            }
            else {
              // turn the IP address into a string.
              struct sockaddr_in thissock;
              memcpy(&thissock.sin_addr.s_addr, ih_incoming->dest_ip, 4);
              char* addr = inet_ntoa(thissock.sin_addr);

              // Look up in forwarding table...
              for (j = 0; j < num_tablerows; j++) {
                // bits to bytes of stringified IP
                int len = (atoi(myRoutingTable[j].ipBits) / 8) * 2;
                if ((memcmp(addr, myRoutingTable[j].ipAddress, len)) == 0) {
                  printf("I think I found a match...\n");
                  printf("The routing table found a match: %s\n", myRoutingTable[j].ipAddress);
                  matched = 0;
                  break;
                }
              }

              // if we matched in the table... lets forward it!
              if (matched == 0) {
                printf("I am going to attempt forwarding this packet...\n");
                char buffer[98];
                memcpy(&buffer, &buf[0], 98);

                // get next interface for the hop
                int x;
                int socket = 0;
                for (x = 0; x < num_tablerows; x++) {
                  if (memcmp(interfaces[x].name, myRoutingTable[j].name, 7) == 0) {
                    socket = interfaces[x].sockNum;
                    break;
                  }
                }

                // is this outside my network?
                if (memcmp(myRoutingTable[j].ipHopper, "-", 1) != 0) {
                  printf("Outside my network...\n");
                  addr = myRoutingTable[j].ipHopper;
                }

                printf("Hopping to: %s\n", addr);

                unsigned char broadcast[6];
                int q;
                for (q = 0; q < 6; q++) { broadcast[q] = 0XFF; } // broadcast this stuff to everyone...

                // Send an ARP request...
                  
                printf("Building the ARP header right now...\n");
                // Copy data into an ARP struct.
                ah_outgoing = (struct arpheader*) (bufsend + sizeof(struct ethheader));
                ah_outgoing->hardware = htons(1);
                ah_outgoing->protocol = htons(2048);
                ah_outgoing->hardware_length = 6;
                ah_outgoing->protocol_length = 4;
                ah_outgoing->opcode = (unsigned short) htons(1); // request code
                memcpy(ah_outgoing->sender_addr, interfaces[k].mac, 6);
                memcpy(ah_outgoing->sender_ip, interfaces[k].ip, 4);
                memcpy(ah_outgoing->target_addr, &broadcast, 6);

                printf("Building the ethernet header right now...\n");
                /* Construct eth header */
                eh_outgoing = (struct ethheader*) bufsend;
                memcpy(eh_outgoing->eth_dest, &broadcast, 6);
                memcpy(eh_outgoing->eth_src, interfaces[socket].mac, 6);
                eh_outgoing->eth_type = htons(0x0806); // ARP

                struct sockaddr_in *temp = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));

                unsigned char dstip[4];
                inet_aton(addr, &temp->sin_addr); // next hop address into temp
                memcpy(&dstip, &temp->sin_addr, 4);

                printf("ARP Request DST IP address: %d.%d.%d.%d\n",
                       dstip[0],
                       dstip[1],
                       dstip[2],
                       dstip[3]
                );

                memcpy(ah_outgoing->target_ip, &dstip, 4);

                // Send the reply.
                printf("Now sending the ARP reply...\n");
                send(socket, bufsend, 42, 0);

                // Wait for a response...
                int reply = 1;
                struct sockaddr_ll recvaddr;
                int recvaddrlen = sizeof(struct sockaddr_ll);
                printf("Now waiting for a response...\n");

                char tempBuf[1500]; 
                char arpBuf[42];
                while(reply) {
                  int n = recvfrom(socket, tempBuf, 1500, 0, (struct sockaddr*) &recvaddr, &recvaddrlen);
                  if (recvaddr.sll_pkttype == PACKET_OUTGOING) continue;
                  reply = 0;
                  printf("Got a response!\n");
                }

                memcpy(arpBuf, tempBuf, 42);

                struct ethheader* eh_forward = (struct ethheader*) arpBuf;
                memcpy(eh_forward->eth_dest, eh_forward->eth_src, 6);
                memcpy(eh_forward->eth_src, interfaces[x].mac, 6);
                eh_forward->eth_type = htons(0x0800);

                // print eth destination received from ARP reply
                printf("-DST MAC from ARP reply: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       eh_forward->eth_dest[0],
                       eh_forward->eth_dest[1],
                       eh_forward->eth_dest[2],
                       eh_forward->eth_dest[3],
                       eh_forward->eth_dest[4],
                       eh_forward->eth_dest[5]
                );

                memcpy(&buffer[0], eh_forward, 14);

                // Sending an ICMP response packet.
                printf("Sending ICMP response...\n");
                send(socket, buffer, sizeof(buffer), 0);

                free(temp);
              }
            }
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
int loadTable(struct routingTable *arrRoutingTable) {
  //struct routingTable myRoutingTable[6];
  FILE* fp;
  char fileName[30];
  printf("Enter the file name of a forwarding table: \n");
  fgets(fileName, 30, stdin);
  fileName[strlen(fileName) - 1] = '\0';
  fp = fopen(fileName, "r"); // open read only.
  if (fp == NULL) {
    perror("Error opening the file. Now shutting down...\n");
    exit(1);
  }

  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  char string[50];

  int i = 0;
  while ((read = getline(&line, &len, fp)) != -1) {
    //printf("%s", line);
    strcpy(string, line);
    string[read]  = '\0';
    strcpy(arrRoutingTable[i].ipAddress, strtok(string, "/"));
    strcpy(arrRoutingTable[i].ipBits, strtok(NULL, " "));
    strcpy(arrRoutingTable[i].ipHopper, strtok(NULL, " "));
    strcpy(arrRoutingTable[i].name, strtok(NULL, "\n"));

    printf("IP Address: %s Bits: %s IP Hop: %s Name: %s\n", arrRoutingTable[i].ipAddress, arrRoutingTable[i].ipBits, arrRoutingTable[i].ipHopper, arrRoutingTable[i].name);
    i++;
  }
  free(line);
  fclose(fp);

  return i;
}

void icmpError(char buf[1500], int interNum, struct interface *interfaces, int errorType, int errorCode) {
  // initialize all structures we need...
  char ipPlusEight[sizeof(struct ipheader) + 8];
  memcpy(ipPlusEight, &buf[sizeof(struct ethheader)], sizeof(struct ipheader) + 8);
  struct ethheader *eh_outgoing = (struct ethheader*) &buf[0];
  struct ipheader *ih_outgoing = (struct ipheader*) &buf[sizeof(struct ethheader)];
  struct icmperror *icmph_outgoing = (struct icmperror *) &buf[sizeof(struct ethheader) + sizeof(struct ipheader)];
  uint8_t *data = &buf[sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct icmperror)];
  
  printf("Building ethernet header.\n");
  memcpy(eh_outgoing->eth_dest, eh_outgoing->eth_src, 6);
  memcpy(eh_outgoing->eth_src, interfaces[interNum].mac, 6);
  eh_outgoing->eth_type = htons(0x0800); //IP

  printf("Building IP header.\n");
  ih_outgoing->ttl = 64; // ?
  //ih_outgoing->protocol = 1; // ?
  //ih_outgoing->id = ih_outgoing->id + 1; // ?
  //ih_outgoing->len = htons(((2 * sizeof(struct ipheader)) + sizeof(struct icmperror) + 8));
  memcpy(ih_outgoing->dest_ip, ih_outgoing->src_ip, 4);
  memcpy(ih_outgoing->src_ip, interfaces[interNum].ip, 4);
  // check sum?
  ih_outgoing->checksum = 0;
  ih_outgoing->checksum = checksum((char*) ih_outgoing, sizeof(struct ipheader));

  printf("Checking error types...\n");
  if (errorType == 11 && errorCode == 0) { // ttl error?
    printf("I think it is time exceeded!\n");
    icmph_outgoing->type = errorType;
    icmph_outgoing->code = errorCode;
    icmph_outgoing->un.ttl.unused = 0;
  }
  else if (errorType == 3 && errorCode == 0) { // network unreachable?
    // put in the guts here
  }
  else if (errorType == 3 && errorCode == 1) { // host unreachable?
    // put in the guts here
  }

  memcpy(data, ipPlusEight, sizeof(struct ipheader) + 8);

  icmph_outgoing->checksum = 0;
  icmph_outgoing->checksum = checksum((char*) icmph_outgoing, sizeof(struct ipheader) + sizeof(struct icmperror) + 8);

  send(interfaces[interNum].sockNum, buf, sizeof(struct ethheader) + (2 * sizeof(struct ipheader)) + sizeof(struct icmperror) + 8, 0);

}
