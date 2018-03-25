/*
 * sniffer.c
 *
 * Last edit: 03/25/2018
 * Author: Noah Williamson
 * Course: CS371
 * Project 1
 *
 * this sniffs ip packets over macos wifi device.
 * this program has only been tested on macos, it
 * may work on linux by modifying the device name
 * to suit your purposes. other os are presumably
 * unsupported. (note: after compilation, the 
 * executable must be ran with root permissions)
 */

#include <pcap.h> // libpcap
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define MAXSIZE 100

/* FUNCTION PROTOTYPES */
void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_info(const u_char *, int);
//void print_udp_packet(const u_char *, int);
//void print_icmp_packet(const u_char *, int);
//void print_ethernet_header(const u_char *, int);
//void print_ip_header(const u_char *, int);
void print_data(const u_char *, int); 

/* GLOBALS */
FILE *logfile;
struct sockaddr_in source, dest;
int tcp_count = 0, udp_count = 0, other_count = 0, total_count = 0;
int total_packet_size = 0, total_tcp_size = 0, total_udp_size = 0;

/*
 * main function
 *
 */
int main(int argc, char** argv) {
  pcap_if_t *device;
  pcap_t *handle;
  struct bpf_program fp;
  bpf_u_int32 maskp;
  bpf_u_int32 netp;
  char errbuff[MAXSIZE];
  char device_name[] = "en0"; // wifi device name on Mac
  
  pcap_lookupnet(device_name, &netp, &maskp, errbuff);

  printf("Sniffing on device: %s\n", device_name); // print device
  
  // open device
  handle = pcap_open_live(device_name, 65536, 1, 300000, errbuff);
  if(handle == NULL){ // check for error in opening device for sniffing
    fprintf(stderr, "Could not open device %s: %s\n", device_name, errbuff);
    exit(1);
  }

  logfile = fopen("log.txt", "w"); // start logs
  if(logfile == NULL){  // check for errror in file creation/opening
    printf("Error in creating file.");
  }

  // compile and set filters
  if(pcap_compile(handle, &fp, "ip", 0, netp) == -1){
    fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
    return(2);
  }

  if(pcap_setfilter(handle, &fp) == -1){
    fprintf(stderr, "Couldn't use filter: %s\n", pcap_geterr(handle));
    return(2);
  }

  // start sniffing loop
  pcap_loop(handle, -1, got_packet, NULL);
  
  // clean up
  pcap_freecode(&fp);
  pcap_close(handle);

  return 0;
}

/*
 *
 *
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                                  const u_char *buffer) {
  int size = header->len; // packet size
  
  ++total_count;
  total_packet_size += size; 
  
  struct ethhdr *eth = (struct ethhdr*)buffer;
  struct ip *iph = (struct ip*)(buffer + sizeof(eth) );

  switch(iph->ip_p){
    case IPPROTO_TCP: // TCP
      ++tcp_count;
      total_tcp_size += size; // update total size of all tcp packets

      print_tcp_info(buffer, size); // source and destination port number
      break;
    
    case IPPROTO_UDP: // UDP
      ++udp_count;
      total_udp_size += size; // update total size of all udp packets
      print_data(buffer, size);
      break;
    
    default:  // some other protocol
      ++other_count;
      break;
  }

  printf("Protocol count:\nTCP: %d UDP: %d Others: %d\n", tcp_count, udp_count, other_count);
  printf("Total packets: %d\n", total_count);

}

/*
 *
 *
 
void print_ethernet_header(const u_char *Buffer, int Size){
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile, "\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], 
        eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
        eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], 
        eth->h_source[4], eth->h_source[5]);
    fprintf(logfile , "   |-Protocol            : %u \n",
        (unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size){
    print_ethernet_header(Buffer , Size);
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",
        (unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",
        (unsigned int)iph->ihl, ((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",
        (unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
        ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",
        ntohs(iph->id));
    fprintf(logfile , "   |-TTL      : %d\n", (unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n", (unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n", ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}
*/

void print_tcp_info(const u_char *buffer, int size){
    unsigned short iphdrlen;

    struct ethhdr *eth = (struct ethhdr*)buffer;
    struct ip *iph = (struct ip*)(buffer + sizeof(eth));
    iphdrlen = iph->ip_hl * 4;

    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(eth));

    //int header_size =  sizeof(eth) + iphdrlen + tcph->doff*4;

    fprintf(logfile,"\n***********************TCP Packet %d*************************\n\n", tcp_count);
    fprintf(logfile,"   |-Source Port      : %u\n", ntohs(tcph->th_sport));
    fprintf(logfile,"   |-Destination Port : %u\n", ntohs(tcph->th_dport));
    /*fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");

    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile , "Data Payload\n");
    PrintData(Buffer + header_size , Size - header_size );

    fprintf(logfile , "\n\n\n");
*/
    fclose(logfile);
}

/*
void print_udp_packet(const u_char *Buffer , int Size){
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    print_data(Buffer , iphdrlen);

    fprintf(logfile , "UDP Header\n");
    print_data(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "Data Payload\n");

    // move the pointer ahead and reduce the size of string
    print_data(Buffer + header_size , Size - header_size);

    fprintf(logfile , "\n\n\n");
}

void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer , Size);

    fprintf(logfile , "\n");

    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11){
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY){
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }

    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    fprintf(logfile , "\n");

    fprintf(logfile , "IP Header\n");
    print_data(Buffer, iphdrlen);

    fprintf(logfile , "UDP Header\n");
    print_data(Buffer + iphdrlen , sizeof icmph);

    fprintf(logfile , "Data Payload\n");

    // move the pointer ahead and reduce the size of string
    print_data(Buffer + header_size , (Size - header_size) );

    fprintf(logfile , "\n\n\n");
}
*/

/*
void print_data (const u_char * data , int Size){
    int i, j;
    
    for(i = 0; i < Size; ++i){
        if(i != 0 && i%16 == 0){ // check if one line of hex is complete
            fprintf(logfile, "         ");
            
            for(j=i-16 ; j<i ; ++j){
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile, "%c", (unsigned char)data[j]); //if its a number or alphabet

                else fprintf(logfile, "."); //otherwise print a dot
            }
            fprintf(logfile, "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile, " %02X", (unsigned int)data[i]);

        if( i==Size-1){  // print the last spaces
            for(j = 0; j < 15 - i%16; ++j){
              fprintf(logfile, "   "); //extra spaces
            }

            fprintf(logfile, "         ");

            for(j = i - i%16; j <= i ; ++j){
                if(data[j] >= 32 && data[j] <= 128){
                  fprintf(logfile, "%c", (unsigned char)data[j]);
                }
                else{
                  fprintf(logfile, ".");
                }
            }

            fprintf(logfile,  "\n" );
        }
    }
}
*/

void print_data(const u_char *packet, int size){
  printf("Got packet.\n");
  return;
}
