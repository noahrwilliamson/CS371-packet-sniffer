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
#include <signal.h>
#include <unistd.h>
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
void alarm_handler(int);  // used to break pcap loop after 5 minutes

/* GLOBALS */
pcap_t *handle;
int tcp_count = 0, udp_count = 0, other_count = 0, total_count = 0;
int total_packet_size = 0, total_tcp_size = 0, total_udp_size = 0;


/*
 * main function
 *
 */
int main(int argc, char** argv) {
  pcap_if_t *device;
  struct bpf_program fp;
  bpf_u_int32 maskp;
  bpf_u_int32 netp;
  char errbuff[MAXSIZE];
  char device_name[] = "en0"; // wifi device name on Mac
  
  pcap_lookupnet(device_name, &netp, &maskp, errbuff);

  printf("Sniffing on device: %s\n", device_name); // print device
  
  // open device
  handle = pcap_open_live(device_name, 65536, 1, 0, errbuff);
  if(handle == NULL){ // check for error in opening device for sniffing
    fprintf(stderr, "Could not open device %s: %s\n", device_name, errbuff);
    exit(1);
  }

  // compile and set filters
  if(pcap_compile(handle, &fp, "ip", 0, netp) == -1){
    fprintf(stderr, "Could not parse filter: %s\n", pcap_geterr(handle));
    exit(2);
  }

  if(pcap_setfilter(handle, &fp) == -1){
    fprintf(stderr, "Could not use filter: %s\n", pcap_geterr(handle));
    exit(2);
  }

  // set alarm
  alarm(300);
  signal(SIGALRM, alarm_handler);

  // start sniffing loop
  pcap_loop(handle, -1, got_packet, NULL);
  
  // clean up
  pcap_freecode(&fp);
  pcap_close(handle);

  // output final results
  printf("\n###############################################\n");
  printf("\nCount:\tTCP: %d UDP: %d Others: %d\n", tcp_count, udp_count, other_count);
  printf("Total packets: %d\n", total_count);
  printf("Total TCP packets size: %d\n", total_tcp_size);
  printf("Total UDP packets size: %d\n", total_udp_size);
  printf("Total all packets size: %d\n", total_packet_size);

  return 0;
}

/*
 * callback function for the sniffing loop,
 * finds protocol for each packet, and then
 * extracts/keeps track of the data we desire
 * PARAMS: arguments, packet header, packet info buffer
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
      
      printf("Source IP:\t%s\n", inet_ntoa(iph->ip_src));
      printf("\nCount:\tTCP: %d UDP: %d Others: %d\n", tcp_count, udp_count, other_count);
      printf("Total packets: %d\n", total_count);
      break;
    
    case IPPROTO_UDP: // UDP
      ++udp_count;
      total_udp_size += size; // update total size of all udp packets

      printf("\n\n***********************UDP Packet %d*************************\n", udp_count);
      printf("Source IP:\t%s\n", inet_ntoa(iph->ip_src));
      printf("\nCount:\tTCP: %d UDP: %d Others: %d\n", tcp_count, udp_count, other_count);
      printf("Total packets: %d\n", total_count);
      break;
    
    default:  // some other protocol
      ++other_count;
      break;
  }

}


/*
 * prints port number for TCP packets
 * PARAMS: byte buffer, size
 */
void print_tcp_info(const u_char *buffer, int size){
  unsigned short iphdrlen;

  struct ethhdr *eth = (struct ethhdr*)buffer;
  struct ip *iph = (struct ip*)(buffer + sizeof(eth));
  iphdrlen = iph->ip_hl * 4;

  struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(eth));

  printf("\n\n***********************TCP Packet %d*************************\n", tcp_count);
  printf("Source Port:\t%u\n", ntohs(tcph->th_sport));
}

/* 
 * handles breaking pcap loop after specified
 * number of seconds
 */
void alarm_handler(int sig){
  pcap_breakloop(handle);
}

