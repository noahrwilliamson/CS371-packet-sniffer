/*
 * sniffer.c
 *
 * Last edit: 03/21/2018
 * Authors: Noah Williamson, Robert Williams
 * Course: CS371
 * Project 1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h> // libpcap library
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>

/* CONSTANTS */
#define MAXSIZE 128   // max size for buffers

/* FUNCTION PROTOTYPES */
void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_packet(const u_char *, int);
void print_udp_packet(const u_char *, int);
void print_icmp_packet(const u_char *, int);

/* GLOBALS */
FILE *logfile;
struct sockaddr_in source, dest;
int tcp_count = 0, udp_count = 0, icmp_count = 0, igmp_count = 0;
int other_count = 0, total_packet_count = 0; 

/*
 *
 *
 */
int main(int argc, char** argv) {
  pcap_if_t *device;
  pcap_t *handle;
  
  char *device_name;
  
  return 0;
}

/*
 *
 *
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                                  const u_char *buffer) {
  

}
