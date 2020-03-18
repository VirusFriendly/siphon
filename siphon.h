#ifndef SIPHON_H
#define SIPHON_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/signal.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>


#define VERSION "Version 1 beta\n"

#define bzero(a,b) memset(a,0,b)

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

void parse(u_char *, struct pcap_pkthdr *, u_char *);

int verbose, back, append;
FILE *output;
#endif
