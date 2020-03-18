/*
 ** The Siphon Project: The Passive Network Mapping Tool
 ** Copyright (c) 2000 Subterrain Security Group
 **
 ** Siphon Homepage: http://www.subterrain.net/projects/siphon/
 ** 
 ** Author Contacts:
 **  bind	<bind@subterrain.net>
 **  aempirei	<aempirei@subterrain.net>
 **
 ** Improvements:
 **  maetrics	<maetrics@users.sourceforge.net>
*/

#include "siphon.h"

int oslookup(int, int, int);
int findttl(int);

void parse(u_char *user, struct pcap_pkthdr *h, u_char *sp) {
	static int nl=0;
	struct ip *iph=NULL;
	struct tcphdr *tcp=NULL;

	sp+=sizeof(struct ether_header);
	iph=(struct ip *)sp;
	sp+=sizeof(struct iphdr);
	tcp=(struct tcphdr *)sp;
	fprintf(output, "%s\t%d", inet_ntoa(iph->ip_src), ntohs(tcp->source));
	
	if(verbose) {
		oslookup(ntohs(tcp->window), iph->ip_ttl, iph->ip_off);
	} else {
		nl++;
		if(nl > 2) {
			nl=0;
		}
	}
	
	if(nl == 0) {
		fprintf(output, "\n");
	} else {
		fprintf(output, "\t");
	}

	fflush(output);
}

int oslookup(int window, int ttl, int df) {
	int frag=0;
	FILE *osprints;
	static char line[80], *oswin, *os, *osttl, *osdf, hexed[10];

	osprints = fopen("/etc/osprints.conf","r");

	if(!osprints) {
		perror("Unable to find osprints.conf\n");
		return -1;
	}

	if(htons(df) == 0x4000) {
		frag=1;
	}
	
	snprintf(hexed,10,"%04X",window);
	fgets(line,80,osprints);
  
	while(!feof(osprints)) {
		oswin = strtok(line,":");
		osttl = strtok(NULL,":");
		osdf = strtok(NULL,":");
		os = strtok(NULL,"\n");

		if((os != NULL) && (findttl(ttl) == atoi(osttl)) &&
				(frag == atoi(osdf)) &&
				(strstr(oswin, hexed) != NULL)) {
			fclose(osprints);
			fprintf(output, "\t%d\t%d\t%s", ttl, frag, os);
			fflush(output);
			return 1;
		}
		
		fgets(line,80,osprints);
	}
	
	fclose(osprints);
	fprintf(output, "\t%d\t%d\t%s", ttl, frag, hexed);
	return -1;
}

int findttl(int ttl) {
	if((ttl&0xC0) == 0xC0) {
		return 255;
	} else if((ttl&0xE0) == 0x60) {
			return 128;
	} else if((ttl&0xF0) == 0x30) {
		return 64;
	} else if((ttl&0xF8) == 0x18) {
		return 32;
	}
	
	return ttl;
}
