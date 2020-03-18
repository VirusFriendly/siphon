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

void usage(char *);
void title(void);

int main (int argc, char **argv) {
	char *device=NULL;
	int opt;
	extern char *optarg;
	extern int opterr;
	struct utsname hinfo;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapd=NULL;
	pcap_handler callback=(pcap_handler)parse;
	struct bpf_program fp;
	char *str=NULL;
	int x=0;
	
	pid_t pid=0;
	int i=0;
	append = verbose = back =  0;
	title();
	output=stdout;
	opterr = 0;
	
	while ((opt=getopt(argc, argv, "Vvr:b:i:")) != EOF) {
		switch (opt) {
			case 'v': 
				verbose = 1;
				break;
			case 'b':
				if((pid=fork()) < 0) {
					return(-1);
				} else if(pid != 0) {
					exit(0);
				}
			
				setsid();
				
				for(i=0; i < 4; i++) {
					close(i);
				}
			
			 	output=fopen(optarg,"w+");
		 		append=1;
		 		back=1;
		 		break;
			case 'i':
				pcapd=pcap_open_live(optarg, 128, 1, 0, errbuf);
				break;
			case 'r':
				pcapd=pcap_open_offline(optarg, errbuf);
				break;
			case 'V':
				puts(VERSION); exit(0);
				break;
			case '?':
			default:
				usage (argv[0]);
				break;
		}
	}

	if(verbose^append) {
		uname (&hinfo);
		printf ("\nRunning on: '%s' running %s %s on a(n) %s\n\n",
		hinfo.nodename, hinfo.sysname, hinfo.release,
		hinfo.machine);
	}

	if(pcapd == NULL) {
		device = pcap_lookupdev(errbuf);

		if(device == NULL) { 
			printf("Error: Unable to lookup device.\n");
			exit(-1);
		} else if(verbose^append) {
			printf("Using Device: %s\n", device);
		}
		
		pcapd=pcap_open_live(device, 128, 1, 0, errbuf);
		
		if(pcapd == NULL) {
			perror("pcap_open");
			exit(-1);
		}
	}

	if(append == 0) {
		fprintf(output, "\nHost\t\tPort");
		if(verbose) {
			fprintf(output, "\tTTL\tDF\tOperating System");
		} else {
			fprintf(output, "\tHost\t\tPort\tHost\t\tPort");
		}
		fprintf(output, "\n\n");
		fflush(output);
	}
	
	str="tcp[13]&0x12=0x12";
	x=pcap_compile(pcapd, &fp, str, 1, 0xffff00);
	
	if(x == -1) {
		fprintf(stderr, "pcap_compile error\n %s\n", pcap_geterr(pcapd));
		exit(-1);
	}
	
	x=pcap_setfilter(pcapd, &fp);

	if(x == -1) {
		fprintf(stderr, "pcap_setfilter error\n");
		exit(-1);
	}

	pcap_loop(pcapd, -1, callback, errbuf);
	pcap_freecode(&fp);
	pcap_close(pcapd);
	exit(0);
}

void usage(char *arg) {
   printf ("Usage:\n"
	   "  %s [options]\n\n"
	   "Options:\n"
	   "  [ -v Verbose mode ]\n"
	   "  [ -b <logfile> Run in background ]\n" 
           "  [ -i <device> ]\n"
	   "  [ -r <input file> ]\n"
           "  [ -V Show version and exit ]\n\n",arg);
   exit (0);
}

void title(void) {
  printf("\n\t [ The Siphon Project: The Passive Network Mapping Tool ]\n"
	 "\t     [ Copyright (c) 2000 Subterrain Security Group ]\n\n");
  printf("\n\t [ Improved by Deathcubek and Maetrics ]\n"
	 "\t     [ Copyright (c) 2001 GomiSquad ]\n\n"); 
}
