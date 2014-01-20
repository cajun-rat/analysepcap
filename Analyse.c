/*
Analyse a pcap dump file and report statistics
*/

#include <stdio.h>
#define HAVE_REMOTE
#include <pcap.h>
#include "bstrlib.h"
#include "Analyse.h"

int metrics_ensure_space(struct metrics* m, int requiredsize) {
	int newlen;
	struct metric *nb;
	if (requiredsize <= m->bufferlen) {
		return 0;
	}

	if (m->bufferlen == 0) {
		newlen = 4;
	} else {
		newlen = m->bufferlen;
	}
	while(newlen < requiredsize) {
		newlen *=2;
	}

	nb = (struct metric*) realloc(m->metrics, newlen * sizeof(struct metric));
	if (!nb) {
		return 1;
	}
	m->bufferlen = newlen;
	m->metrics = nb;
	return 0;
}

void usage(char *argv0) {
	printf("usage: %s metrics.spec trace.pcap\n"
		"Each line of metrics.spec contains a packet flow to measure\n"
		"It is of the format: Description | BPF filter. For example:\n"
		"Outgoing web traffic | (src host 10.71.131.116) and (tcp port 443)\n"
		"trace.pcap is a non pcapng format trace file from wireshark or tcpdump\n", argv0);
}

#define INNAME 1
#define INBFP 2

void readmetricsspec(struct metrics* metrics, FILE *infile) {
	int chr;
	int state;
	int line;
	bstring name, filter; 
	struct metric *metric;
	name = bfromcstr("");
	filter = bfromcstr("");
	state = INNAME;

	line = 1;
	while((chr = fgetc(infile)) != EOF) {
		switch(state) {
		case INNAME:
			switch (chr) {
			case '|':
				state = INBFP;
				break;
			case '\n':
				printf("error on line %d: expected: |\n", line);
				btrunc(name, 0);
				break;
			default:
				bconchar(name, chr);
				break;
			}
			break;
		case INBFP:
			switch(chr) {
			case '\n':
				/* printf("Got metric called '%s' with body '%s'\n", name->data, filter->data); */
				metrics_ensure_space(metrics, metrics->count+1);
				metric = &metrics->metrics[metrics->count];
				metrics->count++;
				metric->name = name;
				metric->filterprogram = filter;
				name = bfromcstr("");
				filter = bfromcstr("");
				state = INNAME;
				break;
			default:
				bconchar(filter, chr);
				break;
			}
		}
		if (chr == '\n') {
			line++;
		}

	}
	/* Null terminate */
	metrics_ensure_space(metrics, metrics->count+1);
	metric = &metrics->metrics[metrics->count];
	metric->name = NULL;
	metric->filterprogram = NULL;
}

int openpcapfile(pcap_t **pcapout, char *filename) {
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];

	/* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            filename,        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (pcap = pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
		fprintf(stderr,"\nUnable to open %s: %s\n", filename, errbuf);
        return -1;
    }

	*pcapout = pcap;
	return 0;
}


int compileallfilters(pcap_t *pcap, struct metric *metrics) {
	struct metric *m;

	for(m=metrics; m->name; m++) {
		if (pcap_compile(pcap, &m->compiledfilter, (char*) m->filterprogram->data, 0, 0)) {
			fprintf(stderr, "Error compiling %s filter %s ", m->name->data, m->filterprogram->data);
			pcap_perror(pcap, "");
			return 1;
		}
		m->bytes = 0;
	}
	return 0;
}

void processpacket(struct metric *metrics, struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct metric *m;

	for(m=metrics; m->name; m++) {
		if (pcap_offline_filter(&m->compiledfilter, header, pkt_data)) {
			m->bytes += header->caplen;
		}
	}
}

void displayresults(struct metric *metrics, double capturetime) {
	struct metric *m;

	for(m=metrics; m->name; m++) {
		printf("%s  %.2f MB  %.2f GB/month\n", m->name->data, m->bytes/1e6, m->bytes/1e9/capturetime*3600*24*30);
	}
}

int main(int argc, char* argv[]) {
	struct metrics metrics;
	FILE *metricssourcefile;
	pcap_t *pcap;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int packetnum;
	struct timeval firstpacket;
	struct timeval lastpacket;
	double capturetime;
	int res;

    if(argc != 3)
    {
        usage(argv[0]);
        return 1;
    }

	memset(&metrics, 0, sizeof(struct metrics));
	#pragma warning(push)
    #pragma warning(disable: 4996)
	metricssourcefile = fopen(argv[1], "r");
	#pragma warning(pop)
	if (metricssourcefile == NULL) {
		printf("Couldn't open %s\n", argv[1]);
		return 1;
	}

	readmetricsspec(&metrics, metricssourcefile);

	fclose(metricssourcefile);

    if (openpcapfile(&pcap, argv[2])) {
		return 1;
	}
    
	/* Compile pcap filters */
	if (compileallfilters(pcap, metrics.metrics)) {
		return -1;
	}
	
    /* Retrieve the packets from the file */
	packetnum = 0;
    while((res = pcap_next_ex(pcap, &header, &pkt_data)) >= 0)
    {
		if (packetnum++ == 0) {
			memcpy(&firstpacket, &header->ts, sizeof(struct timeval));
		}
		processpacket(metrics.metrics, header, pkt_data);
    }
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(pcap));
	}
	if (packetnum > 0) {
		memcpy(&lastpacket, &header->ts, sizeof(struct timeval));
		capturetime = (lastpacket.tv_sec - firstpacket.tv_sec) + 1e-6*(lastpacket.tv_usec - firstpacket.tv_usec);
		if (capturetime == 0.0) {
			capturetime = 1.0;
		}
		printf("Results of %.1f second capture\n", capturetime);

		displayresults(metrics.metrics, capturetime);
	} else {
		printf("No packets read");
	}
    return 0;
}