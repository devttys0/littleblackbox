#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "littleblackbox.h"
#include "network.h"
#include "certs.h"
#include "dbupdate.h"
#include "config.h"

#define MIN_ARGS 2
void usage(char *prog);

int main(int argc, char *argv[])
{
	int retval = EXIT_FAILURE;
	int long_opt_index = 0, display_info = 0, display_public_cert = 0, update_db = 0, quiet = 0;
	char c = 0;
	char *pcap_filter = NULL, *pcap_file = NULL, *pcap_interface = NULL, *update_db_outfile = NULL;
	struct keymaster certinfo = { 0 };
	struct option long_options[] = {       
        	{ "fingerprint", required_argument, NULL, 'f' },     
        	{ "pem", required_argument, NULL, 'p'  },    
        	{ "host", required_argument, NULL, 'r' }, 
		{ "pcap", required_argument, NULL, 'c' },
		{ "interface", required_argument, NULL, 'i' },
		{ "search", required_argument, NULL, 's' },
		{ "filter", required_argument, NULL, 'l' },
        	{ "keypair", no_argument, NULL, 'k' },
        	{ "info", no_argument, NULL, 'v' },
        	{ "quiet", no_argument, NULL, 'q' },
		{ "update", optional_argument, NULL, 'u' },
        	{ "help", no_argument, NULL, 'h' },
        	{ 0,    0,    0,    0   }      
    	};
	char *short_options = "f:p:r:c:i:s:l:u::kvqh";

	if(argc < MIN_ARGS)
	{
		usage(argv[0]);
		goto end;
	}

	while((c = getopt_long(argc,argv,short_options, long_options, &long_opt_index)) != -1)
	{
		switch(c)
		{
			case 'c':
				if(optarg) pcap_file = strdup(optarg);
				break;
			case 'f':
				if(optarg) certinfo.fingerprint = strdup(optarg);
				break;
			case 'p':
				if(optarg) certinfo.fingerprint = fingerprint_pem_file(optarg);
				break;
			case 'r':
				if(optarg) certinfo.fingerprint = fingerprint_host(optarg);
				break;
			case 'i':
				if(optarg) pcap_interface = strdup(optarg);
				break;
			case 'l':
				if(optarg) pcap_filter = strdup(optarg);
				break;
			case 's':
				if(optarg) print_search_results(optarg);
				break;
			case 'u':
				update_db = 1;
				if(optarg) update_db_outfile = strdup(optarg);
				else update_db_outfile = strdup(DB_NAME);
				break;
			case 'k':
                                display_public_cert = 1;
                                break;
			case 'v':
                                display_info = 1;
                                break;
			case 'q':
				quiet = 1;
				break;
			default:
				usage(argv[0]);
				goto end;
		}
	}

	/* Update the certificate database */
	if(update_db)
	{
		fprintf(stderr, "Updating %s from %s...", update_db_outfile, DB_UPDATE_URL);
		if(!update_database(DB_UPDATE_URL, update_db_outfile))
		{
			fprintf(stderr, "update failed!\n");
			goto end;
		} else {
			fprintf(stderr, "done.\n");
			goto success;
		}
	}
			
	/* If no filter was specified, use the default */
	if(pcap_filter == NULL)
	{
		pcap_filter = strdup(DEFAULT_FILTER);
	}

	/* Do raw traffic capture if specified */
	if(pcap_file != NULL)
	{
		certinfo.fingerprint = sniff(pcap_file, pcap_filter, PFILE);
	} else if(pcap_interface != NULL) {
		certinfo.fingerprint = sniff(pcap_interface, pcap_filter, IFACE);
	}

	/* Make sure we have a fingerprint */
	if(!certinfo.fingerprint)
	{
		fprintf(stderr, "No suitable certificate fingerprint provided!\n");
		goto end;
	}

	/* Try to lookup the private key that corresponds to this certificate */
	if(!lookup_key(&certinfo) || certinfo.key == NULL)
	{
		fprintf(stderr, "ERROR: Failed to locate a matching private certificate for fingerprint: %s\n", certinfo.fingerprint); 
		goto end;
	}

	/* Display private key */
	if(!quiet)
	{
		printf("%s\n", certinfo.key);
	}

	/* Display public key */
	if(display_public_cert)
	{
		printf("%s\n", certinfo.certificate);
	}

	/* Show all certificate info for this cert */
	if(display_info)
	{
		print_all_cert_info(&certinfo);
	}

success:
	retval = EXIT_SUCCESS;
end:
	free_key(&certinfo);
	if(update_db_outfile) free(update_db_outfile);
	if(pcap_file) free(pcap_file);
	if(pcap_interface) free(pcap_interface);
	if(pcap_filter) free(pcap_filter);
	return retval;
}

void usage(char *prog)
{
        fprintf(stderr, "\n");
	fprintf(stderr, "%s\n\n", PACKAGE_STRING);
        fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
        fprintf(stderr, "\n"); 
        fprintf(stderr, "\t-r, --host=<host:port>               Obtain the public key of a remote host\n");
        fprintf(stderr, "\t-p, --pem=<file>                     Read public key from PEM file\n");
        fprintf(stderr, "\t-f, --fingerprint=<sha1>             Public key's SHA1 fingerprint\n");
        fprintf(stderr, "\t-c, --pcap=<file>                    Look for public key exchanges in pcap file\n");
        fprintf(stderr, "\t-i, --interface=<iface>              Listen on iface for public key exchanges\n");
        fprintf(stderr, "\t-k, --filter=<filter>                Specify the pcap filter to use [%s]\n", DEFAULT_FILTER);
	fprintf(stderr, "\t-s, --search=<table.column%squery>    Search the database for a given search term\n", QUERY_DELIMITER);
	fprintf(stderr, "\t-u, --update=[file]                  Download the latest certificate database to file [%s]\n", DB_NAME);
        fprintf(stderr, "\t-k, --keypair                        Display both the private key and the public key\n");
        fprintf(stderr, "\t-v, --info                           Display all database info related to the public/private keypair\n");
	fprintf(stderr, "\t-q, --quiet                          Do not display the private key\n");
        fprintf(stderr, "\t-h, --help                           Show help\n");
        fprintf(stderr, "\n");
        return;
}
