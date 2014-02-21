#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <openssl/sha.h>
#include "network.h"
#include "common.h"

/* Initializes pcap */
pcap_t *initialize_network(char *iface, char *filter, int type)
{
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	pcap_t *handle = NULL;
	struct bpf_program fp = { 0 };
	bpf_u_int32 mask = 0, net = 0;

	if (type == PFILE)
	{
		handle = pcap_open_offline(iface, errbuf);
	} else {
		if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) 
		{
			fprintf(stderr, "ERROR: Failed to get netmask for device %s\n", iface);
			return NULL;
		}

		handle = pcap_open_live(iface, BUFSIZ, PROMISC, PCAP_READ_TIMEOUT, errbuf);
		if (handle == NULL) 
		{
			fprintf(stderr, "ERROR: Failed to open device %s: %s\n", iface, errbuf);
			return NULL;
		}
	}

	if (pcap_compile(handle, &fp, filter, 0, net) == -1) 
	{
		fprintf(stderr, "ERROR: Failed to parse filter %s: %s\n", filter, pcap_geterr(handle));
		return NULL;
	}
	
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "ERROR: Failed to install filter %s: %s\n", filter, pcap_geterr(handle));
		return NULL;
	}

	return handle;
}

/* Processes each incoming packet looking for SSL certificate handshakes */
char *process_packet(const u_char *packet, struct pcap_pkthdr *header)
{
	struct sniff_ethernet *ethernet = NULL;
	struct sniff_ip *ip = NULL;
	struct sniff_tcp *tcp = NULL;
	u_char *tls_record = NULL;
	u_char *tls_handshake = NULL;
	short tls_record_size = 0;
	int size_ip = 0, size_tcp = 0, size_eth = 0, offset = 0, payload_size = 0, cert_size = 0;
	const u_char *payload = NULL;
	char *fingerprint = NULL;
	unsigned char md[SHA_DIGEST_LENGTH] = { 0 };

	if(packet == NULL)
	{
		goto end;
	}

	ethernet = (struct sniff_ethernet*)(packet);
	size_eth = sizeof(struct sniff_ethernet);

	ip = (struct sniff_ip*)(packet + size_eth);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		fprintf(stderr, "ERROR: Invalid IP header length: %u bytes\n", size_ip);
		goto end;
	}

	tcp = (struct sniff_tcp*)(packet + size_eth + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		fprintf(stderr, "ERROR: Invalid TCP header length: %u bytes\n", size_tcp);
		goto end;
	}

	/* Get a pointer to the payload and calculate the payload size based on IP and TCP header values */
	payload = (u_char *)(packet + size_eth + size_ip + size_tcp);
	payload_size = (int) ntohs(ip->ip_len) - size_tcp;

	/* Certificate exchanges have at least three TLS record headers */
	if(payload_size < (TLS_RECORD_HEADER_SIZE*3))
	{
		goto end;
	}

	/* Loop until we find a certificate exchange or run out of payload data */
	while((offset+TLS_RECORD_HEADER_SIZE) < payload_size)
	{
		/* Get a pointer to the next TLS record */
		tls_record = (u_char *) (payload + offset);

		/* Check to see if this TLS record is a handshake */
		if(tls_record[TLS_TYPE] == TLS_CONTENT_TYPE_HANDSHAKE)
		{
			/* Calculate TLS record size. This is a two byte value. */
			tls_record_size = (short) (tls_record[TLS_LENGTH] << 8) + 
							tls_record[TLS_LENGTH+1];

			/* Get a pointer to the actual handshake data */
			tls_handshake = (u_char *) (tls_record + TLS_RECORD_HEADER_SIZE);

			/* We are only concerned with certificate handshakes */
			if(tls_handshake[TLS_TYPE] == TLS_HANDSHAKE_TYPE_CERTIFICATE)
			{
				/* Calculate certificate size. This is a three byte value. */
				cert_size = (tls_handshake[CERT_LEN_OFFSET] << 16) + 
						(tls_handshake[CERT_LEN_OFFSET+1] << 8) +
						tls_handshake[CERT_LEN_OFFSET+2];

				/* Calculate the SHA1 fingerprint of the certificate */	
				SHA1(tls_handshake+CERT_OFFSET, cert_size, (unsigned char *) &md);

				/* Convert fingerprint bytes into colon-delimited hex string */
				fingerprint = format_sha1_hash((unsigned char *) &md);
				break;
			} else {
				/* If this handshake was not a certificate, move on to the next TLS record */
				offset += tls_record_size + TLS_RECORD_HEADER_SIZE;
			}
		} else {
			break;
		}
	}

end:
	return fingerprint;
}

/* Loops pcap_next until there are no more packets */
char *sniff(char *iface, char *filter, int type)
{
	struct pcap_pkthdr header;
	const u_char *packet = NULL;
	pcap_t *handle = NULL;
	char *fingerprint = NULL;

	handle = initialize_network(iface, filter, type);
	
	if(handle != NULL)
	{
		while(fingerprint == NULL)
		{
			packet = pcap_next(handle, &header);
			if(packet != NULL)
			{
				fingerprint = process_packet(packet, &header);
			} else {
				break;
			}
		}

		pcap_close(handle);
	}

	return fingerprint;
}

