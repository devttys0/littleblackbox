#ifndef __CERTS_H__
#define __CERTS_H__

#include <openssl/x509.h>
#include <openssl/ssl.h>

#define DEFAULT_SSL_PORT    443

char *fingerprint_host(char *target);
char *fingerprint_pem_file(char *file);
X509 *open_pem_file(char *file);
char *sha1_fingerprint(X509 *cert);
int tcp_connect(char *host, int port);
char *remote_fingerprint(char *host, int port);

#endif
