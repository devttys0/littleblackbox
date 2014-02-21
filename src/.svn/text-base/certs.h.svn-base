#include <openssl/x509.h>
#include <openssl/ssl.h>

#define DEFAULT_SSL_PORT	443
#define SSLV2			2
#define SSLV3			3

char *fingerprint_host(char *target);
char *fingerprint_pem_file(char *file);
X509 *open_pem_file(char *file);
char *sha1_fingerprint(X509 *cert);
int tcp_connect(char *host, int port);
char *remote_fingerprint(char *host, int port, int ssl_version);
