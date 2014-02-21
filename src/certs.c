#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "certs.h"
#include "common.h"

/* 
 * Given a host and port number, connect to the host, retrieve the host's public certificate,
 * and return a SHA1 fingerprint of that certificate.
 */
char *fingerprint_host(char *target)
{
    int port = DEFAULT_SSL_PORT;
    char *host = NULL, *fingerprint = NULL, *delim_ptr = NULL;

    if(target)
    {
        /* Make a copy of the target string so we don't mangle the original */
        host = strdup(target);

        /* The target string can be in the following formats:
         *
         *     o 192.168.1.1
         *     o 192.168.1.1:443
         *
         * IPv6 is not supported.
         * If a port is defined, we need to parse it out. Else, just use 443.
         */
        if(strchr(host, ':') != strrchr(host, ':'))
        {
            fprintf(stderr, "Invalid host '%s'!\n", host);
        } 
        else 
        {
            if((delim_ptr = strstr(host, ":")))
            {
                memset(delim_ptr, 0, 1);
                delim_ptr++;
                port = atoi(delim_ptr);
            }

            fingerprint = remote_fingerprint(host, port);
        }
    }

    return fingerprint;
}

/* Fingerprint a remote host's public key */
char *remote_fingerprint(char *host, int port)
{
    int sock = 0;
    char *fingerprint = NULL;
    SSL *ssl_handle = NULL;
    SSL_CTX *ssl_ctx = NULL;

    /* Connect to the remote host */
    sock = tcp_connect(host, port);
    if(sock > 0)
    {
        /* Initialize OpenSSL library */
            SSL_load_error_strings();
            SSL_library_init();

        /* Create a new SSL context */
        ssl_ctx = SSL_CTX_new(SSLv3_client_method());

        if(ssl_ctx == NULL)
        {
                goto error;
        }

        /* Create a new SSL handle from the above SSL context */
        ssl_handle = SSL_new(ssl_ctx);
        if(ssl_handle == NULL)
        {
            goto error;
        }

        /* Assign the TCP socket to the SSL handle */
        if(!SSL_set_fd(ssl_handle, sock))
        {
            goto error;
        }

        /* Establish an SSL connection to the remote host */
        if(SSL_connect(ssl_handle) != 1)
        {
            goto error;
        }

        /* The remote host's certificate is stored in SSL->session->peer.
         * Generate a SHA1 fingerprint from this certificate.
         */
        fingerprint = sha1_fingerprint(ssl_handle->session->peer);
    }
    else 
    {
        perror("Socket");
    }

    goto end;

error:
    ERR_print_errors_fp(stderr);

end:
    if(sock > 0) close(sock);
    if(ssl_handle)
    {
        SSL_shutdown (ssl_handle);
        SSL_free (ssl_handle);
    }
    if (ssl_ctx)
    {
        SSL_CTX_free (ssl_ctx);
    }

    return fingerprint;
}

/* Given a file path to a PEM formatted certificate, return the SHA1 hash of the certificate */
char *fingerprint_pem_file(char *file)
{
    X509 *cert = NULL;
    char *fingerprint = NULL;

    cert = open_pem_file(file);
    if(cert != NULL)
    {
        fingerprint = sha1_fingerprint(cert);
        X509_free(cert);
    }

    return fingerprint;
}

/* Open a PEM formatted certificate file and convert it to a X509 structure */
X509 *open_pem_file(char *file)
{
    FILE *fp = NULL;
    X509 *cert = NULL;

    fp = fopen(file, "rb");

    if(fp)
    {
        if(PEM_read_X509(fp,&cert,NULL,NULL) == NULL)
        {
            cert = NULL;
        }
        fclose(fp);
    } 
    else 
    {
        perror(file);
    }

    return cert;
}

/* Generate a SHA1 fingerprint of a given certificate */
char *sha1_fingerprint(X509 *cert)
{
    unsigned char md[EVP_MAX_MD_SIZE] = { 0 };
    char *fingerprint = NULL;
    unsigned int md_size = 0;

    if(X509_digest(cert,EVP_sha1(),md,&md_size) > 0)
    {
        /* Convert fingerprint bytes into colon-delimited hex string */
        fingerprint = format_sha1_hash((unsigned char *) &md);
    }
    else 
    {
        printf("X509_digest() failed!!!!\n");
    }

    return fingerprint;
}

/* Create TCP connection to remote host for retrieving the host's public certificate */
int tcp_connect(char *host, int port)
{
        int sock = 0;
        struct hostent *h = NULL;
        struct sockaddr_in server = { 0 };

        h = gethostbyname(host);
        if(h)
        {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if(sock > 0)
            {
                server.sin_family = AF_INET;
                server.sin_port = htons(port);
                server.sin_addr = *((struct in_addr *) h->h_addr);
                memset((void *) &server.sin_zero, 0, 8);

                if(connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1)
                {
                        close(sock);
                        sock = 0;
                }
            }
        }

        return sock;
}
