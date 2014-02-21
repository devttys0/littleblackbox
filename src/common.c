#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

/* 
 * Converts a raw SHA1 hash to a colon-delimited string.
 * This is the format in which certificate fingerprints are stored in the database.
 */
char *format_sha1_hash(unsigned char *hash)
{
    int i = 0;
    char sha_str[(SHA_DIGEST_LENGTH*3)+1] = { 0 };

    for(i=0; i<SHA_DIGEST_LENGTH; i++)
    {
        sprintf((char *) &sha_str+(i*3),"%.2X:", hash[i]);
    }

    /* Zero out the trailing colon in the fingerprint string */
    sha_str[(i*3)-1] = 0;
        
    return strdup(sha_str);
}
