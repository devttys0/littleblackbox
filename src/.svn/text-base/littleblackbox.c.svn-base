#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include "sql.h"
#include "littleblackbox.h"

/* Queries the database for the public / private keypair that matches the fingerprint stored in certinfo. 
 * If found, the certificate / key members of the keymaster struct are populated accordingly.
 * Returns 1 on success, 0 on failure.
 */
int lookup_key(struct keymaster *certinfo)
{
	int result_size = 0, err_code = 0, retval = 1;
	char *desc_query = NULL, *priv_query = NULL, *pub_query = NULL;

	if(sql_init(DB_NAME, DB_LOCAL) != SQLITE_OK)
	{
		goto error;
	}

	priv_query = sqlite3_mprintf("SELECT key FROM certificates WHERE fingerprint = %Q", certinfo->fingerprint);
	certinfo->key = sql_exec(priv_query, &result_size, &err_code);
	sqlite3_free(priv_query);
	if(err_code != SQLITE_OK)
	{
		goto error;
	}

	pub_query = sqlite3_mprintf("SELECT certificate FROM certificates WHERE fingerprint = %Q", certinfo->fingerprint);
	certinfo->certificate = sql_exec(pub_query, &result_size, &err_code);
	sqlite3_free(pub_query);
	if(err_code != SQLITE_OK)
	{
		goto error;
	}

	desc_query = sqlite3_mprintf("SELECT description FROM certificates WHERE fingerprint = %Q", certinfo->fingerprint);
	certinfo->description = sql_exec(desc_query, &result_size, &err_code);
	sqlite3_free(desc_query);
	if(err_code != SQLITE_OK)
	{
		goto error;
	}

	goto end;

error:
	sql_log_error();
	retval = 0;

end:
	sql_cleanup();
	return retval;
}

/* Prints out all information related to the selected certificate to stdout */
void print_all_cert_info(struct keymaster *certinfo)
{
	int count = 0;
	char *query = NULL;
	/* Format strings for the respective columns retrieved in sql_dump() */
	char *col_fmt[NUM_COLS] = {"%-25s", "%-50s", "%-25s", "%-25s", "%-15s", "%-50s"};

	if(sql_init(DB_NAME, DB_LOCAL) != SQLITE_OK)
	{
		sql_log_error();
		return;
	}

	query = sqlite3_mprintf("SELECT firmware.vendor,firmware.description,hardware.vendor,model,revision,hardware.description FROM firmware JOIN hardware ON firmware.device_id=hardware.id WHERE certificate_id = (SELECT id FROM certificates WHERE fingerprint = %Q)", certinfo->fingerprint);

	/* Print out a table of all relevant database info related to this certificate */
	printf("\n%s\n%s\n", COL_HEADERS, HEADER_DELIM);
	count = sql_dump(query, col_fmt, NUM_COLS, stdout);
	printf("\nFound %d firmware(s) using this certificate.\n\n", count);

	sqlite3_free(query);
	sql_cleanup();
	return;
}

/* Dumps search results that match the provided query term */
void print_search_results(char *term)
{
	int count = 0;
        char *query = NULL, *q = NULL, *table = NULL;
        /* Format strings for the respective columns retrieved in sql_dump() */
        char *col_fmt[NUM_COLS] = {"%-25s", "%-50s", "%-25s", "%-25s", "%-15s", "%-50s"};

	if(sql_init(DB_NAME, DB_LOCAL) != SQLITE_OK)
	{
		sql_log_error();
		goto end;
	}

	/* Queries should be in the format: <table.column>=<search term> */
	table = strdup(term);
	q = strstr(table, QUERY_DELIMITER);
	if(!q)
	{
		fprintf(stderr, "ERROR: Improperly formatted query!\n");
		goto end;
	}
	memset(q, 0, 1);
	q++;

	query = sqlite3_mprintf("SELECT firmware.vendor,firmware.description,hardware.vendor,model,revision,hardware.description FROM firmware JOIN hardware ON firmware.device_id=hardware.id WHERE %s LIKE '%%%q%%'", table, q);


	/* Print out a table of all relevant database info related to this certificate */
        printf("\n%s\n%s\n", COL_HEADERS, HEADER_DELIM);
        count = sql_dump(query, col_fmt, NUM_COLS, stdout);
        printf("\nFound %d matches for '%s'.\n\n", count, q);

end:
	if(table) free(table);
        sqlite3_free(query);
        sql_cleanup();
        return;

}

/* Frees any allocated memory pointed to by the structure members */
void free_key(struct keymaster *certinfo)
{
	if(certinfo->key != NULL) free(certinfo->key);
	if(certinfo->fingerprint != NULL) free(certinfo->fingerprint);
	if(certinfo->certificate != NULL) free(certinfo->certificate);
	if(certinfo->description != NULL) free(certinfo->description);
	return;
}
