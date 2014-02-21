/* Wrapper functions for common SQLite queries */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include "sql.h"

sqlite3 *db  = NULL;

/* Initialize the sqlite database */
int sql_init(char *db_name, char *db_backup)
{
	int err_code = 0;

	if(!db)
	{
		/* Open database */
        	if(sqlite3_open(db_name, &db)){
			if(sqlite3_open(db_backup, &db)){
	        	        return err_code;
			}
        	}
	}

        return SQLITE_OK;
}

/* Execute given SQL query. Will only return the FIRST row of the FIRST column of data. Caller must free the returned pointer. */
void *sql_exec(char *query, int *result_size, int *err_code)
{
	sqlite3_stmt *stmt = NULL;
	int rc = 0, col_type = 0;
	void *result = NULL, *tmp_result = NULL;

	*result_size = 0;

	if(!query){
		return NULL;
	}

	/* Prepare the SQL query */
	rc = sqlite3_prepare_v2(db,query,strlen(query),&stmt,NULL);
	if(rc != SQLITE_OK){
		*err_code = sqlite3_errcode(db);
		return NULL;
	}

	/* Loop until the query has finished */
	while(((rc = sqlite3_step(stmt)) != SQLITE_DONE) && (result == NULL)){
		switch(rc){

			case SQLITE_ERROR:
				*err_code = sqlite3_errcode(db);
				sqlite3_finalize(stmt);
				return NULL;
				break;

			case SQLITE_BUSY:
				/* If the table is locked, wait then try again */
				usleep(BUSY_WAIT_PERIOD);
				break;

			case SQLITE_ROW:
			{
				col_type = sqlite3_column_type(stmt,0);
				switch(col_type)
				{
					case SQLITE_TEXT:
					case SQLITE_INTEGER:
						tmp_result = (void *) sqlite3_column_text(stmt,0);
						break;
					
					case SQLITE_BLOB:
						tmp_result = (void *) sqlite3_column_blob(stmt,0);
						break;
					
					default:
						continue;
				}

				/* Get the size of the data we just received from the database */
				*result_size = sqlite3_column_bytes(stmt,0);

				/* Create a copy of tmp_result to pass back to the caller */
        			if((tmp_result != NULL) && (*result_size > 0)){
        			        if((result = malloc(*result_size+1)) == NULL){
        			                perror("Malloc failure");
        			                return NULL;
        			        }
        			        memset(result,0,*result_size+1);
        			        memcpy(result,tmp_result,*result_size);
       				}
				break;
			}
		}
	}

	sqlite3_finalize(stmt);
	*err_code = sqlite3_errcode(db);	

	return result;
}

int sql_dump(char *query, char **str_fmt, int num_cols, FILE *fp)
{
	sqlite3_stmt *stmt = NULL;
	int rc = 0, j = 0, count = 0;

	if(!query){
		return 0;
	}

	/* Prepare the SQL query */
	rc = sqlite3_prepare_v2(db,query,strlen(query),&stmt,NULL);
	if(rc != SQLITE_OK){
		sql_log_error();
		return 0;
	}

	/* Loop until the query has finished */
	while(((rc = sqlite3_step(stmt)) != SQLITE_DONE)){
		switch(rc){

			case SQLITE_ERROR:
				sqlite3_finalize(stmt);
				sql_log_error();
				return 0;

			case SQLITE_BUSY:
				/* If the table is locked, wait then try again */
				usleep(BUSY_WAIT_PERIOD);
				break;

			case SQLITE_ROW:
			{
				for(j=0; j<num_cols; j++)
				{
					fprintf(fp, str_fmt[j], (char *) sqlite3_column_text(stmt,j));
				}
				printf("\n");
				count++;
				break;
			}
		}
	}

	sqlite3_finalize(stmt);

	return count;
}

/* Log last SQLite error message */
void sql_log_error()
{
	char *err_msg = sqlite3_mprintf("SQL ERROR: %s",(char *) sqlite3_errmsg(db));

	fprintf(stderr, "%s\n", err_msg);

	sqlite3_free(err_msg);
	return;
}

/* Clean up after ourselves... */
void sql_cleanup()
{
        sqlite3_close(db);
	db = NULL;
}
