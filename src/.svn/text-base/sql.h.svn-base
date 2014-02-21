#define BUSY_WAIT_PERIOD		100

int sql_init(char *db_name, char *db_backup);
void *sql_exec(char *query, int *result_size, int *err_code);
int sql_dump(char *query, char **str_fmt, int num_cols, FILE *fp);
void sql_log_error();
void sql_cleanup();
