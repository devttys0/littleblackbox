#define DB_NAME			"/etc/lbb.db"
#define DB_LOCAL		"lbb.db"
#define NUM_COLS		6
#define COL_HEADERS		"FW Vendor                FW Description                                    HW Vendor                HW Model                 HW Revision    HW Description"
#define HEADER_DELIM		"-----------------------------------------------------------------------------------------------------------------------------------------------------------------------"
#define QUERY_DELIMITER		"="
#define FIRMWARE_TABLE_QUERY	"firmware"
#define HARDWARE_TABLE_QUERY	"hardware"

struct keymaster
{
	char *fingerprint;
	char *certificate;
	char *key;
	char *description;
};

int lookup_key(struct keymaster *certinfo);
void print_all_cert_info(struct keymaster *certinfo);
void print_search_results(char *term);
char *fingerprint_cert(char *cert_file);
void free_key(struct keymaster *certinfo);
