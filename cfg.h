/*
ndyndns.conf
------------

username=
password=
hostname=<LIST: host1,host2,...,hostN>
mx=host (default: NOCHG)
wildcard|nowildcard (default: NOCHG)
backmx|nobackmx (default: NOCHG)
offline (default: NO)
*/

#ifndef __NJK_CONFIG_H_
#define __NJK_CONFIG_H_ 1
typedef enum {
	WC_NOCHANGE,
	WC_YES,
	WC_NO
} wc_state;

typedef enum {
	BMX_NOCHANGE,
	BMX_YES,
	BMX_NO
} backmx_state;

typedef enum {
	OFFLINE_NO,
	OFFLINE_YES
} offline_state;

typedef enum {
	SYSTEM_DYNDNS,
	SYSTEM_STATDNS,
	SYSTEM_CUSTOMDNS
} dyndns_system;

typedef struct {
	char *host;
	char *ip;
	time_t date;
	void *next;
} host_data_t;

typedef struct {
	char *username;
	char *password;
	host_data_t *hostlist;
	char *mx;
	wc_state wildcard;
	backmx_state backmx;
	offline_state offline;
	dyndns_system system;
} dyndns_conf_t;

void remove_host_from_host_data_list(dyndns_conf_t *conf, char *host);
void modify_hostip_in_list(dyndns_conf_t *conf, char *host, char *ip);
void modify_hostdate_in_list(dyndns_conf_t *conf, char *host, time_t time);
void init_dyndns_conf(dyndns_conf_t *t);
int parse_config(char *file, dyndns_conf_t *dc);
#endif

