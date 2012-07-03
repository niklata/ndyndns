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

#ifndef NJK_CONFIG_H_
#define NJK_CONFIG_H_ 1

#include <time.h>
#include <strlist.h>

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

typedef struct {
    char *password;
    host_data_t *hostlist;
} namecheap_conf_t;

typedef struct {
    char *host;
    char *password;
    char *ip;
    time_t date;
    void *next;
} hostpairs_t;

typedef struct {
    char *userid;
    char *passhash;
    hostpairs_t *hostpairs;
    host_data_t *tunlist;
} he_conf_t;

void remove_host_from_host_data_list(dyndns_conf_t *conf, char *host);
void modify_hostip_in_list(dyndns_conf_t *conf, char *host, char *ip);
void modify_hostdate_in_list(dyndns_conf_t *conf, char *host, time_t time);
void modify_nc_hostip_in_list(namecheap_conf_t *conf, char *host, char *ip);
void modify_nc_hostdate_in_list(namecheap_conf_t *conf, char *host, time_t time);
void modify_he_hostip_in_list(he_conf_t *conf, char *host, char *ip);
void modify_he_hostdate_in_list(he_conf_t *conf, char *host, time_t time);
void init_dyndns_conf(dyndns_conf_t *t);
void init_namecheap_conf(namecheap_conf_t *t);
void init_he_conf(he_conf_t *t);
int parse_config(char *file, dyndns_conf_t *dc, namecheap_conf_t *nc,
                 he_conf_t *hc);
#endif

