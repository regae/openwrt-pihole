#ifndef CONFIG_UCI_H
#define CONFIG_UCI_H

#include "config.h"
#include "inotify.h"
#include <uci.h>

extern struct uci_package *uci_dhcp;
extern struct uci_package *uci_pihole;
extern struct uci_package *uci_network;

#define SET_IN_DHCP_FLAG(cfg_item) \
    if (!(cfg_item & FLAG_PKG_DHCP)) \
        cfg_item |= FLAG_PKG_DHCP;

int uci_set_value(struct conf_item *item,
				  const char *value, bool commit);
int uci_get_value(struct conf_item *conf_item, const char *sec, const char *opt);
int uci_foreach_section(struct conf_item *conf_item,
					    const char *target, bool delete);
void uci_get_config_values(struct config *conf, bool reload);
const char *uci_get_string(struct uci_package *pkg, const char *sec, const char *opt);
void clean_all_leftovers(void);

void write_static_hosts(void);
void write_config_dhcp(FILE *fp);
void write_dnsmasq_conf(FILE *fp);
struct uci_package *init_uci_pkg(const char *cfg);
void uci_clean_config(void);
void _uci_commit(struct uci_package **pkg);
bool uci_read_bool(struct uci_section *s,
			  const char *opt, const char *fallback);
struct uci_package *_uci_lookup_package(const char *p);

#endif // CONFIG_UCI_H
