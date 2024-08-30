#include "FTL.h"
#include "log.h"
#include <sys/file.h>
#include "config.h"
#include "config_uci.h"
#include "../datastructure.h"
#include "password.h"
#include <uci_blob.h>

static struct uci_context *uci_ctx;
struct uci_package *uci_dhcp = NULL;
struct uci_package *uci_pihole = NULL;
struct uci_package *uci_network = NULL;

extern char *username;
extern const char **argv_dnsmasq;
extern const char *hostname(void);

#define MAX_BUFFER_SIZE 512

struct uci_package *init_uci_pkg(const char *cfg)
{
	struct uci_context *ctx = uci_ctx;
	struct uci_package *p = NULL;

	if (!ctx) {
		ctx = uci_alloc_context();
		uci_ctx = ctx;

		// disable strict mode, continue on parser errors
		ctx->flags &= ~UCI_FLAG_STRICT;
	} else {
		p = uci_lookup_package(ctx, cfg);
		if (p)
			uci_unload(ctx, p);
	}

	if (uci_load(ctx, cfg, &p))
		return NULL;

	return p;
}

void uci_cleanup(void)
{
	if (uci_ctx) {
		uci_free_context(uci_ctx);
		uci_ctx = NULL;
	}
}

static void set_uci_type_name(struct conf_item *item, const char **section, const char **option)
{
	unsigned int level = config_path_depth(item->p);

	if (item->f & FLAG_PKG_DHCP) {
		*section = "@dnsmasq[0]";
		if (item == &config.dns.cache.size)
			*option = "cachesize";
		else if (item == &config.files.log.dnsmasq)
			*option = "logfacility";
		else if (item == &config.dns.upstreams)
			*option = "server";
		else if (item == &config.dhcp.logging)
			*option = "logdhcp";
		else {
			static char option_buffer[64];
			snprintf(option_buffer, sizeof(option_buffer), "%s", item->p[level - 1]);
			for (char *p = option_buffer; *p; ++p)
				*p = tolower(*p);
			*option = option_buffer;
		}
	} else {
		const char *dot_pos = strchr(item->k, '.');
		*section = (level >= 3) ? item->p[0] : item->p[level - 2];
		if (dot_pos) {
			static char option_buffer[64];
			snprintf(option_buffer, sizeof(option_buffer), "%s", dot_pos + 1);
			for (char *p = option_buffer; *p; ++p) {
				if (*p == '.')
					*p = '_';
			}
			*option = option_buffer;
		}
	}
}

static struct uci_section *get_uci_section_type(struct uci_package *pkg, const char *s)
{
	struct uci_ptr ptr = { 0 };

	if (!pkg || !s)
		return NULL;

	if (*s == '@') {
		ptr.flags |= UCI_LOOKUP_EXTENDED;
		ptr.section = s;
		ptr.target = UCI_TYPE_SECTION;
		ptr.p = pkg;
		if (!uci_lookup_ptr(uci_ctx, &ptr, NULL, true) && ptr.s)
			return ptr.s;
	}

	struct uci_element *e;
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *section = uci_to_section(e);
		if (strcmp(section->type, s) == 0)
			return section;
	}

	return NULL;
}

static void uci_read_foreach_to_json(struct conf_item *conf_item)
{
	if (conf_item->t != CONF_JSON_STRING_ARRAY)
		return;

	const char *delim, *sec;
	const char *opts[3];
	int cnt = 0;
	struct uci_package *pkg = (conf_item->f & FLAG_PKG_DHCP) ? uci_dhcp : uci_pihole;
	if (!pkg) {
		log_err("%s: package is null?", __func__);
		return;
	}

	if (conf_item == &config.dns.cnameRecords) {
		opts[0] = "cname";
		opts[1] = "target";
		opts[2] = "ttl";
		cnt = 3;
		delim = ",";
		sec = "cname";
	} else if (conf_item == &config.dns.hosts) {
		opts[0] = "ip";
		opts[1] = "name";
		cnt = 2;
		delim = " ";
		sec = "domain";
	} else if (conf_item == &config.dhcp.hosts) {
		opts[0] = "mac";
		opts[1] = "ip";
		opts[2] = "name";
		cnt = 3;
		delim = ",";
		sec = "host";
	} else
		return;

	cJSON_Delete(conf_item->v.json);
	conf_item->v.json = cJSON_CreateArray();

	struct uci_element *e;
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (strcmp(s->type, sec) != 0)
			continue;

		static char buffer[MAX_BUFFER_SIZE];
		size_t t_len = 0;

		for (int i = 0; i < cnt; i++) {
			struct uci_option *o = uci_lookup_option(uci_ctx, s, opts[i]);
			if (o && o->v.string) {
				size_t v_len = strlen(o->v.string);
				if (t_len + v_len + 1 >= MAX_BUFFER_SIZE) {
					log_err("%s: buffer size exceeded", __func__);
					break;
				}
				memcpy(buffer + t_len, o->v.string, v_len);
				t_len += v_len;
				if (i < cnt - 1 && t_len < MAX_BUFFER_SIZE - 1)
					buffer[t_len++] = delim[0];
			}
		}

		// ensure null-termination
		if (t_len < MAX_BUFFER_SIZE)
			buffer[t_len] = '\0';
		else
			buffer[MAX_BUFFER_SIZE - 1] = '\0';

		if (t_len > 0)
			cJSON_AddItemToArray(conf_item->v.json, cJSON_CreateString(buffer));
	}
}

static bool uci_read_bool(struct uci_section *s, const char *opt,
						  const char *fallback)
{
	bool fallb = (strcmp(fallback, "1") == 0);

	if (!s)
		return fallb;

	const char *val = uci_lookup_option_string(uci_ctx, s, opt);
	if (!val)
		return fallb;

	if (val[0] == '0' || !strcasecmp(val, "false"))
		return false;
	else if (val[0] == '1' || !strcasecmp(val, "true") )
		return true;

	return fallb;
}

int uci_set_value(struct conf_item *item, const char *value, bool commit)
{
	struct uci_ptr ptr = { 0 };
	const char *sec = NULL, *opt = NULL;
	char *buf = NULL;
	int ret = -1;

	set_uci_type_name(item, &sec, &opt);

	if (!opt || !sec)
		return -1;

	ptr.p = (item->f & FLAG_PKG_DHCP) ? uci_dhcp : uci_pihole;
	ptr.s = get_uci_section_type(ptr.p, sec);
	if (!ptr.s) {
		char *_sec = NULL;
		// section name
		ptr.section = sec;
		// section type
		ptr.value = sec;

		if (*sec == '@') {
			const char *start = strchr(sec, '@');
			const char *end = strchr(sec, '[');

			// extract the substring between '@' and '['
			if (start && end && start < end)
				_sec = strndup(start + 1, end - start - 1);

			ptr.section = _sec;
			ptr.value  = _sec;
		}

		if (uci_set(uci_ctx, &ptr)) {
			log_err("failed to create a new named section for: %s", item->k);
			if (_sec)
				free(_sec);

			return -1;
		}

		if (_sec)
			free(_sec);
	}

	ptr.option = opt;
	ptr.target = UCI_TYPE_OPTION;

	switch(item->t) {
		case CONF_BOOL:
		case CONF_ALL_DEBUG_BOOL:
			ptr.value = item->v.b ? "1" : "0";
			break;
		case CONF_STRING:
		case CONF_STRING_ALLOCATED:
			ptr.value = item->v.s;
			break;
		case CONF_ENUM_BLOCKING_MODE:
			ptr.value = get_blocking_mode_str(item->v.blocking_mode);
			break;
		case CONF_ENUM_WEB_THEME:
			ptr.value = get_web_theme_str(item->v.web_theme);
			break;
		case CONF_ENUM_PTR_TYPE:
			ptr.value = get_ptr_type_str(item->v.ptr_type);
			break;
		case CONF_ENUM_LISTENING_MODE:
			ptr.value = get_listeningMode_str(item->v.listeningMode);
			break;
		case CONF_ENUM_BUSY_TYPE:
			ptr.value = get_busy_reply_str(item->v.busy_reply);
			break;
		case CONF_ENUM_REFRESH_HOSTNAMES:
			ptr.value = get_refresh_hostnames_str(item->v.refresh_hostnames);
			break;
		case CONF_INT:
		case CONF_ENUM_PRIVACY_LEVEL:
		case CONF_ENUM_TEMP_UNIT:
			if (asprintf(&buf, "%i", item->v.i) > 0)
				ptr.value = buf;

			break;
		case CONF_UINT:
			if (asprintf(&buf, "%u", item->v.ui) > 0)
				ptr.value = buf;

			break;
		case CONF_DOUBLE:
			if (asprintf(&buf, "%f", item->v.d) > 0)
				ptr.value = buf;

			break;
		case CONF_UINT16:
			if (asprintf(&buf, "%u", item->v.ui) > 0)
				ptr.value = buf;

			break;
		case CONF_LONG:
			if (asprintf(&buf, "%li", item->v.l) > 0)
				ptr.value = buf;

			break;
		case CONF_ULONG:
			if (asprintf(&buf, "%lu", item->v.ul) > 0)
				ptr.value = buf;

			break;
		case CONF_STRUCT_IN_ADDR:
			char addr4[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &item->v.in_addr, addr4, INET_ADDRSTRLEN);
			ptr.value = addr4;

			break;
		case CONF_STRUCT_IN6_ADDR:
			char addr6[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &item->v.in6_addr, addr6, INET6_ADDRSTRLEN);
			ptr.value = addr6;

			break;
		case CONF_PASSWORD:
		case CONF_JSON_STRING_ARRAY:
			break;
	}

	if (item->t == CONF_JSON_STRING_ARRAY) {
		if (!uci_lookup_ptr(uci_ctx, &ptr, NULL, true) && ptr.o)
			uci_delete(uci_ctx, &ptr);

		for (int i = 0; i < cJSON_GetArraySize(item->v.json); i++) {
			cJSON *server = cJSON_GetArrayItem(item->v.json, i);
			if (server != NULL && cJSON_IsString(server)) {
				ptr.value = server->valuestring;
				if (!uci_lookup_ptr(uci_ctx, &ptr, NULL, true)) {
					ret = uci_add_list(uci_ctx, &ptr);
					if (ret)
						break;
				}
			}
		}
	} else if (item->t == CONF_PASSWORD) {
		// from cli.c
		item--;
		char *pwhash = strlen(value) > 0 ? create_password(value) : strdup("");
		const enum password_result status = verify_password(value, pwhash, false);
		if (status != PASSWORD_CORRECT && status != NO_PASSWORD_SET) {
			log_err("Failed to create password hash (verification failed), password remains unchanged");
			free(pwhash);
			if (buf != NULL)
				free(buf);

			return -1;
		}

		ptr.value = pwhash;
		if (!uci_lookup_ptr(uci_ctx, &ptr, NULL, true))
			ret = uci_set(uci_ctx, &ptr);

		free(pwhash);
	} else {
		if (!uci_lookup_ptr(uci_ctx, &ptr, NULL, true))
			ret = uci_set(uci_ctx, &ptr);
	}

	if (!ret) {
		uci_save(uci_ctx, ptr.p);
		if (commit)
			_uci_commit(&ptr.p);
	} else {
		uci_revert(uci_ctx, &ptr);
		log_err("%s: failed to set %s %s (%d)", __func__, sec, opt, ret);
	}

	if (buf != NULL)
		free(buf);

	return ret;
}

void uci_get_config_values(struct config *conf, bool reload)
{
	struct uci_section *ntp_sec = NULL;
	struct uci_package *sys_pkg = NULL;
	bool sysntpd_enabled = false;

	if (reload) {
		log_info("%s: Reloading UCI packages", __func__);
		uci_dhcp = init_uci_pkg("dhcp");
		uci_pihole = init_uci_pkg( "pihole");
		uci_network = init_uci_pkg( "network");
	}

	// set FLAG for config in dhcp here
	// kinda lazy to patch config.c
	SET_IN_DHCP_FLAG(conf->dns.upstreams.f);
	SET_IN_DHCP_FLAG(conf->dns.domainNeeded.f);
	SET_IN_DHCP_FLAG(conf->dns.expandHosts.f);
	SET_IN_DHCP_FLAG(conf->dns.domain.f);
	SET_IN_DHCP_FLAG(conf->dns.bogusPriv.f);
	SET_IN_DHCP_FLAG(conf->dns.dnssec.f);
	SET_IN_DHCP_FLAG(conf->dns.interface.f);
	SET_IN_DHCP_FLAG(conf->dns.hostRecord.f);
	SET_IN_DHCP_FLAG(conf->dns.listeningMode.f);
	SET_IN_DHCP_FLAG(conf->dns.queryLogging.f);
	SET_IN_DHCP_FLAG(conf->dns.cnameRecords.f);
	SET_IN_DHCP_FLAG(conf->dns.port.f);
	SET_IN_DHCP_FLAG(conf->dns.cache.size.f);
	SET_IN_DHCP_FLAG(conf->dns.revServers.f);
	SET_IN_DHCP_FLAG(conf->dhcp.multiDNS.f);
	SET_IN_DHCP_FLAG(conf->dhcp.rapidCommit.f);
	SET_IN_DHCP_FLAG(conf->dhcp.logging.f);
	SET_IN_DHCP_FLAG(conf->dhcp.ignoreUnknownClients.f);
	SET_IN_DHCP_FLAG(conf->dhcp.hosts.f);
	SET_IN_DHCP_FLAG(conf->dns.hosts.f);
	SET_IN_DHCP_FLAG(conf->files.log.dnsmasq.f);

	for (unsigned int i = 0; i < CONFIG_ELEMENTS; i++) {
		struct conf_item *cfg_item = get_conf_item(conf, i);
		const char *sec = NULL, *opt = NULL;

		if (cfg_item == &config.dns.cnameRecords ||
		   cfg_item == &config.dns.hosts ||
		   cfg_item == &config.dhcp.hosts)
			uci_read_foreach_to_json(cfg_item);

		set_uci_type_name(cfg_item, &sec, &opt);

		if (!opt || !sec)
			continue;

		uci_get_value(cfg_item, sec, opt);
	}

	if (!reload && (conf->ntp.ipv4.active.v.b || conf->ntp.ipv6.active.v.b)) {
		sys_pkg = uci_lookup_package(uci_ctx, "system");
		if (!sys_pkg)
			uci_load(uci_ctx, "system", &sys_pkg);

		ntp_sec = uci_lookup_section(uci_ctx, sys_pkg, "ntp");
		if (ntp_sec)
			sysntpd_enabled = uci_read_bool(ntp_sec, "enable_server", "0");

		// disable builtin ntp if its handled by ntpd (openwrt)
		if (sysntpd_enabled) {
			log_info("Sysntpd is enabled, disabling builtin ntp");
			conf->ntp.ipv4.active.v.b = false;
			conf->ntp.ipv6.active.v.b = false;
		}

		uci_unload(uci_ctx, sys_pkg);
	}

	set_debug_flags(conf);
}

int uci_get_value(struct conf_item *conf_item, const char *sec, const char *opt)
{
	struct uci_ptr ptr = { 0 };
	struct uci_package *pkg = (conf_item->f & FLAG_PKG_DHCP) ? uci_dhcp : uci_pihole;

	if (!sec)
		return -1;

	if (*sec == '@') {
		ptr.section = sec;
		ptr.flags |= UCI_LOOKUP_EXTENDED;
	} else
		ptr.s = get_uci_section_type(pkg, sec);

	ptr.p = pkg;
	ptr.option = opt;

	if (uci_lookup_ptr(uci_ctx, &ptr, NULL, true))
		return UCI_ERR_INVAL;

	if (!ptr.o || !(ptr.flags & UCI_LOOKUP_COMPLETE))
		return UCI_ERR_NOTFOUND;

	if (ptr.o->type == UCI_TYPE_LIST) {
		struct uci_element *e;
		struct uci_list *list = &ptr.o->v.list;
		if (conf_item->t == CONF_JSON_STRING_ARRAY) {
			cJSON_Delete(conf_item->v.json);
			conf_item->v.json = cJSON_CreateArray();
			uci_foreach_element(list, e) {
				if (e->name)
					cJSON_AddItemToArray(conf_item->v.json, cJSON_CreateString(e->name));
			}
		} else if (conf_item->t == CONF_STRING) {
			const char *tmp = uci_get_string(pkg, sec, opt);
			if (tmp) {
				if (conf_item->t == CONF_STRING_ALLOCATED)
					free(conf_item->v.s);

				conf_item->v.s = strdup(tmp);
				conf_item->t = CONF_STRING_ALLOCATED;
				return 0;
			}
		}
	}
	else if (ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string)
		return readStringValue(conf_item, ptr.o->v.string, &config) ? 0 : UCI_ERR_PARSE;

	return 0;
}

const char *uci_get_string(struct uci_package *pkg, const char *sec, const char *opt)
{
	struct uci_ptr ptr = {
		.p = pkg,
		.section = sec,
		.option = opt,
		.target = UCI_TYPE_OPTION
	};

	if (sec && *sec == '@')
		ptr.flags |= UCI_LOOKUP_EXTENDED;

	if (uci_lookup_ptr(uci_ctx, &ptr, NULL, true))
		return NULL;

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE))
		return NULL;

	if (ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string) {
		return ptr.o->v.string;
	} else if (ptr.o->type == UCI_TYPE_LIST) {
		struct uci_element *e = NULL;
		struct uci_list *list = &ptr.o->v.list;
		static char buffer[MAX_BUFFER_SIZE];
		unsigned pos = 0;
		bool first = true;

		buffer[0] = '\0';
		uci_foreach_element(list, e) {
			if (e->name) {
				if (!first)
					pos += snprintf(buffer + pos, sizeof(buffer) - pos, ",");

				pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s", e->name);
				first = false;
			}

			if (pos >= sizeof(buffer) - 1)
				break;
        }
		return buffer;
	}

	return NULL;
}

void _uci_commit(struct uci_package **pkg)
{
	watch_config(false);
	uci_commit(uci_ctx, pkg, false);
	watch_config(true);

	// needs to be reloaded after commiting changes
	log_info("%s: Reloading UCI packages", __func__);
	uci_dhcp = init_uci_pkg("dhcp");
	uci_pihole = init_uci_pkg( "pihole");
	uci_network = init_uci_pkg( "network");
}

struct uci_package *_uci_lookup_package(const char *p)
{
	// null if not loaded
	return uci_lookup_package(uci_ctx, p);
}

void config_cleansed(void)
{
	// read notes in free_config()
	for (unsigned int i = 0; i < CONFIG_ELEMENTS; i++) {
		struct conf_item *item = get_conf_item(&config, i);

		if (item->a != NULL)
			cJSON_Delete(item->a);

		if (item->p != NULL) {
			free_config_path(item->p);
			free(item->p);
		}

		if (item->e != NULL)
			free(item->e);

		if (item->t == CONF_STRING_ALLOCATED)
			free(item->v.s);
		else if (item->t == CONF_JSON_STRING_ARRAY) {
			cJSON_Delete(item->d.json);
			cJSON_Delete(item->v.json);
		}
	}

	if (argv_dnsmasq != NULL)
		free(argv_dnsmasq);

	if (username != NULL)
		free(username);
}

// TODO: need better approach
int uci_foreach_section( struct conf_item *conf_item, const char *target, bool delete)
{
	struct uci_ptr ptr = { 0 };
	char *tmp = NULL;
	int ret = 0;

	ptr.p = (conf_item->f & FLAG_PKG_DHCP) ? uci_dhcp : uci_pihole;
	if (!ptr.p) {
		log_err("%s: package is null?", __func__);
		return -1;
	}

	const char *delim = (!strcmp(conf_item->k, "dns.hosts")) ? " " : ",";
	char *strtmp = strdup(target);
	char *token = strtok_r(strtmp, delim, &tmp);
	if (delete) {
		const char *a = token;
		token = strtok_r(NULL, delim, &tmp);
		const char *b = token;

		if (a == NULL || b == NULL) {
			log_err("failed to delete section for target: %s", target);
			free(strtmp);
			return -1;
		}

		struct uci_element *e;
		uci_foreach_element(&ptr.p->sections, e) {
	        struct uci_option *t1, *t2;
			struct uci_section *s = uci_to_section(e);
			// only find cname and domain section
			if (strcmp(s->type, "cname") == 0) {
	        	t1 = uci_lookup_option(uci_ctx, s, "target");
		        t2 = uci_lookup_option(uci_ctx, s, "cname");
			} else if (strcmp(s->type, "domain") == 0) {
	        	t1 = uci_lookup_option(uci_ctx, s, "name");
		        t2 = uci_lookup_option(uci_ctx, s, "ip");
			} else
				continue;

			if (!t1 && !t2)
				continue;

	        if (t1->v.string && strcmp(t1->v.string, b) == 0) {
		        if (t2->v.string && strcmp(t2->v.string, a) == 0) {
					ptr.s = s;
					ret = uci_delete(uci_ctx, &ptr);
					if (!ret) {
						_uci_commit(&ptr.p);
						break;
					} else
						log_err("%s: failed to delete section: %s [%s] (%d)",
								__func__, s->type, s->e.name, ret);
				}
	        }
		}
	} else {
		const char *sec = NULL;
		bool commit = false;
		int i = 0;
		// 3 is the max num between cnameRecords and dns.hosts
		while (token != NULL && i < 3) {
			if (!strcmp(conf_item->k, "dns.cnameRecords")) {
				if (i == 0) ptr.option = "cname";
				else if (i == 1) ptr.option = "target";
				else if (i == 2) ptr.option = "ttl";

				sec = "cname";
			} else if (!strcmp(conf_item->k, "dns.hosts")) {
				if (i == 0) ptr.option = "ip";
				else if (i == 1) ptr.option = "name";

				sec = "domain";
			} else
				continue;

			if (ptr.option) {
				if (!ptr.s) {
					if (uci_add_section(uci_ctx, ptr.p, sec, &ptr.s))
						break;
				}

				ptr.value = token;
				ret = uci_set(uci_ctx, &ptr);
				if (!ret)
					commit = true;

				i++;
			}

			token = strtok_r(NULL, delim, &tmp);
		}

		if (i > 1) {
			if (commit)
				_uci_commit(&ptr.p);
			else
				uci_revert(uci_ctx, &ptr);
		}
	}

	free(strtmp);
	return ret;
}

void write_config_dhcp(FILE *fp)
{
	if (!uci_dhcp || !uci_network) {
		log_err("dhcp package is not found in the current context");
		return;
	}

	struct uci_element *ep;
	uci_foreach_element(&uci_dhcp->sections, ep) {
		struct uci_section *network_section = NULL;
		struct uci_section *s = uci_to_section(ep);

		if (strcmp(s->type, "host") == 0)
			continue;

		// TODO: use ubus data instead
		if (strcmp(ep->name, "wan") == 0) {
			network_section = uci_lookup_section(uci_ctx, uci_network, "wan");
			const char *proto = NULL;
			if (network_section)
				proto = uci_lookup_option_string(uci_ctx, network_section, "proto");
			if (proto && strcmp(proto, "pppoe") == 0) {
				const char *ignore = uci_lookup_option_string(uci_ctx, s, "ignore");
				if (strcmp(ignore, "1") == 0)
					fputs("no-dhcp-interface=pppoe-wan\n", fp);
			}
		}

		bool skipped_dhcp = false;
		int dhcp_start = 0, dhcp_limit = 0;
		const char *iface = NULL;
		const char *domain_iface = NULL;
		const char *leasetime = NULL;
		struct uci_element *eo;
		uci_foreach_element(&s->options, eo) {
			struct uci_option* opt = uci_to_option(eo);
			if (opt->type == UCI_TYPE_STRING && opt->v.string) {
				if (strcmp(s->type, "dhcp") == 0) {
					if (strcmp(opt->e.name, "ignore") == 0 && strcmp(opt->v.string, "1") == 0) {
						skipped_dhcp = true;
						break;
					}

					if (strcmp(opt->e.name, "interface") == 0)
						iface = opt->v.string;
					else if (strcmp(opt->e.name, "start") == 0)
						dhcp_start = atoi(opt->v.string);
					else if (strcmp(opt->e.name, "limit") == 0)
						dhcp_limit = atoi(opt->v.string);
					else if (strcmp(opt->e.name, "leasetime") == 0)
						leasetime = opt->v.string;
					else if (strcmp(opt->e.name, "domain_iface") == 0)
						domain_iface = opt->v.string;
				} else if (strcmp(s->type, "dnsmasq") == 0) {
					if (strcmp(opt->e.name, "dhcpleasemax") == 0)
						fprintf(fp, "dhcp-lease-max=%s\n", opt->v.string);
					else if (strcmp(opt->e.name, "dhcp_boot") == 0)
						fprintf(fp, "dhcp-boot=%s\n", opt->v.string);
				}
			} else if (opt->type == UCI_TYPE_LIST) {
				const char *networkid = NULL;
				const char *vendorclass = NULL;
				if (strcmp(s->type, "vendorclass") == 0) {
					networkid = uci_lookup_option_string(uci_ctx, s, "networkid");
					vendorclass = uci_lookup_option_string(uci_ctx, s, "vendorclass");
					if (networkid && vendorclass)
						fprintf(fp, "dhcp-vendorclass=set:%s,%s\n", networkid, vendorclass);
				}

				struct uci_element *el;
				uci_foreach_element(&opt->v.list, el) {
					if (!el->name)
						continue;

					if (strcmp(s->type, "vendorclass") == 0 && networkid && vendorclass)
						fprintf(fp, "dhcp-option=%s,%s\n", networkid, el->name);

					if (iface != NULL && strcmp(opt->e.name, "dhcp_option") == 0)
						fprintf(fp, "dhcp-option=%s,%s\n", iface, el->name);
				}
			}
		}

		if (skipped_dhcp || iface == NULL)
			continue;

		network_section = uci_lookup_section(uci_ctx, uci_network, iface);
		if (!network_section)
			continue;

		const char *ipaddr = uci_lookup_option_string(uci_ctx, network_section, "ipaddr");
		const char *netmask = uci_lookup_option_string(uci_ctx, network_section, "netmask");

		if (!ipaddr || !netmask)
			continue;

		struct in_addr addr4, mask, net;
		memset(&addr4, 0, sizeof(addr4));
		if (!inet_pton(AF_INET, ipaddr, &addr4))
			continue;

		char ip_net[INET_ADDRSTRLEN] = { 0 },
		     ip_start[INET_ADDRSTRLEN] = { 0 },
		     ip_end[INET_ADDRSTRLEN] = { 0 };

		memset(&mask, 0, sizeof(mask));
		if (!inet_pton(AF_INET, netmask, &mask))
			continue;

		unsigned long mask_val = ntohl(mask.s_addr);
		int prfx = 0;
		while (mask_val) {
			prfx += (mask_val & 1);
			mask_val >>= 1;
		}

		memset(&net, 0, sizeof(net));
		net.s_addr = addr4.s_addr & mask.s_addr;

		addr4.s_addr = htonl(ntohl(net.s_addr));
		inet_ntop(AF_INET, &addr4.s_addr, ip_net, INET_ADDRSTRLEN);

		addr4.s_addr = htonl(ntohl(net.s_addr) + dhcp_start);
		inet_ntop(AF_INET, &addr4.s_addr, ip_start, INET_ADDRSTRLEN);

		addr4.s_addr = htonl(ntohl(net.s_addr) + dhcp_start + dhcp_limit - 1);
		inet_ntop(AF_INET, &addr4.s_addr, ip_end, INET_ADDRSTRLEN);

		// dhcp-range=set:lan,192.168.0.10,192.168.0.19,255.255.255.0,24h
		fprintf(fp, "dhcp-range=set:%s,%s,%s,%s", iface, ip_start,
				ip_end, netmask);

		if (leasetime)
			fprintf(fp, ",%s", leasetime);

		fprintf(fp, "\ndhcp-option=%s,option:router,%s\n", iface, ipaddr);

		// domain=lan,192.168.0.0/24,local
		// domain=lan,192.168.0.1,192,168.0.50,local
		// needs expandhosts in order to work without manually adding domain to host
		if (config.dns.domainNeeded.v.b && domain_iface != NULL)
			fprintf(fp, "domain=%s,%s/%i,local\n", domain_iface, ip_net, prfx);
	}
}

void write_static_hosts(void)
{
	if (!uci_dhcp) {
		log_err("dhcp package is not found in the current context");
		return;
	}

	FILE *hostfile = fopen("/tmp/hosts/host_static", "w");
	if (!hostfile) {
		log_err("Cannot open /tmp/hosts/host_static for writing, unable to update host_static: %s", strerror(errno));
		return;
	}

	if (flock(fileno(hostfile), LOCK_EX) != 0) {
		log_err("Cannot open /tmp/hosts/host_static in exclusive mode: %s", strerror(errno));
		fclose(hostfile);
		return;
	}

	struct uci_element *e;
	struct uci_section *s;
	uci_foreach_element(&uci_dhcp->sections, e) {
		s = uci_to_section(e);
		if (strcmp(s->type, "host") != 0)
			continue;

		const char *do_dns = uci_lookup_option_string(uci_ctx, s, "dns");
		if (do_dns == NULL)
			continue;

		if (strcmp(do_dns, "1") != 0)
			continue;

		const char *ip = uci_lookup_option_string(uci_ctx, s, "ip");
		const char *name = uci_lookup_option_string(uci_ctx, s, "name");
		if (name != NULL && ip != NULL)
			fprintf(hostfile, "%s %s\n", ip, name);
	}

	if (!uci_network) {
		log_err("network package is not found in the current context");
		goto out;
	}

	uci_foreach_element(&uci_network->sections, e) {
		s = uci_to_section(e);
		if (strcmp(s->type, "interface") != 0)
			continue;

		const char *proto = uci_lookup_option_string(uci_ctx, s, "proto");
		if (!proto || strcmp(proto, "static") != 0)
			continue;

		const char *domain_iface = NULL;
		const char *ipaddr = uci_lookup_option_string(uci_ctx, s, "ipaddr");
		struct uci_section *dhcp_section = uci_lookup_section(uci_ctx, uci_dhcp, e->name);

		if (dhcp_section)
			domain_iface = uci_lookup_option_string(uci_ctx, dhcp_section, "domain_iface");

		if (ipaddr != NULL && strcmp(ipaddr, "127.0.0.1") != 0) {
			if (domain_iface != NULL)
				fprintf(hostfile, "%s %s.%s\n", ipaddr, hostname(), domain_iface);
			else
				fprintf(hostfile, "%s %s\n", ipaddr, hostname());
		}
	}

out:
	if (flock(fileno(hostfile), LOCK_UN) != 0)
		log_err("Cannot release lock on host_static: %s", strerror(errno));

	fclose(hostfile);
}

struct dnsmasqOpt {
	const char* option;
	const char* opt;
	const char* defaultValue;
};

// dnsmasq options that are not covered by struct config, for now to differentiate
// between bool or not is by defaultValue, or use second dnsmasqOpts?
static const struct dnsmasqOpt dnsmasqOpts[] = {
	{ "ubus", "enable-ubus", "1" },
	{ "nonwildcard", "bind-dynamic", "1" },
	{ "tftp_no_fail", "tftp-no-fail", "0" },
	{ "noresolv", "no-resolv", "0" },
	{ "nonegcache", "no-negcache", "0" },
	{ "no_id", "no-ident", "0" },
	{ "filterwin2k", "filterwin2k", "0" },
	{ "nohosts", "no-hosts", "0" },
	{ "strictorder", "strict-order", "0" },
	{ "readethers", "read-ethers", "0" },
	{ "dbus", "enable-dbus", "0" },
	{ "allservers", "all-servers", "0" },
	{ "noping", "no-ping", "0" },
	{ "filter_a", "filter-A", "0" },
	{ "filter_aaaa", "filter-AAAA", "0" },
	{ "scriptarp", "script-arp", "0" },
	{ "enable_tftp", "enable-tftp", "0" },
	{ "proxydnssec", "proxy-dnssec", "0" },
	{ "rebind_protection", "stop-dns-rebind", "0" },
	{ "rebind_localhost", "rebind-localhost-ok", "0" },
	{ "quietdhcp", "quiet-dhcp", "0" },
	{ "fqdn", "dhcp-fqdn", "0" },
	{ "sequential_ip", "dhcp-sequential-ip", "0" },
	{ "tftp_root", "tftp-root", NULL },
	{ "tftp_unique_root", "ftp-unique-root", NULL} ,
	{ "ednspacket_max", "edns-packet-max", NULL },
	{ "dnsforwardmax", "dns-forward-max", NULL },
	{ "queryport", "query-port", NULL },
	{ "minport", "min-port", NULL },
	{ "maxport", "max-port", NULL },
	{ "local_ttl", "local-ttl", NULL },
	{ "max_ttl", "max-ttl", NULL },
	{ "min_cache_ttl", "min-cache-ttl", NULL },
	{ "max_cache_ttl", "max-cache-ttl", NULL },
	{ "serversfile", "servers-file", NULL },
	{ "rebind_domain", "rebind-domain-ok", NULL },
	{ "notinterface", "except-interface", NULL },
	{ "addnhosts", "addn-hosts", NULL },
	{ "bogusnxdomain", "bogus-nxdomain", NULL }
};

#define NUM_DNSMQ_OPT (sizeof(dnsmasqOpts) / sizeof(dnsmasqOpts[0]))

void write_dnsmasq_conf(FILE *fp)
{
	struct uci_section *dhcp_section = get_uci_section_type(uci_dhcp, "@dnsmasq[0]");
 
	if (!dhcp_section) {
		log_err("%s: dhcp package is not found in the current context", __func__);
		return;
	}
 
	bool rebind_protection = true;
	bool rebind_localhost = false;
	for (size_t i = 0; i < NUM_DNSMQ_OPT; ++i) {
		const char *dnsmasq_opt = dnsmasqOpts[i].opt;
		const char *dnsmasq_option = dnsmasqOpts[i].option;

		// dealing only for boolean
		if (dnsmasqOpts[i].defaultValue != NULL) {
			bool tmp = uci_read_bool(dhcp_section, dnsmasq_option, dnsmasqOpts[i].defaultValue);

			if (!strcmp(dnsmasq_option, "proxydnssec")) {
				if (!config.dns.dnssec.v.b && tmp) {
					fputs(dnsmasq_opt, fp);
					fputs("\n", fp);
					const char *cpe_id = uci_lookup_option_string(uci_ctx, dhcp_section, "cpe_id");
					if (cpe_id != NULL)
						fprintf(fp, "add-cpe-id=%s\n", cpe_id);
				}
			} else if (!strcmp(dnsmasq_option, "rebind_protection")) {
				rebind_protection = tmp;
			} else if (!strcmp(dnsmasq_option, "rebind_localhost")) {
				rebind_localhost = tmp;
			} else if (tmp) {
				fputs(dnsmasq_opt, fp);
				fputs("\n", fp);
			}
		} else {
			// dealing for not boolean
			struct uci_element *elem;
			uci_foreach_element(&dhcp_section->options, elem) {
				struct uci_option* opt = uci_to_option(elem);
				if (!opt)
					continue;

				if (opt->type == UCI_TYPE_STRING && opt->v.string) {
					if (strcmp(opt->e.name, dnsmasq_option) == 0)
						fprintf(fp, "%s=%s\n", dnsmasq_opt, opt->v.string);
				} else if (opt->type == UCI_TYPE_LIST) {
					struct uci_element *el;
					uci_foreach_element(&opt->v.list, el) {
						if (el->name && strcmp(opt->e.name, dnsmasq_option) == 0) {
							// TODO: use ubus data instead to get device/ifname
							if (strcmp("notinterface", dnsmasq_option) == 0) {
								const char *iface = NULL;
								const char *proto = uci_get_string(uci_network, el->name, "proto");
								if (strcmp(proto, "pppoe") == 0)
									iface = "pppoe-wan";
								else
									iface = uci_get_string(uci_network, el->name, "device");

								fprintf(fp, "%s=%s\n", dnsmasq_opt, iface ? iface : el->name);
							} else
								fprintf(fp, "%s=%s\n", dnsmasq_opt, el->name);
						}
					}
				}
			}
		}
	}
	fputs("\n", fp);

	if (rebind_protection)
	{
		fputs("# Discard upstream RFC1918 responses!\n", fp);
		fputs("stop-dns-rebind\n", fp);
		fputs("\n", fp);
		if (rebind_localhost)
		{
			fputs("# Allowing 127.0.0.0/8 responses\n", fp);
			fputs("rebind-localhost-ok\n", fp);
			fputs("\n", fp);
		}
	}
}
