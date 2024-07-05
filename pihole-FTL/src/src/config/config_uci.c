#include "FTL.h"
#include "log.h"
#include "config.h"
#include "config_uci.h"
#include "../datastructure.h"
#include "password.h"
#include <uci_blob.h>

extern char *username;
extern const char **argv_dnsmasq;

static struct uci_ptr uci_ptr;

static void uci_read_foreach_to_json(struct conf_item *conf_item)
{
	if (conf_item->t != CONF_JSON_STRING_ARRAY || !conf_item->uci.opt)
		return;

	const char *package = (conf_item->f & FLAG_PKG_DHCP) ? "dhcp" : "pihole";
	const char *delim = (!strcmp(conf_item->uci.stype, "domain")) ? " " : ",";
	struct uci_package *pkg = uci_lookup_package(config.uci_ctx, package);
	if(!pkg) {
		log_err("%s: %s package is not found in the current context.",
				__func__, package);
		return;
	}

	cJSON_Delete(conf_item->v.json);
	conf_item->v.json = cJSON_CreateArray();

	struct uci_element *e;
	uci_foreach_element(&pkg->sections, e)
	{
		struct uci_section *s = uci_to_section(e);
		if (strcmp(s->type, conf_item->uci.stype) != 0)
			continue;

		char *buffer = NULL;
		char *str_copy = strdup(conf_item->uci.opt);
		char *token = strtok(str_copy, "_");
		size_t buffer_size = 0;
		while (token != NULL) {
			struct uci_option *o = uci_lookup_option(config.uci_ctx, s, token);
			if (o && o->v.string) {
				size_t token_len = strlen(o->v.string) + 1; // +1 for len delim
				buffer = realloc(buffer, buffer_size + token_len + 1); // +1 for null terminator
				if (!buffer) {
					log_err("%s: Memory allocation failed.", __func__);
					free(str_copy);
					return;
				}
				strcpy(buffer + buffer_size, o->v.string);
				strcat(buffer + buffer_size, delim);
				buffer_size += token_len;
			}
			token = strtok(NULL, "_");
		}

		// remove last delim
		if (buffer_size > 1)
			buffer[buffer_size - 1] = '\0';
		else {
			// No tokens were added
			free(buffer);
			buffer = NULL;
		}

		if (buffer) {
			cJSON_AddItemToArray(conf_item->v.json, cJSON_CreateString(buffer));
			free(buffer);
		}

		free(str_copy);
	}
}

static int check_uci_section_type(struct uci_context *ctx, struct conf_item *conf_item)
{
	if(conf_item->uci.sname)
		return 0;

	const char *package = (conf_item->f & FLAG_PKG_DHCP) ? "dhcp" : "pihole";
	struct uci_package *pkg = uci_lookup_package(ctx, package);
	if(!pkg)
		uci_load(ctx, package, &pkg);

	// check the named section first
	struct uci_section *s = uci_lookup_section(ctx, pkg, conf_item->uci.stype);
	if(s && s->e.name) {
		conf_item->uci.sname = strdup(s->e.name);
		return 0;
	}

	// this point we have no named section
	// search section type name
	struct uci_element *e;
	uci_foreach_element(&pkg->sections, e)
	{
		s = uci_to_section(e);
		if (strcmp(s->type, conf_item->uci.stype) == 0) {
			/* use s->e.name instead of uci_section */
			conf_item->uci.sname = strdup(s->e.name);
			return 0;
		}
	}

	return -1;
}

int uci_set_value(struct uci_context *ctx, struct conf_item *item, const char *value, bool commit)
{
	struct uci_ptr ptr = { 0 };
	char *buf = NULL;
	int ret = 0;

	ptr.package = (item->f & FLAG_PKG_DHCP) ? "dhcp" : "pihole";
	ptr.p = uci_lookup_package(ctx, ptr.package);
	if(!ptr.p) {
		log_err("%s package is not found in the current context", ptr.package);
		return -1;
	}
	// create a new section if not found
	if(!item->uci.sname) {
		// section name
		ptr.section = item->uci.stype;
		// section type
		ptr.value  = item->uci.stype;
		item->uci.sname = strdup(item->uci.stype);

		ret = uci_set(ctx, &ptr);
		log_warn("Creating new named section : %s (%s).",
				  item->uci.stype, ret > 0 ? "failed" : "success");
	}

	if(ret)
		return -1;

	switch(item->t)
	{
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
		{
			if (asprintf(&buf, "%i", item->v.i) > 0)
				ptr.value = buf;

			break;
		}
		case CONF_UINT:
		{
			if (asprintf(&buf, "%u", item->v.ui) > 0)
				ptr.value = buf;

			break;
		}
		case CONF_DOUBLE:
		{
			if (asprintf(&buf, "%f", item->v.d) > 0)
				ptr.value = buf;

			break;
		}
		case CONF_UINT16:
		{
			if (asprintf(&buf, "%u", item->v.ui) > 0)
				ptr.value = buf;

			break;
		}
		case CONF_LONG:
		{
			if (asprintf(&buf, "%li", item->v.l) > 0)
				ptr.value = buf;

			break;
		}
		case CONF_ULONG:
		{
			if (asprintf(&buf, "%lu", item->v.ul) > 0)
				ptr.value = buf;

			break;
		}
		case CONF_STRUCT_IN_ADDR:
		{
			char addr4[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &item->v.in_addr, addr4, INET_ADDRSTRLEN);
			ptr.value = addr4;

			break;
		}
		case CONF_STRUCT_IN6_ADDR:
		{
			char addr6[INET6_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET6, &item->v.in6_addr, addr6, INET6_ADDRSTRLEN);
			ptr.value = addr6;

			break;
		}
		case CONF_PASSWORD:
		case CONF_JSON_STRING_ARRAY:
			break;
	}

	ptr.section = item->uci.sname;
	ptr.option = item->uci.opt;
	ptr.target = UCI_TYPE_OPTION;

	if(item->t == CONF_JSON_STRING_ARRAY)
	{
		if(!uci_lookup_ptr(ctx, &ptr, NULL, false)) {
			if(ptr.o)
				uci_delete(ctx, &ptr);
		}

		for(int i = 0; i < cJSON_GetArraySize(item->v.json); i++)
		{
			cJSON *server = cJSON_GetArrayItem(item->v.json, i);
			if(server != NULL && cJSON_IsString(server)) {
				ptr.value = server->valuestring;
				if(!uci_lookup_ptr(ctx, &ptr, NULL, false)) {
					ret = uci_add_list(ctx, &ptr);
					if(ret)
						break;
				}
			}
		}
	} else if(item->t == CONF_PASSWORD) {
		// from cli.c
		item--;
		char *pwhash = strlen(value) > 0 ? create_password(value) : strdup("");
		const enum password_result status = verify_password(value, pwhash, false);
		if(status != PASSWORD_CORRECT && status != NO_PASSWORD_SET)
		{
			log_err("Failed to create password hash (verification failed), password remains unchanged");
			free(pwhash);
			if(buf != NULL)
				free(buf);

			return -1;
		}

		ptr.value = pwhash;
		if(!uci_lookup_ptr(ctx, &ptr, NULL, false))
			ret = uci_set(ctx, &ptr);

		free(pwhash);
	} else {
		if(!uci_lookup_ptr(ctx, &ptr, NULL, false))
			ret = uci_set(ctx, &ptr);
	}

	if(!ret) {
		uci_save(ctx, ptr.p);
		if(commit)
			_uci_commit(ctx, &ptr.p);
	}
	else {
		uci_revert(ctx, &ptr);
		log_err("%s: failed to set %s %s (%d)", __func__, item->uci.stype, item->uci.opt, ret);
	}

	if(buf != NULL)
		free(buf);

	return ret;
}

void uci_get_config_values(struct config *conf, bool reload)
{
	if(reload) {
		struct uci_package *pkg = uci_lookup_package(conf->uci_ctx, "dhcp");
		if(pkg)
			uci_unload(conf->uci_ctx, pkg);

		pkg = uci_lookup_package(conf->uci_ctx, "pihole");
		if(pkg)
			uci_unload(conf->uci_ctx, pkg);
	}

	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		struct conf_item *cfg_item = get_conf_item(conf, i);

		if(cfg_item == &config.dns.cnameRecords ||
		   cfg_item == &config.dns.hosts ||
		   cfg_item == &config.dhcp.hosts)
			uci_read_foreach_to_json(cfg_item);
		else {
			uci_get_value(conf->uci_ctx, cfg_item);

			log_debug(DEBUG_UCI, "UCI config for %s has section name \"%s\", section type %s",
					  cfg_item->k, cfg_item->uci.sname ? cfg_item->uci.sname : "NULL", cfg_item->uci.stype);
		}
	}

	set_debug_flags(conf);
}

int uci_get_value(struct uci_context *ctx, struct conf_item *conf_item)
{
	struct uci_ptr ptr = { 0 };

	ptr.package = (conf_item->f & FLAG_PKG_DHCP) ? "dhcp" : "pihole";
	ptr.option = conf_item->uci.opt;

	if(check_uci_section_type(ctx, conf_item)) {
		log_warn("There is no section for %s, type: %s in %s uci config.",
				 conf_item->k, conf_item->uci.stype, ptr.package);
		return -1;
	}

	ptr.section = conf_item->uci.sname;

	if(uci_lookup_ptr(ctx, &ptr, NULL, false))
		return UCI_ERR_INVAL;

	if(!ptr.o || !(ptr.flags & UCI_LOOKUP_COMPLETE)) {
		log_debug(DEBUG_UCI, "UCI config \"%s\" not found for %s, using default value.",
				  conf_item->uci.opt, conf_item->k);
		return UCI_ERR_NOTFOUND;
	}

	if(ptr.o->type == UCI_TYPE_LIST && conf_item->t == CONF_JSON_STRING_ARRAY)
	{
		struct uci_element *e;
		struct uci_list *list = &ptr.o->v.list;
		cJSON_Delete(conf_item->v.json);
		conf_item->v.json = cJSON_CreateArray();
		uci_foreach_element(list, e) {
			if(e->name)
				cJSON_AddItemToArray(conf_item->v.json, cJSON_CreateString(e->name));
		}
	}
	else if(ptr.o->type == UCI_TYPE_STRING && ptr.o->v.string)
		return readStringValue(conf_item, ptr.o->v.string, &config) ? 0 : UCI_ERR_PARSE;

	return 0;
}

void clean_all_leftovers(void)
{
	// free all config
	free_config(&config);

	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		struct conf_item *copy_item = get_conf_item(&config, i);

		// read notes in free_config()
		if(copy_item->a != NULL)
			cJSON_Delete(copy_item->a);

		if(copy_item->p != NULL)
		{
			free_config_path(copy_item->p);
			free(copy_item->p);
		}

		if(copy_item->e != NULL)
			free(copy_item->e);

		if(copy_item->t == CONF_JSON_STRING_ARRAY)
			cJSON_Delete(copy_item->d.json);

		if(copy_item->uci.sname != NULL)
			free(copy_item->uci.sname);
	}

	if(argv_dnsmasq != NULL)
		free(argv_dnsmasq);

	if(username != NULL)
		free(username);
}

// TODO: use better approach
int uci_foreach_section(struct uci_context *ctx, struct conf_item *conf_item, const char *target, bool delete)
{
	char *tmp = NULL;
	int ret = 0;

	memset(&uci_ptr, 0, sizeof(struct uci_ptr));
	const char *package = (conf_item->f & FLAG_PKG_DHCP) ? "dhcp" : "pihole";

	uci_ptr.p = uci_lookup_package(ctx, package);
	if(!uci_ptr.p) {
		log_err("%s: %s package is not found in the current context.",
				__func__, package);
		return -1;
	}

	const char *delim = (!strcmp(conf_item->k, "dns.hosts")) ? " " : ",";
	char *strtmp = strdup(target);
	char *token = strtok_r(strtmp, delim, &tmp);
	if(delete) {
		const char *a = token;
		token = strtok_r(NULL, delim, &tmp);
		const char *b = token;

		if(a == NULL || b == NULL) {
			log_debug(DEBUG_UCI, "failed to delete section for target: %s", target);
			free(strtmp);
			return -1;
		}

		struct uci_element *e;
		uci_foreach_element(&uci_ptr.p->sections, e) {
	        struct uci_option *t1, *t2;
			struct uci_section *s = uci_to_section(e);
			// only find cname and domain section
			if (strcmp(s->type, "cname") == 0) {
	        	t1 = uci_lookup_option(ctx, s, "target");
		        t2 = uci_lookup_option(ctx, s, "cname");
			} else if (strcmp(s->type, "domain") == 0) {
	        	t1 = uci_lookup_option(ctx, s, "name");
		        t2 = uci_lookup_option(ctx, s, "ip");
			} else
				continue;

			if(!t1 && !t2)
				continue;

	        if (t1->v.string && strcmp(t1->v.string, b) == 0) {
		        if (t2->v.string && strcmp(t2->v.string, a) == 0) {
					uci_ptr.s = s;
					ret = uci_delete(ctx, &uci_ptr);
					if(!ret) {
						_uci_commit(ctx, &uci_ptr.p);
						break;
					} else
						log_err("%s: failed to delete section: %s [%s] (%d)",
								__func__, s->type, s->e.name, ret);
				}
	        }
		}
	} else {
		bool commit = false;
		int i = 0;
		while(token != NULL && i < 3) // 3 is the max num between cnameRecords and dns.hosts
		{
			if(!strcmp(conf_item->k, "dns.cnameRecords")) {
				if(i == 0) uci_ptr.option = "cname";
				else if(i == 1) uci_ptr.option = "target";
				else if(i == 2) uci_ptr.option = "ttl";
			}
			else if(!strcmp(conf_item->k, "dns.hosts")) {
				if(i == 0) uci_ptr.option = "ip";
				else if(i == 1) uci_ptr.option = "name";
			}

			if(uci_ptr.option) {
				if(!uci_ptr.s) {
					if(uci_add_section(ctx, uci_ptr.p, conf_item->uci.stype, &uci_ptr.s))
						break;
				}

				uci_ptr.value = token;
				ret = uci_set(ctx, &uci_ptr);
				if(!ret)
					commit = true;

				i++;
			}

			token = strtok_r(NULL, delim, &tmp);
		}

		if(i > 1) {
			if(commit)
				_uci_commit(ctx, &uci_ptr.p);
			else
				uci_revert(ctx, &uci_ptr);
		}
	}

	free(strtmp);
	return ret;
}
