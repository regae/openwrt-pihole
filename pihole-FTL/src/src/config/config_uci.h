#ifndef CONFIG_UCI_H
#define CONFIG_UCI_H

#include "config.h"
#include "inotify.h"
#include <uci.h>

int uci_set_value(struct uci_context *ctx, struct conf_item *item,
				  const char *value, bool commit);
int uci_get_value(struct uci_context *ctx, struct conf_item *conf_item);
int uci_foreach_section(struct uci_context *ctx, struct conf_item *conf_item,
					    const char *target, bool delete);
void uci_get_config_values(struct config *conf, bool reload);
void clean_all_leftovers(void);

static inline void
_uci_commit(struct uci_context *ctx, struct uci_package **pkg)
{
	watch_config(false);
	uci_commit(ctx, pkg, false);
	watch_config(true);
}

static inline void
uci_cleanup(struct uci_context *ctx)
{
	uci_free_context(ctx);
}

static inline bool
uci_read_bool(struct uci_context *ctx, struct uci_section *s,
			  const char *opt, const char *fallback)
{
	if (!s)
		return (strcmp(fallback, "1") == 0);

	const char *val = uci_lookup_option_string(ctx, s, opt);
	if(!val)
		return (strcmp(fallback, "1") == 0);

	if(strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0)
		return false;
	else if(strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0)
		return true;

	return (strcmp(fallback, "1") == 0);
}

#endif // CONFIG_UCI_H
