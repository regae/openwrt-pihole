'use strict';
'require fs';
'require ui';
'require rpc';
'require uci';
'require view';
'require poll';
'require form';
'require tools.widgets as widgets';

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('pihole', _('FTLDNS&trade;'));
		m.description = _("<abbr title=\"pihole\'s Faster Than Light daemon\">FTL</abbr>DNS&trade; (pihole-FTL) offers DNS services within the Pi-hole® project. " +
			  "It provides blazing fast DNS and DHCP services. It can also provide TFTP and more as the resolver part based on the popular dnsmasq. " +
			  "Furthermore, FTL offers an interactive API where extensive network analysis data and statistics may be queried. " +
			  "<br><a href=\"https://docs.pi-hole.net/ftldns/configfile/\" target=\"_blank\">FTL Config Documentation</a>.");

		s = m.section(form.TypedSection, 'pihole');
		s.tab("dns", _("DNS Settings"));
		s.tab("database", _("Database"));
		s.tab("statistic", _("Statistic Settings"));
		s.tab("other", _("Others"));
		s.anonymous = true;
		s.addremove = false;

		o = s.taboption("dns", form.ListValue, 'blockingmode', _("Blocking Mode"), _("How should FTL reply to blocked queries?"));
		o.value("null", _("NULL"));
		o.value("ip-nodata-aaaa", _("IPv4 and IPv6 NODATA"));
		o.value("ip", _("IP Addresses"));
		o.value("nxdomain", _("NXDOMAIN"));
		o.default = 'null';

		o = s.taboption('dns', form.Value, 'block_ipv4',
			_('Block IPv4 Address'),
			_('Override Replied IP address for blocked A queries.<br>Leave this empty, FTL will determines the address of the interface a query arrived on and uses this address.'));

		o.optional = true;
		o.rmempty = false;
		o.depends('blockingmode', 'ip');
		o.depends('blockingmode', 'ip-nodata-aaaa');
		o.placeholder = '192.168.1.1';

		o = s.taboption('dns', form.Value, 'block_ipv6',
			_('Block IPv6 Address'),
			_('Override Replied IP address for blocked AAAA queries.'));

		o.optional = true;
		o.rmempty = false;
		o.depends('blockingmode', 'ip');
		o.placeholder = '::1';

		o = s.taboption('dns', form.Flag, 'cname_deep_inspect',
			_('CNAME Deep Inspect'),
			_('Use this option to disable deep CNAME inspection. This might be beneficial for very low-end devices'));
		o.optional = true;

		o = s.taboption('dns', form.Flag, 'block_esni',
			_('Block ESNI'),
			_('This prevents the SNI from being used to determine which websites users are visiting.'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('dns', form.Flag, 'edns0_ecs',
			_('EDNS0 ECS'),
			_('Should we overwrite the query source when client information is provided through EDNS0 client subnet (ECS) information? This allows Pi-hole to obtain client IPs even if they are hidden behind the NAT of a router.'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('dns', form.Flag, 'mozilla_canary',
			_('Mozilla Canary'),
			_('Should Pi-hole always replies with NXDOMAIN to A and AAAA queries of use-application-dns.net to disable Firefox automatic DNS-over-HTTP?'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('dns', form.Flag, 'block_icloud_pr',
			_('Block iCloud Private Relay'),
			_('Should Pi-hole always replies with NXDOMAIN to A and AAAA queries of mask.icloud.com and mask-h2.icloud.com to disable Apple\'s iCloud Private Relay to prevent Apple devices from bypassing Pi-hole?'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('dns', form.Value, 'rate_limit',
			_('Rate Limit'),
			_('Rate-limited queries are answered with a REFUSED reply and not further processed by FTL. (Queries/Minute)'));
		o.optional = true;
		o.rmempty = false;
		o.placeholder = _('1000/60');

		o = s.taboption('dns', form.Value, 'block_ttl',
			_('Block TTL'),
			_('This settings allows users to select a value different from the dnsmasq config option local-ttl.'));
		o.optional = true;
		o.rmempty = false;
		o.datatype = 'and(uinteger)';
		o.placeholder = _('2');

		o = s.taboption('database', form.Value, 'dbfile',
			_('FTL Database'),
			_('Specify the path and filename of FTL\'s SQLite3 long-term database.<br>Empty this value disables the database altogether.'));
		o.optional = true;
		o.rmempty = false;
		o.placeholder = _('/var/lib/pihole/pihole-FTL.db');

		o = s.taboption('database', form.Value, 'gravitydb',
			_('Gravity Database'),
			_('Specify path and filename of FTL\'s SQLite3 gravity database.<br>This database contains all domains relevant for Pi-hole\'s DNS blocking'));
		o.optional = true;
		o.rmempty = false;
		o.placeholder = _('/var/lib/pihole/gravity.db');

		o = s.taboption('database', form.Value, 'dbinterval',
			_('DB Interval (minutes)'),
			_('if running on SD card or SSD, recommended to set DBINTERVAL value to at least 60'));
		o.optional = true;
		o.datatype = 'and(uinteger,min(1),max(3600))';
		o.placeholder = 360;

		o = s.taboption('database', form.Flag, 'dbimport',
			_('DB Import'),
			_('Should FTL load information from the database on startup to be aware of the most recent history?'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('database', form.Value, 'maxdbdays',
			_('Database Days'),
			_('How long should queries be stored in the database? Setting this to 0 disables the database'));
		o.optional = true;
		o.rmempty = false;
		o.datatype = 'and(uinteger,min(1),max(365))';
		o.placeholder = 365;

		o = s.taboption("statistic", form.ListValue, 'privacylevel', _("Privacy Level"));
		o.value("0", _("Show Everything"));
		o.value("1", _("Hide Domains"));
		o.value("2", _("Hide Domains and Clients"));
		o.value("3", _("Anonymous Everyting"));
		o.default = '0';

		o = s.taboption('statistic', form.Value, 'maxlogage',
			_('Statistic Age (hour)'),
			_('Up to how many hours of queries should be imported from the database and logs?'));
		o.optional = true;
		o.rmempty = false;
		o.datatype = 'and(uinteger,min(1),max(24))';
		o.placeholder = 24;

		o = s.taboption('statistic', form.Flag, 'analyze_only_a_and_aaaa',
			_('Analyze Only A & AAAA'),
			_('Should FTL only analyze A and AAAA queries?'));
		o.optional = true;

		o = s.taboption('statistic', form.Flag, 'aaaa_query_analysis',
			_('Analyze AAAA Queries'),
			_('Should FTL analyze AAAA queries? The DNS server will handle AAAA queries the same way, reglardless of this setting.'));
		o.optional = true;

		o = s.taboption('statistic', form.Flag, 'show_dnssec',
			_('Show DNSSEC'),
			_('Should FTL analyze and include automatically generated DNSSEC queries in the Query Log?'));
		o.optional = true;
		o.default = o.disabled;

		s.taboption('statistic', form.Flag, 'ignore_localhost',
			_('Ignore Localhost'),
			_('Should FTL ignore queries coming from the local machine?'));
		o.optional = true;

		o = s.taboption('other', form.Flag, 'resolve_ipv4',
			_('Resolve IPv4'),
			_('Should FTL try to resolve IPv4 addresses to host names?'));
		o.optional = true;

		o = s.taboption('other', form.Flag, 'resolve_ipv4',
			_('Resolve IPv6'),
			_('Should FTL try to resolve IPv6 addresses to host names?'));
		o.optional = true;

		o = s.taboption('other', form.Value, 'ftlport',
			_('FTL Socket Port'),
			_('On which port should FTL be listening?'));
		o.optional = true;
		o.rmempty = false;
		o.datatype = 'and(uinteger,min(1),max(65534))';
		o.placeholder = 4711;

		o = s.taboption("other", form.ListValue, 'pihole_ptr', _("Pihole PTR"), _("Controls whether and how FTL will reply with for address for which a local interface exists."));
		o.value("pi.hole", _("pi.hole"));
		o.value("hostnamefqdn", _("Hostname FQDN"));
		o.value("hostname", _("Hostname"));
		o.value("none", _("None"));
		o.rmempty = false;
		o.default = 'hostname';

		o = s.taboption("other", form.ListValue, 'socket_listening', _("Socket Listening"), _("Listen only for local socket connections or permit all connections."));
		o.value("local", _("Local"));
		o.value("all", _("All"));
		o.default = 'local';

		o = s.taboption("other", form.ListValue, 'refresh_hostnames', _("Refresh Hostnames"), _("Change how hourly PTR requests are made to check for changes in client and upstream server hostnames."));
		o.value("ipv4", _("IPv4"));
		o.value("all", _("All"));
		o.value("unknown", _("Unknown"));
		o.value("none", _("None"));
		o.default = 'ipv4';

		o = s.taboption('other', form.Flag, 'parse_arp_cache',
			_('Parse ARP Cache'),
			_('This setting can be used to disable ARP cache processing. When disabled, client identification and the network table will stop working reliably.'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('other', form.Flag, 'names_from_netdb',
			_('Names from Database'),
			_('Control whether FTL should use the fallback option to try to obtain client names from network table.'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('other', form.Flag, 'check_load',
			_('Check System Load'),
			_('FTL warns about excessive load when the 15 minute system load average exceeds the number of cores.'));
		o.optional = true;
		o.default = o.enabled;

		o = s.taboption('other', form.Value, 'check_shmem',
			_('Check Shared Memory'),
			_('FTL warns if the shared-memory usage exceeds this value (percentage).'));
		o.optional = true;
		o.rmempty = false;
		o.datatype = 'and(uinteger,min(1),max(100))';
		o.placeholder = 90;

		o = s.taboption('other', form.Value, 'check_disk',
			_('Check Disk Usage'),
			_('FTL warns if the disk-usage usage exceeds this value (percentage).'));
		o.optional = true;
		o.rmempty = false;
		o.datatype = 'and(uinteger,min(1),max(100))';
		o.placeholder = 90;

		return m.render();
	}
})
