// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 * Lukas Märdian <lukas.maerdian@canonical.com>
 *
 * Copyright (C) 2019-2020 Canonical Ltd..
 */

#include "nm-default.h"

#include "nms-netplan-reader.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <netplan/parse.h>

#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-connection.h"
#include "nm-dbus-interface.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-vlan.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bond.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-bridge.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-dcb.h"
#include "nm-setting-user.h"
#include "nm-setting-proxy.h"
#include "nm-setting-generic.h"
#include "nm-core-internal.h"
#include "nm-utils.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

#include "platform/nm-platform.h"
#include "NetworkManagerUtils.h"

#include "nms-netplan-utils.h"

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SETTINGS
#define _NMLOG_PREFIX_NAME "netplan"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), NULL, NULL, \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME": " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

#define PARSE_WARNING(...) _LOGW ("%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), "    " _NM_UTILS_MACRO_REST(__VA_ARGS__))

/*****************************************************************************/

static void
check_if_bond_slave (NetplanNetDefinition *nd, NMSettingConnection *s_con)
{
	const char *v;
	const char *master;

	v = nd->bond;
	if (v) {
		master = nm_setting_connection_get_master (s_con);
		if (master) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring master \"%s\"",
			               master, v);
			return;
		}

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, v,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
		              NULL);
	}
}

#if 0  /* TODO: Implement (read) Team support  */
NM_SETTING_CONNECTION_MASTER
NM_SETTING_CONNECTION_SLAVE_TYPE (NM_SETTING_TEAM_SETTING_NAME)
static void
check_if_team_slave (NetplanNetDefinition *nd, NMSettingConnection *s_con)
#endif

static char *
make_connection_name (NetplanNetDefinition *nd,
                      const char *netplan_name,
                      const char *suggested,
                      const char *prefix)
{
	char *full_name = NULL, *name;

	/* If the NetworkManager backend already has a NAME, use that */
	name = nd->backend_settings.nm.name;
	if (nm_str_not_empty(name))
		return name;

	/* Otherwise construct a new NAME */
	/* XXX: Should we stick to netplan's "netplan-IFNAME[-SSID]" naming scheme? */
	if (!prefix)
		prefix = "System";

	/* For cosmetic reasons, if the suggested name is the same as
	 * the netplan files name, don't use it.  Mainly for wifi so that
	 * the SSID is shown in the connection ID instead of just "wlan0".
	 */
	if (suggested && strcmp (netplan_name, suggested))
		full_name = g_strdup_printf ("%s %s (%s)", prefix, suggested, netplan_name);
	else
		full_name = g_strdup_printf ("%s %s", prefix, netplan_name);

	return full_name;
}

static NMSetting *
make_connection_setting (const char *file,
                         NetplanNetDefinition *nd,
                         const char *type,
                         const char *suggested,
                         const char *prefix)
{
	NMSettingConnection *s_con;
	//NMSettingConnectionLldp lldp;
	const char *netplan_name = NULL;
	gs_free char *new_id = NULL;
	const char *uuid;
	gs_free char *uuid_free = NULL;
	const char *v;
	gs_free char *stable_id = NULL;
	//const char *const *iter;
	//int vint64, i_val;

	netplan_name = utils_get_netplan_name (file);
	if (!netplan_name)
		return NULL;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	new_id = make_connection_name (nd, netplan_name, suggested, prefix);
	g_assert_nonnull (nm_str_not_empty(new_id));
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, new_id, NULL);

	/* Try for a UUID key before falling back to hashing the file name */
	uuid = nd->backend_settings.nm.uuid;
	if (!uuid) {
		uuid_free = nm_utils_uuid_generate_from_string (netplan_name, -1, NM_UTILS_UUID_TYPE_LEGACY, NULL);
		uuid = uuid_free;
	}

	stable_id = nd->backend_settings.nm.stable_id ?: NULL;
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_STABLE_ID, stable_id,
	              NULL);

	/* Get iface/device name from NM backend settings. If missing, fall back to netdef ID. */
	v = nd->backend_settings.nm.device;
	if (!v && nm_utils_is_valid_iface_name (nd->id, NULL))
		v = nd->id;
	if (v) {
		GError *error = NULL;

		if (nm_utils_is_valid_iface_name (v, &error)) {
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_INTERFACE_NAME, v,
			              NULL);
		} else {
			PARSE_WARNING ("invalid DEVICE name '%s': %s", v, error->message);
			g_error_free (error);
		}
	}

#if 0  /* TODO: handle LLDP, ONBOOT (autoconnect) settings for NM */
NM_SETTING_CONNECTION_AUTOCONNECT
NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY
NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES
NM_SETTING_CONNECTION_MULTI_CONNECT
NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES
NM_SETTING_CONNECTION_LLDP
#endif

#if 0  /* TODO: User permissions handling in netplan syntax */
nm_setting_connection_add_permission (s_con, "user", *iter, NULL);
#endif

#if 0  /* TODO: Support ZONE (firewall), Secondary UUIDs, etc. */
NM_SETTING_CONNECTION_ZONE
nm_setting_connection_add_secondary (s_con, *iter);
#endif

	v = nd->bridge;
	if (v) {
		const char *old_value;

		if ((old_value = nm_setting_connection_get_master (s_con))) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring master \"%s\"",
			               old_value, v);
		} else {
			g_object_set (s_con,
			              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
			              NM_SETTING_CONNECTION_MASTER, v,
			              NULL);
		}
	}

	check_if_bond_slave (nd, s_con);
	//check_if_team_slave (nd, s_con);

#if 0  /* TODO: OVS support */
NM_SETTING_CONNECTION_MASTER
NM_SETTING_CONNECTION_SLAVE_TYPE (NM_SETTING_OVS_PORT_SETTING_NAME)
#endif

#if 0  /* TODO: more random settings that are NM-specific */
NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT
NM_SETTING_CONNECTION_METERED
NM_SETTING_CONNECTION_AUTH_RETRIES
NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT
NM_SETTING_CONNECTION_MDNS
#endif

#if 0  /* TODO: LLMNR settings support */
NM_SETTING_CONNECTION_LLMNR
#endif

	return NM_SETTING (s_con);
}

#if 0  /* TODO: Parse through the GArray of addresses and pick just the ipv4 (static addresses) */
static gboolean
read_ip4_address (NetplanNetDefinition *nd, const char *tag, gboolean *out_has_key, guint32 *out_addr, GError **error)
static gboolean
is_any_ip4_address_defined (NetplanNetDefinition *nd, int *idx)
#endif

/*****************************************************************************/

#if 0
static void
parse_dns_options (NMSettingIPConfig *ip_config, const char *value)
{
	gs_free const char **options = NULL;
	const char *const *item;

	g_return_if_fail (ip_config);

	if (!value)
		return;

	if (!nm_setting_ip_config_has_dns_options (ip_config))
		nm_setting_ip_config_clear_dns_options (ip_config, TRUE);

	options = nm_utils_strsplit_set (value, " ");
	if (options) {
		for (item = options; *item; item++) {
			if (!nm_setting_ip_config_add_dns_option (ip_config, *item))
				PARSE_WARNING ("can't add DNS option '%s'", *item);
		}
	}
}
#endif

#if 0
static gboolean
parse_full_ip6_address (NetplanNetDefinition *nd,
                        const char *addr_str,
                        int i,
                        NMIPAddress **out_address,
                        GError **error)
{
	NMIPAddress *addr;
	NMIPAddr addr_bin;
	int prefix;

	nm_assert (addr_str);
	nm_assert (out_address && !*out_address);
	nm_assert (!error || !*error);

	if (!nm_utils_parse_inaddr_prefix_bin (AF_INET6,
	                                       addr_str,
	                                       NULL,
	                                       &addr_bin,
	                                       &prefix)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid IP6 address '%s'", addr_str);
		return FALSE;
	}

	if (prefix < 0)
		prefix = 64;

	addr = nm_ip_address_new_binary (AF_INET6, &addr_bin, prefix, error);
	if (!addr)
		return FALSE;

	*out_address = addr;
	return TRUE;
}
#endif

#if 0   /* TODO: Support user settings in netplan schema */
static NMSetting *
make_user_setting (NetplanNetDefinition *nd)

nms_netplan_utils_user_key_decode (key + NM_STRLEN ("NM_USER_"), str)
s_user = NM_SETTING_USER (nm_setting_user_new ());
nm_setting_user_set_data (s_user, str->str, value, NULL))
#endif /* user settings */

static NMSetting *
make_match_setting (NetplanNetDefinition *nd)
{
	NMSettingMatch *s_match = NULL;
	const char *v;

	s_match = (NMSettingMatch *) nm_setting_match_new ();

	v = nd->match.original_name;
	if (!nd->has_match || !v)
		return NULL;

	nm_setting_match_add_interface_name (s_match, v);

	return (NMSetting *) s_match;
}

#if 0  /* TODO: proxy support */
static NMSetting *
make_proxy_setting (NetplanNetDefinition *nd)

s_proxy = (NMSettingProxy *) nm_setting_proxy_new ();
NM_SETTING_PROXY_METHOD
NM_SETTING_PROXY_PAC_URL
NM_SETTING_PROXY_PAC_SCRIPT
NM_SETTING_PROXY_BROWSER_ONLY
#endif

static void
make_routes (NetplanNetDefinition *nd, NMSettingIPConfig *s_ip, guint family)
{
	NMIPRoute *route = NULL;
	GError *local = NULL;

	for (unsigned i = 0; i < nd->routes->len; ++i) {
		NetplanIPRoute *r = g_array_index(nd->routes, NetplanIPRoute*, i);
		if (r->family != family)
			continue;
		gchar** ipmask = g_strsplit (r->to, "/", 2);
		route = nm_ip_route_new (r->family, ipmask[0], atoi(ipmask[1]), r->via, r->metric, &local);
		// TODO: implement route attributes
		//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_WINDOW, g_variant_new_uint32 (3455));
		//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_ONLINK, g_variant_new_boolean(r.onlink));
		g_assert_no_error (local);
		nm_setting_ip_config_add_route (s_ip, route);
		nm_ip_route_unref (route);
	}
}

static NMSetting *
make_ip4_setting (NetplanNetDefinition *nd, GError **error)
{
	gs_unref_object NMSettingIPConfig *s_ip4 = NULL;
	gs_free char *route_path = NULL;
	gs_free char *value = NULL;
	gs_free char *dns_options_free = NULL;
	NMIPAddress *addr;
	gs_free char *gateway = NULL;
	GError *local = NULL;
	char *method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();

#if 0  /* TODO: Review defroute magic for never-default */
NM_SETTING_IP4_CONFIG_METHOD_*
ifcfg-rh:
DEFROUTE
DEVICE
GATEWAYDEV
RES_OPTIONS
BOOTPROTO
IPV4_ROUTE_TABLE
#endif

	if (nd->ip4_addresses)
		method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;

	if (nd->gateway4)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_GATEWAY, nd->gateway4, NULL);

	/* TODO: map real values for ipv4 -- method + options */
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, FALSE,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, FALSE,
	              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, FALSE,
	              //NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
	              //NM_SETTING_IP_CONFIG_ROUTE_METRIC, 100,
	              NM_SETTING_IP_CONFIG_ROUTE_TABLE, 0,
	              NULL);

	//if (nm_streq (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED))
	//	return NM_SETTING (g_steal_pointer (&s_ip4));

	/* Handle DHCP settings */
	if (nd->dhcp4 && nd->dhcp4_overrides.hostname)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, nd->dhcp4_overrides.hostname, NULL);
	if (nd->dhcp4 && !nd->dhcp4_overrides.send_hostname)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, FALSE, NULL);
#if 0
NM_SETTING_IP_CONFIG_DHCP_TIMEOUT
NM_SETTING_IP4_CONFIG_DHCP_FQDN
NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID
#endif

	/* Read static IP addresses.
	 * Read them even for AUTO method - in this case the addresses are
	 * added to the automatic ones. Note that this is not currently supported by
	 * the legacy 'network' service (ifup-eth).
	 */
	if (nd->ip4_addresses) {
		for (unsigned i = 0; i < nd->ip4_addresses->len; ++i) {
			gchar** ipmask = g_strsplit (g_array_index(nd->ip4_addresses, char*, i), "/", 2);
			addr = nm_ip_address_new (AF_INET, ipmask[0], atoi(ipmask[1]), &local);
			g_assert_no_error (local);
			nm_setting_ip_config_add_address (s_ip4, addr);
			nm_ip_address_unref (addr);
		}
	}

#if 0
	if (gateway && never_default)
		PARSE_WARNING ("GATEWAY will be ignored when DEFROUTE is disabled");
#endif

	if (nd->ip4_nameservers)
		for (unsigned i = 0; i < nd->ip4_nameservers->len; ++i)
			nm_setting_ip_config_add_dns (s_ip4,
										  g_array_index(nd->ip4_nameservers, char*, i));

	if (nd->search_domains)
		for (unsigned i = 0; i < nd->search_domains->len; ++i)
			nm_setting_ip_config_add_dns_search (s_ip4,
												 g_array_index(nd->search_domains, char*, i));

#if 0  /* TODO: Implement read for connection sharing. */
NM_SETTING_IP4_CONFIG_METHOD_SHARED
nm_setting_ip_config_add_dns (s_ip4, v)
nm_setting_ip_config_add_dns_search (s_ip4, *item)
ifcfg-rh:
DNS
DOMAIN
RES_OPTIONS
#endif

#if 0  /* TODO: DNS priority */
NM_SETTING_IP_CONFIG_DNS_PRIORITY
#endif

	if (nd->routes)
		make_routes(nd, s_ip4, AF_INET);

#if 0 /* TODO: dad-timeout */
NM_SETTING_IP_CONFIG_DAD_TIMEOUT
#endif

	return NM_SETTING (g_steal_pointer (&s_ip4));
}

static NMSetting *
make_ip6_setting (NetplanNetDefinition *nd, GError **error)
{
	gs_unref_object NMSettingIPConfig *s_ip6 = NULL;
	gs_free char *value = NULL;
	gs_free const char **list = NULL;
	char *method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
	NMIPAddress *addr6;
	GError *local = NULL;
#if 0
	const char *v;
	gboolean ipv6init;
	gboolean ipv6forwarding;
	gboolean disabled;
	gboolean dhcp6 = FALSE;
	const char *ipv6addr, *ipv6addr_secondaries;
	gs_free char *ipv6addr_to_free = NULL;
	gs_free char *ipv6addr_secondaries_to_free = NULL;
	const char *const *iter;
	guint32 i;
	int i_val;
	int priority;
	gboolean never_default = FALSE;
	gboolean ip6_privacy = FALSE, ip6_privacy_prefer_public_ip;
	NMSettingIP6ConfigPrivacy ip6_privacy_val;
	guint32 route_table;
#endif

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();

#if 0  /* TODO: never-default for ipv6 */
ifcfg-rh:
IPV6_DEFROUTE
#endif

#if 0  /* TODO: ipv6 gateway and all */
ifcfg-rh:
DEVICE
IPV6_DEFAULTGW
IPV6_DEFAULTDEV
IPV6_DISABLED
IPV6INIT
#endif

#if 0  /* TODO: ipv6 config methods */
NM_SETTING_IP6_CONFIG_METHOD_*
NM_SETTING_IP6_CONFIG_PRIVACY_*
ifcfg-rh:
IPV6FORWARDING
DHCPV6C
IPV6_AUTOCONF
IPV6ADDR
IPV6ADDR_SECONDARIES
IPV6_PRIVACY
IPV6_PRIVACY_PREFER_PUBLIC_IP
IPV6_ROUTE_TABLE
#endif

	/* Skip if we have neither static nor dynamic IP6 config */
	if (!nd->ip6_addresses && !nd->dhcp6) {
		g_object_set (s_ip6,
		              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		              NULL);
		return NM_SETTING (g_steal_pointer (&s_ip6));
	}

	if (nd->ip6_addresses)
		method = NM_SETTING_IP6_CONFIG_METHOD_MANUAL;

	if (nd->gateway6)
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_GATEWAY, nd->gateway6, NULL);

	// TODO: make a real s_ip6 object (map from the real values, not just DHCP)
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, method,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, FALSE,
	              NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, FALSE,
	              NM_SETTING_IP_CONFIG_NEVER_DEFAULT, FALSE,
	              //NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
	              //NM_SETTING_IP_CONFIG_ROUTE_METRIC, 100,
	              NM_SETTING_IP_CONFIG_ROUTE_TABLE, 0,
	              NM_SETTING_IP6_CONFIG_IP6_PRIVACY, NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
	              NULL);

#if 0  /* TODO: Don't bother to read IP, DNS and routes when IPv6 is disabled */
	if (NM_IN_STRSET (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	                          NM_SETTING_IP6_CONFIG_METHOD_DISABLED))
		return NM_SETTING (g_steal_pointer (&s_ip6));
#endif

	/* Handle DHCP settings */
	if (nd->dhcp6 && nd->dhcp6_overrides.hostname)
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, nd->dhcp6_overrides.hostname, NULL);
	if (nd->dhcp6 && !nd->dhcp6_overrides.send_hostname)
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, FALSE, NULL);

#if 0  /* TODO: Implement IPv6 DUID, hostname and special DHCP options */
NM_SETTING_IP6_CONFIG_DHCP_DUID
NM_SETTING_IP6_CONFIG_METHOD_*
NM_SETTING_IP_CONFIG_DHCP_HOSTNAME
NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME
ifcfg-rh:
DHCPV6_DUID
DHCPV6_HOSTNAME
DHCP_HOSTNAME
DHCPV6_SEND_HOSTNAME
#endif

	/* Read static IP addresses. */
	if (nd->ip6_addresses) {
		for (unsigned i = 0; i < nd->ip6_addresses->len; ++i) {
			gchar** ipmask = g_strsplit (g_array_index(nd->ip6_addresses, char*, i), "/", 2);
			addr6 = nm_ip_address_new (AF_INET6, ipmask[0], atoi(ipmask[1]), &local);
			g_assert_no_error (local);
			nm_setting_ip_config_add_address (s_ip6, addr6);
			nm_ip_address_unref (addr6);
		}
	}

	if (nd->ip6_nameservers)
		for (unsigned i = 0; i < nd->ip6_nameservers->len; ++i)
			nm_setting_ip_config_add_dns (s_ip6,
										  g_array_index(nd->ip6_nameservers, char*, i));

#if 0  /* TODO: IPv6: read static addresses. */
parse_full_ip6_address (netplan, *iter, i, &addr, error)
nm_setting_ip_config_add_address (s_ip6, addr)
ifcfg-rh:
IPV6ADDR
IPV6ADDR_SECONDARIES
#endif

#if 0  /* IPv6: read gateway. */
nm_setting_ip_config_get_num_addresses (s_ip6)
NM_SETTING_IP_CONFIG_GATEWAY
NM_SETTING_IP6_CONFIG_TOKEN
ifcfg-rh:
IPV6_DEFAULTGW
IPV6_TOKEN
#endif

	/* IPv6 Address generation mode */
	if (nd->ip6_addr_gen_mode == NETPLAN_ADDRGEN_STABLEPRIVACY)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
					  NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY, NULL);
	else if (nd->ip6_addr_gen_mode == NETPLAN_ADDRGEN_EUI64)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
		              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64, NULL);

#if 0  /* TODO: set dns servers */
nm_setting_ip_config_add_dns (s_ip6, v)
ifcfg-rh:
DNS
#endif

	if (nd->routes)
		make_routes(nd, s_ip6, AF_INET6);

#if 0  /* TODO: IPv6 DNS searches */
nm_setting_ip_config_add_dns_search (s_ip6, *iter)
NM_SETTING_IP_CONFIG_DNS_PRIORITY
ifcfg-rh:
IPV6_DOMAIN
IPV6_RES_OPTIONS
IPV6_DNS_PRIORITY
#endif

	return NM_SETTING (g_steal_pointer (&s_ip6));
}

/* TODO: Implement SRIOV support */
/* TODO: Implement TC support */
/* TODO: Implement DCB support */
/* There is useful code to look at in ifcfg-rh plugin ~cyphermox */

#if 0 /* TODO: Netplan doesn't really support WEP right now */
static gboolean
add_one_wep_key (NetplanNetDefinition *nd, const char *shvar_key, guint8 key_idx, gboolean passphrase, NMSettingWirelessSecurity *s_wsec, GError **error)

nm_setting_wireless_security_set_wep_key (s_wsec, key_idx, key);


static gboolean
read_wep_keys (NetplanNetDefinition *nd, NMWepKeyType key_type, guint8 def_idx, NMSettingWirelessSecurity *s_wsec, GError **error)

NM_WEP_KEY_TYPE_PASSPHRASE
add_one_wep_key (nd, "KEY1", 0, FALSE, s_wsec, error)
NM_WEP_KEY_TYPE_KEY
add_one_wep_key (nd, "KEY_PASSPHRASE1", 0, TRUE, s_wsec, error)
#endif

#if 0 /* TODO: Implement WEP in netplan */
static NMSetting *
make_wep_setting (NetplanNetDefinition *nd, const char *file, GError **error)

s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
NM_SETTING_WIRELESS_SECURITY_KEY_MGMT
NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX
NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS
NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE
NM_SETTING_WIRELESS_SECURITY_AUTH_ALG
nm_setting_wireless_security_set_wep_key (s_wsec, 0, nd->auth.password);
#endif

static gboolean
fill_wpa_ciphers (NetplanNetDefinition *nd,
                  NMSettingWirelessSecurity *wsec,
                  gboolean group,
                  gboolean adhoc)
{
#if 0  /* TODO: WPA ciphers selection (not yet in netplan) */
nm_setting_wireless_security_add_group (wsec, "ccmp");
nm_setting_wireless_security_add_pairwise (wsec, "ccmp");
nm_setting_wireless_security_add_group (wsec, "tkip");
nm_setting_wireless_security_add_pairwise (wsec, "tkip");
nm_setting_wireless_security_add_group (wsec, "wep104");
nm_setting_wireless_security_add_group (wsec, "wep40");
ifcfg-rh:
CIPHER_GROUP
CIPHER_PAIRWISE
#endif
	return TRUE;
}

#define WPA_PMK_LEN 32

static char *
parse_wpa_psk (NetplanWifiAccessPoint *ap,
               const char *file,
               GBytes *ssid,
               GError **error)
{
	gs_free char *psk = NULL;
	size_t plen;

	/* Passphrase must be between 10 and 66 characters in length because WPA
	 * hex keys are exactly 64 characters (no quoting), and WPA passphrases
	 * are between 8 and 63 characters (inclusive), plus optional quoting if
	 * the passphrase contains spaces.
	 */
	psk = ap->auth.password;

	if (!psk)
		return NULL;

	plen = strlen (psk);

	if (g_str_has_prefix(psk, "hash:") && plen == 69) {
		/* Verify the hex PSK; 64 digits + 5 for "hash:" */
		if (!NM_STRCHAR_ALL (psk+5, ch, g_ascii_isxdigit (ch))) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid WPA_PSK (contains non-hexadecimal characters)");
			return NULL;
		}
	} else {
		if (plen < 8 || plen > 63) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid WPA_PSK (passphrases must be between "
			             "8 and 63 characters long (inclusive))");
			return NULL;
		}
	}

	return g_steal_pointer (&psk);
}

static NMSetting8021x *
fill_8021x (NetplanNetDefinition *nd,
            NetplanWifiAccessPoint *ap,
            const char *file,
            const char *key_mgmt,
            gboolean wifi,
            GError **error)
{
	gs_unref_object NMSetting8021x *s_8021x = NULL;
	NetplanAuthEAPMethod method = NETPLAN_AUTH_EAP_NONE;
	const char *value = NULL, *pass = NULL;
	NetplanAuthenticationSettings auth = nd->auth;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();

	if (wifi && ap) {
		auth = ap->auth;
	}

	// TODO: read 802.1x settings from hashtable keys (just mapping values already in netplan structures)
	method = auth.eap_method;
	switch (method) {
		case NETPLAN_AUTH_EAP_TLS:
			nm_setting_802_1x_add_eap_method (s_8021x, "tls");
			break;
		case NETPLAN_AUTH_EAP_PEAP:
			nm_setting_802_1x_add_eap_method (s_8021x, "peap");
			break;
		case NETPLAN_AUTH_EAP_TTLS:
			nm_setting_802_1x_add_eap_method (s_8021x, "ttls");
			break;
		default:
			// TODO: set a corresponding error/warning
			return NULL;
	}

	value = auth.phase2_auth;
	if (value)
		g_object_set (s_8021x, NM_SETTING_802_1X_PHASE2_AUTH, value, NULL);

	value = auth.identity;
	if (value)
		g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, value, NULL);

	value = auth.anonymous_identity;
	if (value)
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, value, NULL);

	value = auth.password;
	if (value)
		g_object_set (s_8021x, NM_SETTING_802_1X_PASSWORD, value, NULL);


	value = auth.ca_certificate;
	if (value)
		nm_setting_802_1x_set_ca_cert (s_8021x,
		                               value,
		                               NM_SETTING_802_1X_CK_SCHEME_PATH,
		                               NULL,
		                               error);

	value = auth.client_certificate;
	if (value)
		nm_setting_802_1x_set_client_cert (s_8021x,
		                                   value,
		                                   NM_SETTING_802_1X_CK_SCHEME_PATH,
		                                   NULL,
		                                   error);

	value = auth.client_key;
	pass = auth.client_key_password;
	if (value && pass)
		nm_setting_802_1x_set_private_key (s_8021x,
	                                       value,
	                                       pass,
	                                       NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                       NULL,
	                                       error);

	return g_steal_pointer (&s_8021x);
}

static NMSetting *
make_wpa_setting (NetplanNetDefinition *nd,
                  const char *file,
                  GBytes *ssid,
                  gboolean adhoc,
                  NMSetting8021x **s_8021x,
                  GError **error)
{
	gs_unref_object NMSettingWirelessSecurity *wsec = NULL;
	gs_free char *value = NULL;
	const char *v;
	//int i_val;
	GError *local = NULL;
	GHashTableIter iter;
	gpointer key, val;

	g_hash_table_iter_init (&iter, nd->access_points);
	g_hash_table_iter_next (&iter, &key, &val);
	if (val) {
		NetplanWifiAccessPoint *ap = (NetplanWifiAccessPoint *) val;

		wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

		if (ap->auth.key_management != NETPLAN_AUTH_KEY_MANAGEMENT_WPA_PSK
			&& ap->auth.key_management != NETPLAN_AUTH_KEY_MANAGEMENT_WPA_EAP
			&& ap->auth.key_management != NETPLAN_AUTH_KEY_MANAGEMENT_8021X)
			return NULL; /* Not WPA or Dynamic WEP */

#if 0  /* TODO: support WPS */
nm_setting_wireless_security_wps_method_get_type ()
NM_SETTING_WIRELESS_SECURITY_WPS_METHOD
ifcfg-rh:
WPS_METHOD
#endif

		/* Pairwise and Group ciphers (only relevant for WPA/RSN) */
		if (ap->auth.key_management == NETPLAN_AUTH_KEY_MANAGEMENT_WPA_PSK
			|| ap->auth.key_management == NETPLAN_AUTH_KEY_MANAGEMENT_WPA_EAP) {
			fill_wpa_ciphers (nd, wsec, FALSE, adhoc);
			fill_wpa_ciphers (nd, wsec, TRUE, adhoc);
		}

		/* Adhoc only supports RSN */
		if (adhoc)
			nm_setting_wireless_security_add_proto (wsec, "rsn");
		/* Else: Stay with the default, i.e.: wpa;rsn; */

		if (ap->auth.key_management == NETPLAN_AUTH_KEY_MANAGEMENT_WPA_PSK) {
			if (ap->auth.password) {
				gs_free char *psk = NULL;
				psk = parse_wpa_psk (val, file, ssid, &local);
				if (psk)
					g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_PSK, psk, NULL);
				else if (local) {
					g_propagate_error (error, local);
					return NULL;
				}
			}
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", NULL);
		} else {
			*s_8021x = fill_8021x (nd, ap, file, v, TRUE, &local);
			if (!*s_8021x) {
				g_propagate_error (error, local);
				return NULL;
			}
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
		}
	} else {
		*s_8021x = fill_8021x (nd, NULL, file, v, TRUE, error);
		if (!*s_8021x)
			return NULL;
	}
	/* TODO: support WPA PMF, FILS */

#if 0
NM_SETTING_WIRELESS_SECURITY_AUTH_ALG
ifcfg-rh:
SECURITYMODE
#endif

	return (NMSetting *) g_steal_pointer (&wsec);
}

#if 0  /* TODO: LEAP not yet supported in netplan yaml */
static NMSetting *
make_leap_setting (NetplanNetDefinition *nd, const char *file, GError **error)

wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS
NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD
NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME
NM_SETTING_WIRELESS_SECURITY_KEY_MGMT ("ieee8021x")
NM_SETTING_WIRELESS_SECURITY_AUTH_ALG ("leap")
ifcfg-rh:
IEEE_8021X_PASSWORD
IEEE_8021X_IDENTITY
#endif

static NMSetting *
make_wireless_security_setting (NetplanNetDefinition *nd,
                                const char *file,
                                GBytes *ssid,
                                gboolean adhoc,
                                NMSetting8021x **s_8021x,
                                GError **error)
{
	NMSetting *wsec;

	g_return_val_if_fail (error && !*error, NULL);

#if 0  /* TODO: LEAP support */
	if (!adhoc) {
		wsec = make_leap_setting (netplan, file, error);
		if (wsec)
			return wsec;
		else if (*error)
			return NULL;
	}
#endif

	/* Handle key-management = 'psk', 'eap' or '802.1x' */
	wsec = make_wpa_setting (nd, file, ssid, adhoc, s_8021x, error);
	if (wsec)
		return wsec;
	else if (*error)
		return NULL;

#if 0  /* TODO: WEP is not supported with netplan. */
	 *   Only 'none', 'psk', 'eap' and '802.1x' as handled by make_wpa_setting().
	wsec = make_wep_setting (nd, file, error);
	if (wsec)
		return wsec;
	else if (*error)
		return NULL;
#endif

	return NULL; /* unencrypted, open network */
}

static NMSetting *
make_wireless_setting (NetplanNetDefinition *nd,
                       GError **error)
{
	NMSettingWireless *s_wireless;
	//const char *cvalue;
	//gint64 chan = 0;
	//NMSettingMacRandomization mac_randomization;
	//NMSettingWirelessPowersave powersave = NM_SETTING_WIRELESS_POWERSAVE_DEFAULT;
	GHashTableIter iter;
	gpointer key, value;

	s_wireless = NM_SETTING_WIRELESS (nm_setting_wireless_new ());

	value = nd->set_mac;
	if (value) {
		value = g_strstrip (value);
		g_object_set (s_wireless, NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, value, NULL);
		g_free (value);
	}

	value = nd->match.mac;
	if (value)
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MAC_ADDRESS, value, NULL);

	if (nd->wowlan > NM_SETTING_WIRELESS_WAKE_ON_WLAN_NONE)
		g_object_set (s_wireless, NM_SETTING_WIRELESS_WAKE_ON_WLAN, nd->wowlan, NULL);

	g_hash_table_iter_init (&iter, nd->access_points);
	g_hash_table_iter_next (&iter, &key, &value);
	if (value) {
		NetplanWifiAccessPoint *ap = (NetplanWifiAccessPoint *) value;
		gs_unref_bytes GBytes *bytes = NULL;
		gsize ssid_len = 0;
		gsize value_len = strlen (ap->ssid);
		//char *lcase;
		const char *mode, *band = NULL;

		if (   value_len > 2
		    && (value_len % 2) == 0
		    && g_str_has_prefix (ap->ssid, "0x")
		    && NM_STRCHAR_ALL (&(ap->ssid[2]), ch, g_ascii_isxdigit (ch))) {
			/* interpret the value as hex-digits iff value starts
			 * with "0x" followed by pairs of hex digits */
			bytes = nm_utils_hexstr2bin (&(ap->ssid[2]));
		} else
			bytes = g_bytes_new (ap->ssid, value_len);

		ssid_len = g_bytes_get_size (bytes);
		if (ssid_len > 32 || ssid_len == 0) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid SSID '%s' (size %zu not between 1 and 32 inclusive)",
			             ap->ssid, ssid_len);
			goto error;
		}

		g_object_set (s_wireless, NM_SETTING_WIRELESS_SSID, bytes, NULL);

		/* Read WiFi mode */
		if (ap->mode == NETPLAN_WIFI_MODE_INFRASTRUCTURE) {
			mode = "infrastructure";
		} else if (ap->mode == NETPLAN_WIFI_MODE_ADHOC) {
			mode = "adhoc";
		} else if (ap->mode == NETPLAN_WIFI_MODE_AP) {
			mode = "ap";
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid mode '%d' (not 'adhoc', 'ap', or 'infrastructure')",
			             ap->mode);
			goto error;
		}
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MODE, mode, NULL);

		/* Read BSSID ("MAC" for picking a specific AP) */
		if (ap->bssid)
			g_object_set (s_wireless, NM_SETTING_WIRELESS_BSSID, ap->bssid, NULL);

		/* Read WiFi band and corresponding channel */
		if (ap->band == NETPLAN_WIFI_BAND_DEFAULT)
			band = NULL;
		else if (ap->band == NETPLAN_WIFI_BAND_5) {
			band = "a";
			/* Set channel for selected band, if set */
			if (ap->channel)
				g_object_set (s_wireless, NM_SETTING_WIRELESS_CHANNEL, ap->channel, NULL);
		} else if (ap->band == NETPLAN_WIFI_BAND_24) {
			band = "bg";
			/* Set channel for selected band, if set */
			if (ap->channel)
				g_object_set (s_wireless, NM_SETTING_WIRELESS_CHANNEL, ap->channel, NULL);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid band '%d' (not '5GHz' or '2.4GHz')",
			             ap->band);
			goto error;
		}
		g_object_set (s_wireless, NM_SETTING_WIRELESS_BAND, band, NULL);
	}

	if (nd->mtubytes > 0)
		g_object_set (s_wireless, NM_SETTING_WIRELESS_MTU, nd->mtubytes, NULL);

	/* TODO: Possibly handle hidden SSIDs need extra flag for broadcasting... */
	g_object_set (s_wireless, NM_SETTING_WIRELESS_HIDDEN, FALSE, NULL);

	/* TODO: Support toggling powersave for wifi */
	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_POWERSAVE,
	              NM_SETTING_WIRELESS_POWERSAVE_DEFAULT,
	              NULL);

#if 0  /* TODO: Add support for MAC address randomization */
NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION
ifcfg-rh:
MAC_ADDRESS_RANDOMIZATION
#endif

	return NM_SETTING (s_wireless);

error:
	if (s_wireless)
		g_object_unref (s_wireless);
	return NULL;
}

static NMConnection *
wireless_connection_from_netplan (const char *file,
                                  NetplanNetDefinition *nd,
                                  GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wireless_setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	GBytes *ssid;
	NMSetting *security_setting = NULL;
	gs_free char *ssid_utf8 = NULL;
	const char *mode;
	gboolean adhoc = FALSE;
	GError *local = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (nd != NULL, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	connection = nm_simple_connection_new ();

	/* Wireless */
	wireless_setting = make_wireless_setting (nd, error);
	if (!wireless_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, wireless_setting);

	ssid = nm_setting_wireless_get_ssid (NM_SETTING_WIRELESS (wireless_setting));
	mode = nm_setting_wireless_get_mode (NM_SETTING_WIRELESS (wireless_setting));
	if (mode && !strcmp (mode, "adhoc"))
		adhoc = TRUE;

	/* Wireless security */
	security_setting = make_wireless_security_setting (nd, file, ssid, adhoc, &s_8021x, &local);
	if (local) {
		g_object_unref (connection);
		g_propagate_error (error, local);
		return NULL;
	}
	if (security_setting) {
		nm_connection_add_setting (connection, security_setting);
		if (s_8021x)
			nm_connection_add_setting (connection, NM_SETTING (s_8021x));
	}

	if (ssid)
		ssid_utf8 = _nm_utils_ssid_to_utf8 (ssid);

	/* Connection */
	con_setting = make_connection_setting (file,
	                                       nd,
	                                       NM_SETTING_WIRELESS_SETTING_NAME,
	                                       nm_str_not_empty (ssid_utf8) ?: "unmanaged",
	                                       NULL);

	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	return connection;
}

static NMSetting *
make_modem_setting (NetplanNetDefinition *nd,
                    GError **error,
                    gboolean is_gsm)
{
	NMSetting *s_modem;
	const char *tmp;
	const char *field;

	s_modem = is_gsm
	          ? NM_SETTING (nm_setting_gsm_new ())
	          : NM_SETTING (nm_setting_cdma_new());

	/* Make GSM only settings */
	if (is_gsm) {
		if (nd->modem_params.auto_config)
			g_object_set (s_modem, NM_SETTING_GSM_AUTO_CONFIG, TRUE, NULL);

		tmp = nd->modem_params.apn;
		if (tmp)
			g_object_set (s_modem, NM_SETTING_GSM_APN, tmp, NULL);

		tmp = nd->modem_params.device_id;
		if (tmp)
			g_object_set (s_modem, NM_SETTING_GSM_DEVICE_ID, tmp, NULL);

		tmp = nd->modem_params.network_id;
		if (tmp)
			g_object_set (s_modem, NM_SETTING_GSM_NETWORK_ID, tmp, NULL);

		tmp = nd->modem_params.pin;
		if (tmp)
			g_object_set (s_modem, NM_SETTING_GSM_PIN, tmp, NULL);

		tmp = nd->modem_params.sim_id;
		if (tmp)
			g_object_set (s_modem, NM_SETTING_GSM_SIM_ID, tmp, NULL);

		tmp = nd->modem_params.sim_operator_id;
		if (tmp)
			g_object_set (s_modem, NM_SETTING_GSM_SIM_OPERATOR_ID, tmp, NULL);
	}

	/* Make GSM/CDMA settings */
	tmp = nd->modem_params.number;
	field = is_gsm ? NM_SETTING_GSM_NUMBER : NM_SETTING_CDMA_NUMBER;
	if (tmp)
		g_object_set (s_modem, field, tmp, NULL);

	tmp = nd->modem_params.password;
	field = is_gsm ? NM_SETTING_GSM_PASSWORD : NM_SETTING_CDMA_PASSWORD;
	if (tmp)
		g_object_set (s_modem, field, tmp, NULL);

	tmp = nd->modem_params.username;
	field = is_gsm ? NM_SETTING_GSM_USERNAME : NM_SETTING_CDMA_USERNAME;
	if (tmp)
		g_object_set (s_modem, field, tmp, NULL);

	field = is_gsm ? NM_SETTING_GSM_MTU : NM_SETTING_CDMA_MTU;
	if (nd->mtubytes > 0)
		g_object_set (s_modem, field, nd->mtubytes, NULL);

	return NM_SETTING (s_modem);

error:
	if (s_modem)
		g_object_unref (s_modem);
	return NULL;
}

static NMConnection *
modem_connection_from_netplan (const char *file,
                               NetplanNetDefinition *nd,
                               GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *modem_setting = NULL;
	gboolean is_gsm = FALSE;
	GError *local = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (nd != NULL, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	connection = nm_simple_connection_new ();

	// XXX: make this part of the netplan library
	/* Same check as defined in netplan/src/nm.c:modem_is_gsm() */
	if (nd->modem_params.apn ||  nd->modem_params.auto_config ||
	    nd->modem_params.device_id || nd->modem_params.network_id ||
		nd->modem_params.pin || nd->modem_params.sim_id ||
		nd->modem_params.sim_operator_id)
        is_gsm = TRUE;

	/* Modem */
	modem_setting = make_modem_setting (nd, error, is_gsm);
	if (!modem_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, modem_setting);

	/* Connection */
	con_setting = make_connection_setting (file, nd, is_gsm ?
	                                       NM_SETTING_GSM_SETTING_NAME :
										   NM_SETTING_CDMA_SETTING_NAME,
	                                       NULL, NULL);

	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	return connection;
}

/* TODO: Support ethtool settings */

static void
read_routing_rules (NetplanNetDefinition *nd,
                    NMSettingIPConfig *s_ip4,
                    NMSettingIPConfig *s_ip6)
{
	NMIPRoutingRule *rule;

	for (unsigned i = 0; i < nd->ip_rules->len; ++i) {
		NetplanIPRule *r = g_array_index(nd->ip_rules, NetplanIPRule*, i);
		gboolean is_ipv4 = r->family == AF_INET;

		rule = nm_ip_routing_rule_new (r->family);
		if (r->from) {
			gchar** ipmask = g_strsplit (r->from, "/", 2);
			guint8 len = atoi(ipmask[1]);
			nm_ip_routing_rule_set_to (rule, len ? ipmask[0] : NULL, len);
		}
		if (r->to) {
			gchar** ipmask = g_strsplit (r->to, "/", 2);
			guint8 len = atoi(ipmask[1]);
			nm_ip_routing_rule_set_to (rule, len ? ipmask[0] : NULL, len);
		}
		if (r->table != NETPLAN_ROUTE_TABLE_UNSPEC)
			nm_ip_routing_rule_set_table (rule, r->table);
		if (r->priority != NETPLAN_IP_RULE_PRIO_UNSPEC)
			nm_ip_routing_rule_set_priority (rule, r->priority);
		/* TODO: Implement fwmask, which is missing in NetplanNetDefinition. */
		if (r->fwmark != NETPLAN_IP_RULE_FW_MARK_UNSPEC)
			nm_ip_routing_rule_set_fwmark (rule, r->fwmark, 0);
		if (r->tos != NETPLAN_IP_RULE_TOS_UNSPEC)
			nm_ip_routing_rule_set_tos (rule, r->tos);

		nm_setting_ip_config_add_routing_rule (is_ipv4 ? s_ip4 : s_ip6, rule);
		nm_ip_routing_rule_unref (rule);
	}
}

static NMSetting *
make_wired_setting (NetplanNetDefinition *nd,
                    const char *file,
                    NMSetting8021x **s_8021x,
                    GError **error)
{
	gs_unref_object NMSettingWired *s_wired = NULL;
	//const char *cvalue;
	gs_free char *value = NULL;
	//gboolean found = FALSE;

	s_wired = NM_SETTING_WIRED (nm_setting_wired_new ());

	/* Only for physical devices */
	if (nd->type < NETPLAN_DEF_TYPE_VIRTUAL) {
		if (nd->mtubytes > 0)
			g_object_set (s_wired, NM_SETTING_WIRED_MTU, nd->mtubytes, NULL);

		value = nd->match.mac;
		if (value)
			g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, value, NULL);

		value = nd->set_mac;
		if (value)
			g_object_set (s_wired, NM_SETTING_WIRED_CLONED_MAC_ADDRESS, value, NULL);

		/* TODO: Implement all the different wake-on-lan flags in netplan.
		 *   Right now we can only enable the DEFAULT (0x1) or NONE (0x0). */
		if (!nd->wake_on_lan)
			g_object_set (s_wired,
			              NM_SETTING_WIRED_WAKE_ON_LAN, NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
			              NULL);
	}


	/* TODO: Add subchannels and other s390 options */

#if 0  /* TODO: wired: generate mac address */
NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK
ifcfg-rh:
GENERATE_MAC_ADDRESS_MASK
#endif

#if 0  /* TODO: 802.1x wired settings */
*s_8021x = fill_8021x (netplan, NULL, file, cvalue, FALSE, error);
ifcfg-rh:
KEY_MGMT
#endif  /* 802.1x */

	return (NMSetting *) g_steal_pointer (&s_wired);
}

static NMConnection *
wired_connection_from_netplan (const char *file,
                               NetplanNetDefinition *nd,
                               GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	GError *local = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (nd != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, nd, NM_SETTING_WIRED_SETTING_NAME, NULL, NULL);
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	wired_setting = make_wired_setting (nd, file, &s_8021x, &local);
	if (local && !g_error_matches (local, NM_UTILS_ERROR, NM_UTILS_ERROR_SETTING_MISSING)) {
		g_propagate_error (error, local);
		g_object_unref (connection);
		return NULL;
	}
	g_clear_error (&local);

	if (wired_setting)
		nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

/* TODO: implement infiniband support for reader */

static NMSetting *
make_bond_setting (NetplanNetDefinition *nd,
                   const char *file,
                   GError **error)
{
	NMSettingBond *s_bond;

	s_bond = NM_SETTING_BOND (nm_setting_bond_new ());

	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE,
	                            nd->bond_params.mode);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LACP_RATE,
	                            nd->bond_params.lacp_rate);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIIMON,
	                            nd->bond_params.monitor_interval);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIN_LINKS,
	                            nd->bond_params.min_links
	                            ? g_strdup_printf("%u", nd->bond_params.min_links)
	                            : NULL);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY,
	                            nd->bond_params.transmit_hash_policy);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_AD_SELECT,
	                            nd->bond_params.selection_logic);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE,
	                            nd->bond_params.all_slaves_active ? "1" : NULL);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL,
	                            nd->bond_params.arp_interval);
	//NM_SETTING_BOND_OPTION_ARP_IP_TARGET handled below
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_VALIDATE,
	                            nd->bond_params.arp_validate);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS,
	                            nd->bond_params.arp_all_targets);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY,
	                            nd->bond_params.up_delay);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY,
                                nd->bond_params.down_delay);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_FAIL_OVER_MAC,
                                nd->bond_params.fail_over_mac_policy);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP,
	                            nd->bond_params.gratuitous_arp > 1 // 1 is default
	                            ? g_strdup_printf("%u", nd->bond_params.gratuitous_arp)
	                            : NULL);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE,
	                            nd->bond_params.packets_per_slave != 1 // 1 is default. 0 is random
	                            ? g_strdup_printf("%u", nd->bond_params.packets_per_slave)
	                            : NULL);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY_RESELECT,
	                            nd->bond_params.primary_reselect_policy);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_RESEND_IGMP,
	                            nd->bond_params.resend_igmp > 1 // 1 is default
	                            ? g_strdup_printf("%u", nd->bond_params.resend_igmp)
	                            : NULL);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LP_INTERVAL,
                                nd->bond_params.learn_interval);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY,
                                nd->bond_params.primary_slave);
	/* TODO: Needs to be implemented in netplan. */
	//#define NM_SETTING_BOND_OPTION_ACTIVE_SLAVE      "active_slave"
	//#define NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO "ad_actor_sys_prio"
	//#define NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM   "ad_actor_system"
	//#define NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY  "ad_user_port_key"
	//#define NM_SETTING_BOND_OPTION_NUM_UNSOL_NA      "num_unsol_na"
	//#define NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB    "tlb_dynamic_lb"
	//#define NM_SETTING_BOND_OPTION_USE_CARRIER       "use_carrier"

	if (nd->bond_params.arp_ip_targets) {
		char *ip_target;
		GString *ip_targets = g_string_sized_new (200);
		gint i;

		for (i = 0; (ip_target = (char *)g_array_index(nd->bond_params.arp_ip_targets, gpointer, i)) != NULL; i++) {
			if (i > 0)
				g_string_append_printf (ip_targets, ",");
			g_string_append_printf (ip_targets, "%s", ip_target);
		}

		nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, ip_targets->str);
		g_string_free (ip_targets, TRUE);
	}

	return (NMSetting *) s_bond;
}

static NMConnection *
bond_connection_from_netplan (const char *file,
                              NetplanNetDefinition *nd,
                              GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *bond_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	GError *local = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (nd != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, nd, NM_SETTING_BOND_SETTING_NAME, NULL, _("Bond"));
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	bond_setting = make_bond_setting (nd, file, error);
	if (!bond_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, bond_setting);

	wired_setting = make_wired_setting (nd, file, &s_8021x, &local);
	if (local && !g_error_matches (local, NM_UTILS_ERROR, NM_UTILS_ERROR_SETTING_MISSING)) {
		g_propagate_error (error, local);
		g_object_unref (connection);
		return NULL;
	}
	g_clear_error (&local);

	if (wired_setting)
		nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

/* TODO: add team support for reader */

static NMSetting *
make_bridge_setting (NetplanNetDefinition *nd,
                     const char *file,
                     GError **error)
{
	gs_unref_object NMSettingBridge *s_bridge = NULL;
	const char *value;

	s_bridge = NM_SETTING_BRIDGE (nm_setting_bridge_new ());

	value = nd->set_mac;
	if (value)
		g_object_set (s_bridge, NM_SETTING_BRIDGE_MAC_ADDRESS, value, NULL);

	g_object_set (s_bridge, NM_SETTING_BRIDGE_STP, nd->bridge_params.stp, NULL);

	if (nd->bridge_params.stp) {
		g_object_set (s_bridge, NM_SETTING_BRIDGE_PRIORITY, (guint16) nd->bridge_params.priority, NULL);

		if (nd->bridge_params.forward_delay)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_FORWARD_DELAY,
			              _nm_utils_ascii_str_to_int64 (nd->bridge_params.forward_delay, 10, 0, G_MAXUINT, -1),
			              NULL);
		if (nd->bridge_params.hello_time)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_HELLO_TIME,
			              _nm_utils_ascii_str_to_int64 (nd->bridge_params.hello_time, 10, 0, G_MAXUINT, -1),
			              NULL);
		if (nd->bridge_params.max_age)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_MAX_AGE,
			              _nm_utils_ascii_str_to_int64 (nd->bridge_params.max_age, 10, 0, G_MAXUINT, -1),
			              NULL);

		if (nd->bridge_params.ageing_time)
			g_object_set (s_bridge, NM_SETTING_BRIDGE_AGEING_TIME,
			              _nm_utils_ascii_str_to_int64 (nd->bridge_params.ageing_time, 10, 0, G_MAXUINT, -1),
			              NULL);
	}

#if 0  /* TODO: add the other bridge params */
	g_object_set (s_bridge, NM_SETTING_BRIDGE_MULTICAST_SNOOPING, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_VLAN_FILTERING, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_GROUP_FORWARD_MASK, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID, nd->bridge_params.stp, NULL);
#endif

	return (NMSetting *) g_steal_pointer (&s_bridge);
}

static NMConnection *
bridge_connection_from_netplan (const char *file,
                                NetplanNetDefinition *nd,
                                GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *bridge_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	GError *local = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (nd != NULL, NULL);

	connection = nm_simple_connection_new ();

	_LOGT ("netplan bridge %s ", nd->id);

	con_setting = make_connection_setting (file, nd, NM_SETTING_BRIDGE_SETTING_NAME, NULL, _("Bridge"));
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	_LOGT ("netplan setting connection uuid %s", nm_setting_connection_get_uuid ((NMSettingConnection*)con_setting));
	nm_connection_add_setting (connection, con_setting);
	_LOGT ("netplan connection uuid %s", nm_connection_get_uuid (connection));

	bridge_setting = make_bridge_setting (nd, file, error);
	if (!bridge_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, bridge_setting);

	wired_setting = make_wired_setting (nd, file, &s_8021x, &local);
	if (local && !g_error_matches (local, NM_UTILS_ERROR, NM_UTILS_ERROR_SETTING_MISSING)) {
		g_propagate_error (error, local);
		g_object_unref (connection);
		return NULL;
	}
	g_clear_error (&local);

	if (wired_setting)
		nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

static NMSetting *
make_bridge_port_setting (NetplanNetDefinition *nd)
{
	NMSetting *s_port = NULL;
	g_return_val_if_fail (nd != NULL, FALSE);

	if (!nd->bridge)
		return NULL;

	s_port = nm_setting_bridge_port_new ();

	if (nd->bridge_params.path_cost)
		g_object_set (s_port, NM_SETTING_BRIDGE_PORT_PATH_COST,
		              nd->bridge_params.path_cost, NULL);

	if (nd->bridge_params.port_priority)
		g_object_set (s_port, NM_SETTING_BRIDGE_PORT_PRIORITY,
		              nd->bridge_params.port_priority, NULL);

#if 0 /* TODO: bridge-port vlans need to be implemented in netplan */
	read_bridge_vlans (netplan,
	                   "BRIDGE_PORT_VLANS",
	                   s_port,
	                   NM_SETTING_BRIDGE_PORT_VLANS);

	/* TODO: additional bridge-port settings */
	//g_object_set (s_bridge, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, nd->bridge_params.stp, NULL);
#endif

	return s_port;
}

#if 0  /* TODO: Team device support */
static NMSetting *
make_team_port_setting (NetplanNetDefinition *nd)

NM_SETTING_TEAM_PORT_CONFIG
ifcfg-rh:
TEAM_PORT_CONFIG
#endif

#if 0   /* TODO: Advanced VLAN */
static void
parse_prio_map_list (NMSettingVlan *s_vlan, NetplanNetDefinition *nd, const char *key, NMVlanPriorityMap map)

!nm_setting_vlan_add_priority_str (s_vlan, map, *iter)
#endif

static NMSetting *
make_vlan_setting (NetplanNetDefinition *nd,
                   const char *file,
                   GError **error)
{
	gs_unref_object NMSettingVlan *s_vlan = NULL;
	//guint32 vlan_flags = 0;
	s_vlan = NM_SETTING_VLAN (nm_setting_vlan_new ());

	/* Netplan initializes the ID to G_MAXUINT, as 0 is a valid VLAN ID */
	if (nd->vlan_id > 4094) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Failed to determine VLAN ID (id) from netplan");
		return NULL;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_ID, nd->vlan_id, NULL);

	if (!nd->vlan_link) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Failed to determine VLAN parent (link) from netplan");
		return NULL;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, nd->vlan_link->id, NULL);

	/* TODO: VLAN flags need to be implemented in netplan
	vlan_flags |= NM_VLAN_FLAG_REORDER_HEADERS;
	g_object_set (s_vlan, NM_SETTING_VLAN_FLAGS, vlan_flags, NULL);
	*/

	return NM_SETTING (g_steal_pointer (&s_vlan));
}

static NMConnection *
vlan_connection_from_netplan (const char *file,
                              NetplanNetDefinition *nd,
                              GError **error)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;
	NMSetting *vlan_setting = NULL;
	NMSetting8021x *s_8021x = NULL;
	GError *local = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (nd != NULL, NULL);

	connection = nm_simple_connection_new ();

	con_setting = make_connection_setting (file, nd, NM_SETTING_VLAN_SETTING_NAME, NULL, "Vlan");
	if (!con_setting) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Failed to create connection setting.");
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, con_setting);

	vlan_setting = make_vlan_setting (nd, file, error);
	if (!vlan_setting) {
		g_object_unref (connection);
		return NULL;
	}
	nm_connection_add_setting (connection, vlan_setting);

	wired_setting = make_wired_setting (nd, file, &s_8021x, &local);
	if (local && !g_error_matches (local, NM_UTILS_ERROR, NM_UTILS_ERROR_SETTING_MISSING)) {
		g_propagate_error (error, local);
		g_object_unref (connection);
		return NULL;
	}
	g_clear_error (&local);

	if (wired_setting)
		nm_connection_add_setting (connection, wired_setting);

	if (s_8021x)
		nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	return connection;
}

static NMConnection *
create_unhandled_connection (const char *filename, NetplanNetDefinition *nd,
                             const char *type, char **out_spec)
{
	NMConnection *connection;
	NMSetting *s_con;
	gs_free char *value = NULL;
	const char *v;

	nm_assert (out_spec && !*out_spec);

	connection = nm_simple_connection_new ();

	/* Get NAME, UUID, etc. We need to set a connection type (generic) and add
	 * an empty type-specific setting as well, to make sure it passes
	 * nm_connection_verify() later. */
	s_con = make_connection_setting (filename, nd, NM_SETTING_GENERIC_SETTING_NAME,
	                                 NULL, NULL);
	nm_connection_add_setting (connection, s_con);

	nm_connection_add_setting (connection, nm_setting_generic_new ());

	/* Get a spec */
	v = nd->match.mac;
	if (v) {
		gs_free char *lower = g_ascii_strdown (v, -1);

		*out_spec = g_strdup_printf ("%s:"NM_MATCH_SPEC_MAC_TAG"%s", type, lower);
		return connection;
	}

#if 0  /* TODO: create unhandled matching for s390 subchannels */
*out_spec = g_strdup_printf ("%s:"NM_MATCH_SPEC_S390_SUBCHANNELS_TAG"%s", type, v);
ifcfg-rh:
SUBCHANNELS
#endif

	v = nd->match.original_name;
	if (v) {
		*out_spec = g_strdup_printf ("%s:"NM_MATCH_SPEC_INTERFACE_NAME_TAG"=%s", type, v);
		return connection;
	}

	g_object_unref (connection);
	return NULL;
}


// XXX: This is debug code only, get rid of it before upstreaming.
static void
netplan_ht_debug (gpointer key,
                  gpointer value,
                  gpointer user_data)
{
	NetplanNetDefinition *nd = (NetplanNetDefinition *) value;
	char *key_id = (char *) key;

	_LOGT ("netplan expected id %s : hashtable id %s", key_id, nd->id);
}

static NMConnection *
connection_from_file_full (const char *filename,
                           const char *network_file,  /* for unit tests only */
                           const char *netdef_id,     /* for unit tests only */
                           char **out_unhandled,
                           GError **error,
                           gboolean *out_ignore_error)
{
	NetplanNetDefinition *netdef = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_free char *type = NULL;
	//char *devtype, *bootproto;
	NMSetting *s_ip4, *s_ip6;
	//NMSetting *s_tc, *s_proxy, *s_dcb = NULL, *s_user, *s_sriov;
	NMSetting *s_match, *s_port;
	const char *netplan_name = NULL;
	gboolean ret;
	GHashTableIter iter;
	gpointer key;

	g_return_val_if_fail (filename != NULL, NULL);
	g_return_val_if_fail (out_unhandled && !*out_unhandled, NULL);

	NM_SET_OUT (out_ignore_error, FALSE);

	/* Non-NULL only for unit tests; normally use /etc/netplan/*.yaml
	if (!network_file)
		network_file = SYSCONFDIR "/netplan";
	*/

	netplan_name = utils_get_netplan_name (filename);
	if (!netplan_name) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Ignoring connection '%s' because it's not an netplan file.", filename);
		return NULL;
	}

	if (network_file)
		ret = netplan_parse_yaml (network_file, error);
	ret = netplan_parse_yaml (filename, error);

	if (ret) {
		_LOGT ("commit: parse successful");
		netdefs = netplan_finish_parse (error);
		if (netdefs)
			g_hash_table_foreach (netdefs, netplan_ht_debug, NULL);
	}

	if (error && *error) {
		_LOGT ("commit: parse failed!: %s", (*error)->message);
		return NULL;
	}

#if 0
connection = create_unhandled_connection (filename, main_netplan, "unmanaged", out_unhandled);
ifcfg-rh:
NM_CONTROLLED
BOOTPROTO
DEVICETYPE
TYPE
DEVICE
TEAM_CONFIG
TEAM_MASTER
IPV6TUNNELIPV4
IPV6TUNNELIPV4
#endif

	/* TODO: Check for IBM s390 CTC devices and call them TYPE_ETHERNET */

	if (netdef_id) {
		/* Select netdef specified by ID. */
		netdef = g_hash_table_lookup (netdefs, netdef_id);
	} else {
		/* Select the first netdef from the HashTable,
		 * if ID is not explicitly asked for. */
		g_hash_table_iter_init (&iter, netdefs);
		g_hash_table_iter_next (&iter, &key, (gpointer) &netdef);
	}
	if (!netdef) {
		_LOGE ("invalid netdef");
		return NULL;
	}
	_LOGT ("Selected netdef %s : %d", netdef_id ? netdef_id : (char *) key, netdef->type);


	switch (netdef->type) {
	case NETPLAN_DEF_TYPE_ETHERNET:
		connection = wired_connection_from_netplan (filename, netdef, error);
		break;
	case NETPLAN_DEF_TYPE_WIFI:
		connection = wireless_connection_from_netplan (filename, netdef, error);
		break;
	case NETPLAN_DEF_TYPE_MODEM:
		connection = modem_connection_from_netplan (filename, netdef, error);
		break;
	case NETPLAN_DEF_TYPE_BRIDGE:
		connection = bridge_connection_from_netplan (filename, netdef, error);
		break;
	case NETPLAN_DEF_TYPE_BOND:
		connection = bond_connection_from_netplan (filename, netdef, error);
		break;
	case NETPLAN_DEF_TYPE_VLAN:
		connection = vlan_connection_from_netplan (filename, netdef, error);
		break;
#if 0  /* not yet implemented */
	case NETPLAN_DEF_TYPE_INFINIBAND:
		connection = infiniband_connection_from_netplan (filename, netdef, error);
		break;
	case NETPLAN_DEF_TYPE_TEAM:
		connection = team_connection_from_netplan (filename, netdef, error);
		break;
#endif
	default:
		connection = create_unhandled_connection (filename, netdef, "unrecognized", out_unhandled);
		if (!connection) {
			PARSE_WARNING ("connection type was unrecognized but device was not uniquely identified; device may be managed");
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Failed to read unrecognized connection");
		}
		return g_steal_pointer (&connection);
	}


	if (!connection)
		return NULL;

#if 0  /* TODO: ethtool options */
	parse_ethtool_options (main_netplan, connection);
#endif

	s_ip6 = make_ip6_setting (netdef, error);
	if (!s_ip6)
		return NULL;
	nm_connection_add_setting (connection, s_ip6);
	_LOGT ("netplan conn %p : %s", connection, nm_connection_get_uuid(connection));

	s_ip4 = make_ip4_setting (netdef, error);
	if (!s_ip4)
		return NULL;
	nm_connection_add_setting (connection, s_ip4);
	_LOGT ("netplan conn %p : %s", connection, nm_connection_get_uuid(connection));

	s_match = make_match_setting (netdef);
	if (s_match)
		nm_connection_add_setting (connection, s_match);
	_LOGT ("netplan conn %p : %s", connection, nm_connection_get_uuid(connection));

	s_port = make_bridge_port_setting (netdef);
	if (s_port)
		nm_connection_add_setting (connection, s_port);
	_LOGT ("netplan conn %p : %s", connection, nm_connection_get_uuid(connection));

	if (netdef->ip_rules)
		read_routing_rules (netdef,
		                    NM_SETTING_IP_CONFIG (s_ip4),
		                    NM_SETTING_IP_CONFIG (s_ip6));

#if 0  /* TODO: sriov, tc, etc. */
	s_sriov = make_sriov_setting (main_netplan);
	if (s_sriov)
		nm_connection_add_setting (connection, s_sriov);

	s_tc = make_tc_setting (main_netplan);
	if (s_tc)
		nm_connection_add_setting (connection, s_tc);

	s_proxy = make_proxy_setting (main_netplan);
	if (s_proxy)
		nm_connection_add_setting (connection, s_proxy);

	s_user = make_user_setting (main_netplan);
	if (s_user)
		nm_connection_add_setting (connection, s_user);

	s_port = make_team_port_setting (main_netplan);
	if (s_port)
		nm_connection_add_setting (connection, s_port);

	if (!make_dcb_setting (main_netplan, &s_dcb, error))
		return NULL;
	if (s_dcb)
		nm_connection_add_setting (connection, s_dcb);
#endif

	if (!nm_connection_normalize (connection, NULL, NULL, error)) {
		_LOGT ("normalize fail: %s", (*error)->message);
		return NULL;
	}

	return g_steal_pointer (&connection);
}

NMConnection *
connection_from_file (const char *filename,
                      char **out_unhandled,
                      GError **error,
                      gboolean *out_ignore_error)
{
	return connection_from_file_full (filename, NULL, NULL,
	                                  out_unhandled,
	                                  error,
	                                  out_ignore_error);
}

NMConnection *
nmtst_connection_from_file (const char *filename,
                            const char *network_file,
                            const char *netdef_id,
                            char **out_unhandled,
                            GError **error)
{
	return connection_from_file_full (filename,
	                                  network_file,
	                                  netdef_id,
	                                  out_unhandled,
	                                  error,
	                                  NULL);
}
