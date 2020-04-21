// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd..
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

#if 0   /* TODO: Support certs for reading from netplan files. */
static gboolean
_cert_get_cert (NetplanNetDefinition *nd,
                const char *netplan_key,
                GBytes **out_cert,
                NMSetting8021xCKScheme *out_scheme,
                GError **error)
{
	nm_auto_free_secret char *val_free = NULL;
	const char *val;
	gs_unref_bytes GBytes *cert = NULL;
	GError *local = NULL;
	NMSetting8021xCKScheme scheme;

	val = svGetValueStr (netplan, netplan_key, &val_free);
	if (!val) {
		NM_SET_OUT (out_cert, NULL);
		NM_SET_OUT (out_scheme, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);
		return TRUE;
	}

	cert = _cert_get_cert_bytes (svFileGetName (netplan), val, &local);
	if (!cert)
		goto err;

	scheme = _nm_setting_802_1x_cert_get_scheme (cert, &local);
	if (scheme == NM_SETTING_802_1X_CK_SCHEME_UNKNOWN)
		goto err;

	NM_SET_OUT (out_cert, g_steal_pointer (&cert));
	NM_SET_OUT (out_scheme, scheme);
	return TRUE;

err:
	g_set_error (error,
	             NM_SETTINGS_ERROR,
	             NM_SETTINGS_ERROR_INVALID_CONNECTION,
	             "invalid certificate %s: %s",
	             netplan_key,
	             local->message);
	g_error_free (local);
	return FALSE;
}

static gboolean
_cert_set_from_netplan (gpointer setting,
                        NetplanNetDefinition *nd,
                        const char *netplan_key,
                        const char *property_name,
                        GBytes **out_cert,
                        GError **error)
{
	gs_unref_bytes GBytes *cert = NULL;

	if (!_cert_get_cert (netplan,
	                     netplan_key,
	                     &cert,
	                     NULL,
	                     error))
		return FALSE;

	g_object_set (setting, property_name, cert, NULL);

	NM_SET_OUT (out_cert, g_steal_pointer (&cert));
	return TRUE;
}
#endif /* cert support */

/*****************************************************************************/

#if 0
static void
check_if_bond_slave (NetplanNetDefinition *nd,
                     NMSettingConnection *s_con)
{
	gs_free char *value = NULL;
	const char *v;
	const char *master;

	v = svGetValueStr (netplan, "MASTER_UUID", &value);
	if (!v)
		v = svGetValueStr (netplan, "MASTER", &value);

	if (v) {
		master = nm_setting_connection_get_master (s_con);
		if (master) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring MASTER{_UUID}=\"%s\"",
			               master, v);
			return;
		}

		g_object_set (s_con,
		              NM_SETTING_CONNECTION_MASTER, v,
		              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BOND_SETTING_NAME,
		              NULL);
	}

	/* We should be checking for SLAVE=yes as well, but NM used to not set that,
	 * so for backward-compatibility, we don't check.
	 */
}
#endif

#if 0  /* TODO: Implement (read) Team support  */
static void
check_if_team_slave (NetplanNetDefinition *nd,
                     NMSettingConnection *s_con)
{
	gs_free char *value = NULL;
	const char *v;
	const char *master;

	v = svGetValueStr (netplan, "TEAM_MASTER_UUID", &value);
	if (!v)
		v = svGetValueStr (netplan, "TEAM_MASTER", &value);
	if (!v)
		return;

	master = nm_setting_connection_get_master (s_con);
	if (master) {
		PARSE_WARNING ("Already configured as slave of %s. Ignoring TEAM_MASTER{_UUID}=\"%s\"",
		               master, v);
		return;
	}

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_MASTER, v,
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_TEAM_SETTING_NAME,
	              NULL);
}
#endif /* team support */

static char *
make_connection_name (NetplanNetDefinition *nd,
                      const char *netplan_name,
                      const char *suggested,
                      const char *prefix)
{
	char *full_name = NULL, *name;

	/* If the NetworkManager backend already has a NAME, use that */
	name = nd->backend_settings.nm.name;
	if (name)
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

	/* XXX: Can the stable-id be unset, or do we need to create one? E.g. via g_strdup(new_id)? */
	stable_id = nd->backend_settings.nm.stable_id ? nd->backend_settings.nm.stable_id : NULL;
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
	v = svGetValueStr (netplan, "LLDP", &value);
	if (nm_streq0 (v, "rx"))
		lldp = NM_SETTING_CONNECTION_LLDP_ENABLE_RX;
	else
		lldp = svParseBoolean (v, NM_SETTING_CONNECTION_LLDP_DEFAULT);

	/* Missing ONBOOT is treated as "ONBOOT=true" by the old network service */
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_AUTOCONNECT,
	              svGetValueBoolean (netplan, "ONBOOT", TRUE),
	              NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY,
	              (int) svGetValueInt64 (netplan, "AUTOCONNECT_PRIORITY", 10,
	                                      NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN,
	                                      NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MAX,
	                                      NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT),
	              NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES,
	              (int) svGetValueInt64 (netplan, "AUTOCONNECT_RETRIES", 10,
	                                      -1, G_MAXINT32, -1),
	              NM_SETTING_CONNECTION_MULTI_CONNECT,
	              (gint) svGetValueInt64 (netplan, "MULTI_CONNECT", 10,
	                                      G_MININT32, G_MAXINT32, NM_CONNECTION_MULTI_CONNECT_DEFAULT),
	              NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
	              svGetValueBoolean (netplan, "AUTOCONNECT_SLAVES", NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT),
	              NM_SETTING_CONNECTION_LLDP, lldp,
	              NULL);
	nm_clear_g_free (&value);
#endif

#if 0  /* TODO: User permissions handling in netplan syntax */
	v = svGetValueStr (netplan, "USERS", &value);
	if (v) {
		gs_free const char **items = NULL;

		items = nm_utils_strsplit_set (v, " ");
		for (iter = items; iter && *iter; iter++) {
			if (!nm_setting_connection_add_permission (s_con, "user", *iter, NULL))
				PARSE_WARNING ("invalid USERS item '%s'", *iter);
		}
	}

	nm_clear_g_free (&value);
#endif

#if 0  /* TODO: Support ZONE (firewall), Secondary UUIDs, etc. */
	v = svGetValueStr (netplan, "ZONE", &value);
	g_object_set (s_con, NM_SETTING_CONNECTION_ZONE, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "SECONDARY_UUIDS", &value);
	if (v) {
		gs_free const char **items = NULL;

		items = nm_utils_strsplit_set (v, " \t");
		for (iter = items; iter && *iter; iter++) {
			if (!nm_setting_connection_add_secondary (s_con, *iter))
				PARSE_WARNING ("secondary connection UUID '%s' already added", *iter);
		}
	}

	nm_clear_g_free (&value);
#endif

#if 0  /* TODO: Bridge UUIDs??? */
	v = svGetValueStr (netplan, "BRIDGE_UUID", &value);
	if (!v)
		v = svGetValueStr (netplan, "BRIDGE", &value);
	if (v) {
		const char *old_value;

		if ((old_value = nm_setting_connection_get_master (s_con))) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring BRIDGE=\"%s\"",
			               old_value, v);
		} else {
			g_object_set (s_con, NM_SETTING_CONNECTION_MASTER, v, NULL);
			g_object_set (s_con, NM_SETTING_CONNECTION_SLAVE_TYPE,
			              NM_SETTING_BRIDGE_SETTING_NAME, NULL);
		}
	}

	check_if_bond_slave (netplan, s_con);
	check_if_team_slave (netplan, s_con);

	nm_clear_g_free (&value);
#endif

#if 0  /* TODO: OVS support */
	v = svGetValueStr (netplan, "OVS_PORT_UUID", &value);
	if (!v)
		v = svGetValueStr (netplan, "OVS_PORT", &value);
	if (v) {
		const char *old_value;

		if ((old_value = nm_setting_connection_get_master (s_con))) {
			PARSE_WARNING ("Already configured as slave of %s. Ignoring OVS_PORT=\"%s\"",
			               old_value, v);
		} else {
			g_object_set (s_con, NM_SETTING_CONNECTION_MASTER, v, NULL);
			g_object_set (s_con, NM_SETTING_CONNECTION_SLAVE_TYPE,
			              NM_SETTING_OVS_PORT_SETTING_NAME, NULL);
		}
	}

	nm_clear_g_free (&value);
#endif  /* OVS support */

#if 0  /* TODO: more random settings that are NM-specific */
	v = svGetValueStr (netplan, "GATEWAY_PING_TIMEOUT", &value);
	if (v) {
		gint64 tmp;

		tmp = _nm_utils_ascii_str_to_int64 (v, 10, 0, G_MAXINT32 - 1, -1);
		if (tmp >= 0) {
			if (tmp > 600) {
				tmp = 600;
				PARSE_WARNING ("invalid GATEWAY_PING_TIMEOUT time");
			}
			g_object_set (s_con, NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, (guint) tmp, NULL);
		} else
			PARSE_WARNING ("invalid GATEWAY_PING_TIMEOUT time");
	}

	switch (svGetValueBoolean (netplan, "CONNECTION_METERED", -1)) {
	case TRUE:
		g_object_set (s_con, NM_SETTING_CONNECTION_METERED, NM_METERED_YES, NULL);
		break;
	case FALSE:
		g_object_set (s_con, NM_SETTING_CONNECTION_METERED, NM_METERED_NO, NULL);
		break;
	}

	vint64 = svGetValueInt64 (netplan, "AUTH_RETRIES", 10, -1, G_MAXINT32, -1);
	g_object_set (s_con, NM_SETTING_CONNECTION_AUTH_RETRIES, (int) vint64, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "DEVTIMEOUT", &value);
	if (v) {
		vint64 = _nm_utils_ascii_str_to_int64 (v, 10, 0, ((gint64) G_MAXINT32) / 1000, -1);
		if (vint64 != -1)
			vint64 *= 1000;
		else {
			char *endptr;
			double d;

			d = g_ascii_strtod (v, &endptr);
			if (   errno == 0
			    && endptr[0] == '\0'
			    && d >= 0.0) {
				d *= 1000.0;

				/* We round. Yes, this is not correct to round IEEE 754 floats in general,
				 * but sufficient for our case where we know that NetworkManager wrote the
				 * setting with up to 3 digits for the milliseconds. */
				d += 0.5;
				if (   d >= 0.0
				    && d <= (double) G_MAXINT32)
					vint64 = (gint64) d;
			}
		}
		if (vint64 == -1)
			PARSE_WARNING ("invalid DEVTIMEOUT setting");
		else
			g_object_set (s_con, NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT, (int) vint64, NULL);
	}

	i_val = NM_SETTING_CONNECTION_MDNS_DEFAULT;
	if (!svGetValueEnum (netplan, "MDNS",
	                     nm_setting_connection_mdns_get_type (),
	                     &i_val, NULL))
		PARSE_WARNING ("invalid MDNS setting");
	g_object_set (s_con, NM_SETTING_CONNECTION_MDNS, i_val, NULL);
#endif

#if 0  /* TODO: LLMNR settings support */
	i_val = NM_SETTING_CONNECTION_LLMNR_DEFAULT;
	if (!svGetValueEnum (netplan, "LLMNR",
	                     nm_setting_connection_llmnr_get_type (),
	                     &i_val, NULL))
		PARSE_WARNING ("invalid LLMNR setting");
	g_object_set (s_con, NM_SETTING_CONNECTION_LLMNR, i_val, NULL);
#endif

	return NM_SETTING (s_con);
}

#if 0
static gboolean
read_ip4_address (NetplanNetDefinition *nd,
                  const char *tag,
                  gboolean *out_has_key,
                  guint32 *out_addr,
                  GError **error)
{
	//const char *value;
	//in_addr_t a;

	nm_assert (nd);
	nm_assert (tag);
	nm_assert (!error || !*error);

	// TODO: Parse through the GArray of addresses and pick just the ipv4 (static addresses)

	return TRUE;
}

static gboolean
is_any_ip4_address_defined (NetplanNetDefinition *nd, int *idx)
{
	int i, ignore, *ret_idx;

	ret_idx = idx ?: &ignore;

	for (i = -1; i <= 2; i++) {
		gs_free char *value = NULL;
		char tag[256];

		if (svGetValueStr (netplan, numbered_tag (tag, "IPADDR", i), &value)) {
			*ret_idx = i;
			return TRUE;
		}

		if (svGetValueStr (netplan, numbered_tag (tag, "PREFIX", i), &value)) {
			*ret_idx = i;
			return TRUE;
		}

		if (svGetValueStr (netplan, numbered_tag (tag, "NETMASK", i), &value)) {
			*ret_idx = i;
			return TRUE;
		}
	}
	return FALSE;
}
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
{
	gboolean has_user_data = FALSE;
	gs_unref_object NMSettingUser *s_user = NULL;
	gs_unref_hashtable GHashTable *keys = NULL;
	GHashTableIter iter;
	const char *key;
	nm_auto_free_gstring GString *str = NULL;

	g_hash_table_iter_init (&iter, keys);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, NULL)) {
		const char *value;
		gs_free char *value_to_free = NULL;

		value = svGetValue (netplan, key, &value_to_free);

		if (!value)
			continue;

		if (!str)
			str = g_string_sized_new (100);
		else
			g_string_set_size (str, 0);

		if (!nms_netplan_utils_user_key_decode (key + NM_STRLEN ("NM_USER_"), str))
			continue;

		if (!s_user)
			s_user = NM_SETTING_USER (nm_setting_user_new ());

		if (nm_setting_user_set_data (s_user, str->str,
		                              value, NULL))
			has_user_data = TRUE;
	}

	return   has_user_data
	       ? NM_SETTING (g_steal_pointer (&s_user))
	       : NULL;
}
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
{
	NMSettingProxy *s_proxy = NULL;
	gs_free char *value = NULL;
	const char *v;
	NMSettingProxyMethod method;

	v = svGetValueStr (netplan, "PROXY_METHOD", &value);
	if (!v)
		return NULL;

	if (!g_ascii_strcasecmp (v, "auto"))
		method = NM_SETTING_PROXY_METHOD_AUTO;
	else
		method = NM_SETTING_PROXY_METHOD_NONE;

	s_proxy = (NMSettingProxy *) nm_setting_proxy_new ();

	switch (method) {
	case NM_SETTING_PROXY_METHOD_AUTO:
		g_object_set (s_proxy,
		              NM_SETTING_PROXY_METHOD, (int) NM_SETTING_PROXY_METHOD_AUTO,
		              NULL);

		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, "PAC_URL", &value);
		if (v)
			g_object_set (s_proxy, NM_SETTING_PROXY_PAC_URL, v, NULL);

		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, "PAC_SCRIPT", &value);
		if (v)
			g_object_set (s_proxy, NM_SETTING_PROXY_PAC_SCRIPT, v, NULL);

		break;
	case NM_SETTING_PROXY_METHOD_NONE:
		g_object_set (s_proxy,
		              NM_SETTING_PROXY_METHOD, (int) NM_SETTING_PROXY_METHOD_NONE,
		              NULL);
		break;
	}

	if (svGetValueBoolean (netplan, "BROWSER_ONLY", FALSE))
		g_object_set (s_proxy, NM_SETTING_PROXY_BROWSER_ONLY, TRUE, NULL);

	return NM_SETTING (s_proxy);
}
#endif  /* proxy support */

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
	const char *v;
	const char *dns_options = NULL;
	int i;
	guint32 a;
	gboolean has_key;
	gboolean never_default;
	gint64 timeout;
	int priority;
	const char *const *item;
	guint32 route_table;

	nm_assert (out_has_defroute && !*out_has_defroute);

	/* First check if DEFROUTE is set for this device; DEFROUTE has the
	 * opposite meaning from never-default. The default if DEFROUTE is not
	 * specified is DEFROUTE=yes which means that this connection can be used
	 * as a default route
	 */
	i = svGetValueBoolean (netplan, "DEFROUTE", -1);
	if (i == -1)
		never_default = FALSE;
	else {
		never_default = !i;
		*out_has_defroute = TRUE;
	}

	/* Then check if GATEWAYDEV; it's global and overrides DEFROUTE */
	if (network_netplan) {
		gs_free char *gatewaydev_value = NULL;
		const char *gatewaydev;

		/* Get the connection netplan device name and the global gateway device */
		v = svGetValueStr (netplan, "DEVICE", &value);
		gatewaydev = svGetValueStr (network_netplan, "GATEWAYDEV", &gatewaydev_value);
		dns_options = svGetValue (network_netplan, "RES_OPTIONS", &dns_options_free);

		/* If there was a global gateway device specified, then only connections
		 * for that device can be the default connection.
		 */
		if (gatewaydev && v)
			never_default = !!strcmp (v, gatewaydev);

		nm_clear_g_free (&value);
	}

	v = svGetValueStr (netplan, "BOOTPROTO", &value);

	if (!v || !*v || !g_ascii_strcasecmp (v, "none")) {
		if (is_any_ip4_address_defined (netplan, NULL))
			method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
		else
			method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
	} else if (!g_ascii_strcasecmp (v, "bootp") || !g_ascii_strcasecmp (v, "dhcp")) {
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;
	} else if (!g_ascii_strcasecmp (v, "static")) {
		if (is_any_ip4_address_defined (netplan, NULL))
			method = NM_SETTING_IP4_CONFIG_METHOD_MANUAL;
		else
			method = NM_SETTING_IP4_CONFIG_METHOD_DISABLED;
	} else if (!g_ascii_strcasecmp (v, "autoip")) {
		method = NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL;
	} else if (!g_ascii_strcasecmp (v, "shared")) {
		method = NM_SETTING_IP4_CONFIG_METHOD_SHARED;
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Unknown BOOTPROTO '%s'", v);
		return NULL;
	}

	/* the route table (policy routing) is ignored if we don't handle routes. */
	route_table = svGetValueInt64 (netplan, "IPV4_ROUTE_TABLE", 10,
	                               0, G_MAXUINT32, 0);
	if (   route_table != 0
	    && !routes_read) {
		PARSE_WARNING ("'rule-' or 'rule6-' files are present; Policy routing (IPV4_ROUTE_TABLE) is ignored");
		route_table = 0;
	}
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
	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "DHCP_HOSTNAME", &value);
	if (v)
		g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "DHCP_FQDN", &value);
	if (v) {
		g_object_set (s_ip4,
		              NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, NULL,
		              NM_SETTING_IP4_CONFIG_DHCP_FQDN, v,
		              NULL);
	}

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, svGetValueBoolean (netplan, "DHCP_SEND_HOSTNAME", TRUE),
	              NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, svGetValueInt64 (netplan, "IPV4_DHCP_TIMEOUT", 10, 0, G_MAXINT32, 0),
	              NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "DHCP_CLIENT_ID", &value);
	if (v)
		g_object_set (s_ip4, NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID, v, NULL);
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
	/* We used to skip saving a lot of unused properties for the ipv4 shared method.
	 * We want now to persist them but... unfortunately loading DNS or DOMAIN options
	 * would cause a fail in the ipv4 verify() function. As we don't want any regression
	 * in the unlikely event that someone has a working netplan file for an IPv4 shared ip
	 * connection with a crafted "DNS" entry... don't load it. So we will avoid failing
	 * the connection) */
	if (!nm_streq (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED)) {
		/* DNS servers
		 * Pick up just IPv4 addresses (IPv6 addresses are taken by make_ip6_setting())
		 */
		for (i = 1; i <= 10; i++) {
			char tag[256];

			numbered_tag (tag, "DNS", i);
			nm_clear_g_free (&value);
			v = svGetValueStr (netplan, tag, &value);
			if (v) {
				if (nm_utils_ipaddr_valid (AF_INET, v)) {
					if (!nm_setting_ip_config_add_dns (s_ip4, v))
						PARSE_WARNING ("duplicate DNS server %s", tag);
				} else if (nm_utils_ipaddr_valid (AF_INET6, v)) {
					/* Ignore IPv6 addresses */
				} else {
					PARSE_WARNING ("invalid DNS server address %s", v);
					return NULL;
				}
			}
		}

		/* DNS searches */
		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, "DOMAIN", &value);
		if (v) {
			gs_free const char **searches = NULL;

			searches = nm_utils_strsplit_set (v, " ");
			if (searches) {
				for (item = searches; *item; item++) {
					if (!nm_setting_ip_config_add_dns_search (s_ip4, *item))
						PARSE_WARNING ("duplicate DNS domain '%s'", *item);
				}
			}
		}
	}

	/* DNS options */
	nm_clear_g_free (&value);
	parse_dns_options (s_ip4, svGetValue (netplan, "RES_OPTIONS", &value));
	parse_dns_options (s_ip4, dns_options);
#endif /* shared */

#if 0  /* TODO: DNS priority */
	/* DNS priority */
	priority = svGetValueInt64 (netplan, "IPV4_DNS_PRIORITY", 10, G_MININT32, G_MAXINT32, 0);
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_DNS_PRIORITY,
	              priority,
	              NULL);
#endif

	if (nd->routes)
		make_routes(nd, s_ip4, AF_INET);

#if 0 /* TODO: dad-timeout */
	timeout = svGetValueInt64 (netplan, "ACD_TIMEOUT", 10, -1, NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX, -2);
	if (timeout == -2) {
		timeout = svGetValueInt64 (netplan, "ARPING_WAIT", 10, -1,
		                           NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX / 1000, -1);
		if (timeout > 0)
			timeout *= 1000;
	}
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DAD_TIMEOUT, (int) timeout, NULL);
#endif  /* DNS prio, routes */

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
	/* First check if IPV6_DEFROUTE is set for this device; IPV6_DEFROUTE has the
	 * opposite meaning from never-default. The default if IPV6_DEFROUTE is not
	 * specified is IPV6_DEFROUTE=yes which means that this connection can be used
	 * as a default route
	 */
	never_default = !svGetValueBoolean (netplan, "IPV6_DEFROUTE", TRUE);
#endif

#if 0  /* TODO: ipv6 gateway and all */
	/* Then check if IPV6_DEFAULTGW or IPV6_DEFAULTDEV is specified;
	 * they are global and override IPV6_DEFROUTE
	 * When both are set, the device specified in IPV6_DEFAULTGW takes preference.
	 */
	if (network_netplan) {
		const char *ipv6_defaultgw, *ipv6_defaultdev;
		gs_free char *ipv6_defaultgw_to_free = NULL;
		gs_free char *ipv6_defaultdev_to_free = NULL;
		const char *default_dev = NULL;

		/* Get the connection netplan device name and the global default route device */
		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, "DEVICE", &value);
		ipv6_defaultgw = svGetValueStr (network_netplan, "IPV6_DEFAULTGW", &ipv6_defaultgw_to_free);
		ipv6_defaultdev = svGetValueStr (network_netplan, "IPV6_DEFAULTDEV", &ipv6_defaultdev_to_free);

		if (ipv6_defaultgw) {
			default_dev = strchr (ipv6_defaultgw, '%');
			if (default_dev)
				default_dev++;
		}
		if (!default_dev)
			default_dev = ipv6_defaultdev;

		/* If there was a global default route device specified, then only connections
		 * for that device can be the default connection.
		 */
		if (default_dev && v)
			never_default = !!strcmp (v, default_dev);
	}

	/* Find out method property */
	/* Is IPV6 enabled? Set method to "ignored", when not enabled */
	disabled = svGetValueBoolean(netplan, "IPV6_DISABLED", FALSE);
	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "IPV6INIT", &value);
	ipv6init = svGetValueBoolean (netplan, "IPV6INIT", FALSE);
	if (!v) {
		if (network_netplan)
			ipv6init = svGetValueBoolean (network_netplan, "IPV6INIT", FALSE);
	}
#endif  /* defaults ipv6 */

#if 0  /* TODO: ipv6 config methods */
	if (disabled)
		method = NM_SETTING_IP6_CONFIG_METHOD_DISABLED;
	else if (!ipv6init)
		method = NM_SETTING_IP6_CONFIG_METHOD_IGNORE;
	else {
		ipv6forwarding = svGetValueBoolean (netplan, "IPV6FORWARDING", FALSE);
		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, "IPV6_AUTOCONF", &value);
		dhcp6 = svGetValueBoolean (netplan, "DHCPV6C", FALSE);

		if (!g_strcmp0 (v, "shared"))
			method = NM_SETTING_IP6_CONFIG_METHOD_SHARED;
		else if (svParseBoolean (v, !ipv6forwarding))
			method = NM_SETTING_IP6_CONFIG_METHOD_AUTO;
		else if (dhcp6)
			method = NM_SETTING_IP6_CONFIG_METHOD_DHCP;
		else {
			/* IPV6_AUTOCONF=no and no IPv6 address -> method 'link-local' */
			nm_clear_g_free (&value);
			v = svGetValueStr (netplan, "IPV6ADDR", &value);
			if (!v) {
				nm_clear_g_free (&value);
				v = svGetValueStr (netplan, "IPV6ADDR_SECONDARIES", &value);
			}

			if (!v)
				method = NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL;
		}
	}

	/* Read IPv6 Privacy Extensions configuration */
	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "IPV6_PRIVACY", &value);
	if (v) {
		ip6_privacy = svParseBoolean (v, FALSE);
		if (!ip6_privacy)
			ip6_privacy = (g_strcmp0 (v, "rfc4941") == 0) ||
			              (g_strcmp0 (v, "rfc3041") == 0);
	}
	ip6_privacy_prefer_public_ip = svGetValueBoolean (netplan, "IPV6_PRIVACY_PREFER_PUBLIC_IP", FALSE);
	ip6_privacy_val = v ?
	                      (ip6_privacy ?
	                          (ip6_privacy_prefer_public_ip ? NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR : NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR) :
	                          NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED) :
	                      NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;

	/* the route table (policy routing) is ignored if we don't handle routes. */
	route_table = svGetValueInt64 (netplan, "IPV6_ROUTE_TABLE", 10,
	                               0, G_MAXUINT32, 0);
	if (   route_table != 0
	    && !routes_read) {
		PARSE_WARNING ("'rule-' or 'rule6-' files are present; Policy routing (IPV6_ROUTE_TABLE) is ignored");
		route_table = 0;
	}
#endif  /* ipv6 methods and settings */

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

#if 0
	/* Don't bother to read IP, DNS and routes when IPv6 is disabled */
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
	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "DHCPV6_DUID", &value);
	if (v)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_DHCP_DUID, v, NULL);

	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "DHCPV6_HOSTNAME", &value);
	/* Use DHCP_HOSTNAME as fallback if it is in FQDN format and ipv6.method is
	 * auto or dhcp: this is required to support old netplan files
	 */
	if (!v && (   !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO)
		       || !strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_DHCP))) {
		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, "DHCP_HOSTNAME", &value);
		if (v && !strchr (v, '.'))
			v = NULL;
	}
	if (v)
		g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, v, NULL);

	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME,
	              svGetValueBoolean (netplan, "DHCPV6_SEND_HOSTNAME", TRUE), NULL);
#endif  /* IPv6 DUID, hostname and special DHCP options */

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
	ipv6addr = svGetValueStr (netplan, "IPV6ADDR", &ipv6addr_to_free);
	ipv6addr_secondaries = svGetValueStr (netplan, "IPV6ADDR_SECONDARIES", &ipv6addr_secondaries_to_free);

	nm_clear_g_free (&value);
	value = g_strjoin (ipv6addr && ipv6addr_secondaries ? " " : NULL,
	                   ipv6addr ?: "",
	                   ipv6addr_secondaries ?: "",
	                   NULL);

	list = nm_utils_strsplit_set (value, " ");
	for (iter = list, i = 0; iter && *iter; iter++, i++) {
		NMIPAddress *addr = NULL;

		if (!parse_full_ip6_address (netplan, *iter, i, &addr, error))
			return NULL;

		if (!nm_setting_ip_config_add_address (s_ip6, addr))
			PARSE_WARNING ("duplicate IP6 address");
		nm_ip_address_unref (addr);
	}
#endif  /* IPv6: read static addresses. */

#if 0  /* IPv6: read gateway. */
	/* Gateway */
	if (nm_setting_ip_config_get_num_addresses (s_ip6)) {
		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, "IPV6_DEFAULTGW", &value);
		if (!v) {
			/* If no gateway in the netplan, try global /etc/sysconfig/network instead */
			if (network_netplan) {
				nm_clear_g_free (&value);
				v = svGetValueStr (network_netplan, "IPV6_DEFAULTGW", &value);
			}
		}
		if (v) {
			char *ptr;
			if ((ptr = strchr (v, '%')) != NULL)
				*ptr = '\0';  /* remove %interface prefix if present */
			if (!nm_utils_ipaddr_valid (AF_INET6, v)) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid IP6 address '%s'", v);
				return NULL;
			}

			g_object_set (s_ip6, NM_SETTING_IP_CONFIG_GATEWAY, v, NULL);
		}
	}

	/* IPv6 tokenized interface identifier */
	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "IPV6_TOKEN", &value);
	if (v)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_TOKEN, v, NULL);
#endif

	/* IPv6 Address generation mode */
	if (nd->ip6_addr_gen_mode == NETPLAN_ADDRGEN_STABLEPRIVACY)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
					  NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY, NULL);
	else if (nd->ip6_addr_gen_mode == NETPLAN_ADDRGEN_EUI64)
		g_object_set (s_ip6, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE,
		              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64, NULL);

#if 0  /* TODO: set dns servers */
	/* DNS servers
	 * Pick up just IPv6 addresses (IPv4 addresses are taken by make_ip4_setting())
	 */
	for (i = 1; i <= 10; i++) {
		char tag[256];

		numbered_tag (tag, "DNS", i);
		nm_clear_g_free (&value);
		v = svGetValueStr (netplan, tag, &value);
		if (!v) {
			/* all done */
			break;
		}

		if (nm_utils_ipaddr_valid (AF_INET6, v)) {
			if (!nm_setting_ip_config_add_dns (s_ip6, v))
				PARSE_WARNING ("duplicate DNS server %s", tag);
		} else if (nm_utils_ipaddr_valid (AF_INET, v)) {
			/* Ignore IPv4 addresses */
		} else {
			PARSE_WARNING ("invalid DNS server address %s", v);
			return NULL;
		}
	}
#endif

	if (nd->routes)
		make_routes(nd, s_ip6, AF_INET6);

#if 0  /* TODO: IPv6 DNS searches */
	/* DNS searches */
	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "IPV6_DOMAIN", &value);
	if (v) {
		gs_free const char **searches = NULL;

		searches = nm_utils_strsplit_set (v, " ");
		if (searches) {
			for (iter = searches; *iter; iter++) {
				if (!nm_setting_ip_config_add_dns_search (s_ip6, *iter))
					PARSE_WARNING ("duplicate DNS domain '%s'", *iter);
			}
		}
	}

	/* DNS options */
	nm_clear_g_free (&value);
	parse_dns_options (s_ip6, svGetValue (netplan, "IPV6_RES_OPTIONS", &value));

	/* DNS priority */
	priority = svGetValueInt64 (netplan, "IPV6_DNS_PRIORITY", 10, G_MININT32, G_MAXINT32, 0);
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_DNS_PRIORITY,
	              priority,
	              NULL);
#endif

	return NM_SETTING (g_steal_pointer (&s_ip6));
}

/* TODO: Implement SRIOV support */
/* TODO: Implement TC support */
/* TODO: Implement DCB support */
/* There is useful code to look at in ifcfg-rh plugin ~cyphermox */

#if 0 /* TODO: It looks like we don't really support WEP right now */
static gboolean
add_one_wep_key (NetplanNetDefinition *nd,
                 const char *shvar_key,
                 guint8 key_idx,
                 gboolean passphrase,
                 NMSettingWirelessSecurity *s_wsec,
                 GError **error)
{
	gs_free char *value_free = NULL;
	const char *value;
	const char *key = NULL;

	g_return_val_if_fail (nd != NULL, FALSE);
	g_return_val_if_fail (shvar_key != NULL, FALSE);
	g_return_val_if_fail (key_idx <= 3, FALSE);
	g_return_val_if_fail (s_wsec != NULL, FALSE);

	value = svGetValueStr (ifcfg, shvar_key, &value_free);
	if (!value)
		return TRUE;

	/* Validate keys */
	if (passphrase) {
		if (value[0] && strlen (value) < 64)
			key = value;
	} else {
		if (NM_IN_SET (strlen (value), 10, 26)) {
			/* Hexadecimal WEP key */
			if (NM_STRCHAR_ANY (value, ch, !g_ascii_isxdigit (ch))) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid hexadecimal WEP key.");
				return FALSE;
			}
			key = value;
		} else if (   !strncmp (value, "s:", 2)
		           && NM_IN_SET (strlen (value), 7, 15)) {
			/* ASCII key */
			if (NM_STRCHAR_ANY (value + 2, ch, !g_ascii_isprint (ch))) {
				g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
				             "Invalid ASCII WEP key.");
				return FALSE;
			}

			/* Remove 's:' prefix.
			 * Don't convert to hex string. wpa_supplicant takes 'wep_key0' option over D-Bus as byte array
			 * and converts it to hex string itself. Even though we convert hex string keys into a bin string
			 * before passing to wpa_supplicant, this prevents two unnecessary conversions. And mainly,
			 * ASCII WEP key doesn't change to HEX WEP key in UI, which could confuse users.
			 */
			key = value + 2;
		}
	}

	if (!key) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Invalid WEP key length.");
		return FALSE;
	}

	nm_setting_wireless_security_set_wep_key (s_wsec, key_idx, key);
	return TRUE;
}

static gboolean
read_wep_keys (NetplanNetDefinition *nd,
               NMWepKeyType key_type,
               guint8 def_idx,
               NMSettingWirelessSecurity *s_wsec,
               GError **error)
{
	if (key_type != NM_WEP_KEY_TYPE_PASSPHRASE) {
		if (!add_one_wep_key (nd, "KEY1", 0, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (nd, "KEY2", 1, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (nd, "KEY3", 2, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (nd, "KEY4", 3, FALSE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (nd, "KEY", def_idx, FALSE, s_wsec, error))
			return FALSE;
	}

	if (key_type != NM_WEP_KEY_TYPE_KEY) {
		if (!add_one_wep_key (nd, "KEY_PASSPHRASE1", 0, TRUE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (nd, "KEY_PASSPHRASE2", 1, TRUE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (nd, "KEY_PASSPHRASE3", 2, TRUE, s_wsec, error))
			return FALSE;
		if (!add_one_wep_key (nd, "KEY_PASSPHRASE4", 3, TRUE, s_wsec, error))
			return FALSE;
	}

	return TRUE;
}
#endif

#if 0 /* TODO: Implement WEP in netplan */
static NMSetting *
make_wep_setting (NetplanNetDefinition *nd,
                  const char *file,
                  GError **error)
{
	gs_unref_object NMSettingWirelessSecurity *s_wsec = NULL;
	gs_free char *value = NULL;
	//int default_key_idx = 0;
	//gboolean has_default_key = FALSE;
	//NMSettingSecretFlags key_flags;

	s_wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "none", NULL);

	/* TODO: support specifying keyidx for WEP */
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_WEP_TX_KEYIDX, 0, NULL);

	/* Read WEP key flags */
	// TODO: read wifi WEP secret flags.
	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_WEP_KEY_FLAGS, NM_SETTING_SECRET_FLAG_NONE, NULL);

	g_object_set (G_OBJECT (s_wsec),
	              NM_SETTING_WIRELESS_SECURITY_WEP_KEY_TYPE, NM_WEP_KEY_TYPE_PASSPHRASE,
	              NULL);

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", NULL);
	/* TODO: Support WEP-only (apparently) "shared" AUTH_ALG... */
	//g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "shared", NULL);

	nm_setting_wireless_security_set_wep_key (s_wsec, 0, nd->auth.password);

	return NM_SETTING (g_steal_pointer (&s_wsec));
}
#endif

static gboolean
fill_wpa_ciphers (NetplanNetDefinition *nd,
                  NMSettingWirelessSecurity *wsec,
                  gboolean group,
                  gboolean adhoc)
{
#if 0  /* TODO: WPA ciphers selection (not yet in netplan) */
	gs_free char *value = NULL;
	const char *p;
	gs_free const char **list = NULL;
	const char *const *iter;
	int i = 0;

	p = svGetValueStr (netplan, group ? "CIPHER_GROUP" : "CIPHER_PAIRWISE", &value);
	if (!p)
		return TRUE;

	list = nm_utils_strsplit_set (p, " ");
	for (iter = list; iter && *iter; iter++, i++) {
		if (!strcmp (*iter, "CCMP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec, "ccmp");
			else
				nm_setting_wireless_security_add_pairwise (wsec, "ccmp");
		} else if (!strcmp (*iter, "TKIP")) {
			if (group)
				nm_setting_wireless_security_add_group (wsec, "tkip");
			else
				nm_setting_wireless_security_add_pairwise (wsec, "tkip");
		} else if (group && !strcmp (*iter, "WEP104"))
			nm_setting_wireless_security_add_group (wsec, "wep104");
		else if (group && !strcmp (*iter, "WEP40"))
			nm_setting_wireless_security_add_group (wsec, "wep40");
		else {
			PARSE_WARNING ("ignoring invalid %s cipher '%s'",
			               group ? "CIPHER_GROUP" : "CIPHER_PAIRWISE",
			               *iter);
		}
	}
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
            const char *file,
            const char *key_mgmt,
            gboolean wifi,
            GError **error)
{
	gs_unref_object NMSetting8021x *s_8021x = NULL;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();

	// TODO: read 802.1x settings from hashtable keys (just mapping values already in netplan structures)

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
		/* WPS */
		i_val = NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT;
		if (!svGetValueEnum (netplan, "WPS_METHOD",
							nm_setting_wireless_security_wps_method_get_type (),
							&i_val, error))
			return NULL;
		g_object_set (wsec,
					NM_SETTING_WIRELESS_SECURITY_WPS_METHOD, (guint) i_val,
					NULL);
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

		if (ap->auth.key_management == NETPLAN_AUTH_KEY_MANAGEMENT_WPA_PSK)
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk", NULL);
		else {
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
		}
	} else {
		*s_8021x = fill_8021x (nd, file, v, TRUE, error);
		if (!*s_8021x)
			return NULL;
	}
	/* TODO: support WPA PMF, FILS */

#if 0
	v = svGetValueStr (netplan, "SECURITYMODE", &value);
	if (NM_IN_STRSET (v, NULL, "open"))
		g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, v, NULL);
#endif

	return (NMSetting *) g_steal_pointer (&wsec);
}

#if 0  /* TODO: LEAP not yet supported in netplan yaml */
static NMSetting *
make_leap_setting (NetplanNetDefinition *nd,
                   const char *file,
                   GError **error)
{
	gs_unref_object NMSettingWirelessSecurity *wsec = NULL;
	gs_free char *value   = NULL;
	NMSettingSecretFlag  s flags;
  
	wsec = NM_SETTING_WIRELESS_SECURITY (nm_setting_wireless_security_new ());

	if (nd->auth.key_management != NETPLAN_AUTH_KEY_MANAGEMENT_8021X)
		return NULL;

	if (nd->auth.eap_method != NETPLAN_AUTH_EAP_LEAP)
		return NULL; /* Not LEAP */

	flags = _secret_read_netplan_flags (netplan, "IEEE_8021X_PASSWORD_FLAGS");
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD_FLAGS, flags, NULL);

	/* Read LEAP password if it's system-owned */
	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		value = svGetValueStr_cp (netplan, "IEEE_8021X_PASSWORD");
		if (!value) {
			/* Try to get keys from the "shadow" key file */
			k  eys_netplan = utils_get_keys_netplan (file, FALSE);
  			if (keys_netpl  an) {
				  value = svGetV    alueStr_cp (keys_netplan, "IEEE_8021X_PASSWORD");
  				svCloseFile (k      eys_netplan);
  		    	}
	    	}
		if (value && strle  n (value))
			g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_PASSWORD, value, NULL);
		nm_clear_g_free (&value);
	}

	value = svGetValueStr_cp (netplan, "IEEE_8021X_IDENTITY");
	if (!value) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Missing LEAP identity");
		return NULL;
	}
	g_object_set (wsec, NM_SETTING_WIRELESS_SECURITY_LEAP_USERNAME, value, NULL);
	nm_clear_g_free (&value);

	g_object_set (wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "ieee8021x",
	              NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "leap",
	              NULL);

	return (NMSetting *) g_steal_pointer (&wsec);
}
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

	/* XXX: WEP is not supported with netplan.
	 *   Only 'none', 'psk', 'eap' and '802.1x' as handled by make_wpa_setting().
	wsec = make_wep_setting (nd, file, error);
	if (wsec)
		return wsec;
	else if (*error)
		return NULL;
	*/

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
	cvalue = svGetValue (netplan, "MAC_ADDRESS_RANDOMIZATION", &value);
	if (cvalue) {
		if (strcmp (cvalue, "default") == 0)
			mac_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;
		else if (strcmp (cvalue, "never") == 0)
			mac_randomization = NM_SETTING_MAC_RANDOMIZATION_NEVER;
		else if (strcmp (cvalue, "always") == 0)
			mac_randomization = NM_SETTING_MAC_RANDOMIZATION_ALWAYS;
		else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid MAC_ADDRESS_RANDOMIZATION value '%s'", cvalue);
			g_free (value);
			goto error;
		}
		g_free (value);
	} else
		mac_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;

	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION,
	              mac_randomization,
	              NULL);
#endif  /* MAC address randomization */

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
		/* XXX: Fix/implement fwmask, which is missing in NetplanNetDefinition. */
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
	cvalue = svGetValueStr (netplan, "GENERATE_MAC_ADDRESS_MASK", &value);
	if (cvalue) {
		if (cvalue[0] != '\0') {
			g_object_set (s_wired,
			              NM_SETTING_WIRED_GENERATE_MAC_ADDRESS_MASK,
			              cvalue,
			              NULL);
		}
		nm_clear_g_free (&value);
		found = TRUE;
	}
#endif  /* generate mac address */

#if 0  /* TODO: 802.1x wired settings */
	cvalue = svGetValue (netplan, "KEY_MGMT", &value);
	if (cvalue)
		found = TRUE;
	if (cvalue && cvalue[0] != '\0') {
		if (!strcmp (cvalue, "IEEE8021X")) {
			*s_8021x = fill_8021x (netplan, file, cvalue, FALSE, error);
			if (!*s_8021x)
				return NULL;
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Unknown wired KEY_MGMT type '%s'", cvalue);
			return NULL;
		}
	}
	nm_clear_g_free (&value);
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

	/* TODO: map the other bond_params fields to NM_SETTING_BOND fields */
#if 0
   struct {
        char* lacp_rate;
        guint min_links;
        char* transmit_hash_policy;
        char* selection_logic;
        gboolean all_slaves_active;
        char* arp_validate;
        char* arp_all_targets;
        char* fail_over_mac_policy;
        guint gratuitous_arp;
        /* TODO: unsolicited_na */
        guint packets_per_slave;
        char* primary_reselect_policy;
        guint resend_igmp;
        char* learn_interval;
    } bond_params;
#endif

	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, nd->bond_params.mode);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY, nd->bond_params.primary_slave);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIIMON, nd->bond_params.monitor_interval);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, nd->bond_params.down_delay);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY, nd->bond_params.up_delay);
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL, nd->bond_params.arp_interval);

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
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LACP_RATE, nd->bond_params.lacp_rate);

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
	}

	//g_object_set (s_bridge, NM_SETTING_BRIDGE_PORT_PRIORITY, nd->bridge_params.port_priority, NULL);
	//g_object_set (s_bridge, NM_SETTING_BRIDGE_PORT_PATH_COST, nd->bridge_params.path_cost, NULL);
	
#if 0  /* TODO: add the other bridge params */
	g_object_set (s_bridge, NM_SETTING_BRIDGE_AGEING_TIME, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_MULTICAST_SNOOPING, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_VLAN_FILTERING, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_GROUP_FORWARD_MASK, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID, nd->bridge_params.stp, NULL);
	g_object_set (s_bridge, NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE, nd->bridge_params.stp, NULL);
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

#if 0  /* TODO: bridge-port settings */
static NMSetting *
make_bridge_port_setting (NetplanNetDefinition *nd)
{
	NMSetting *s_port = NULL;
	gs_free char *value_to_free = NULL;
	const char *value;

	g_return_val_if_fail (netplan != NULL, FALSE);

	value = svGetValueStr (netplan, "BRIDGE_UUID", &value_to_free);
	if (!value)
		value = svGetValueStr (netplan, "BRIDGE", &value_to_free);
	if (value) {
		nm_clear_g_free (&value_to_free);

		s_port = nm_setting_bridge_port_new ();
		value = svGetValueStr (netplan, "BRIDGING_OPTS", &value_to_free);
		if (value) {
			handle_bridging_opts (s_port, FALSE, value, handle_bridge_option, BRIDGE_OPT_TYPE_PORT_OPTION);
			nm_clear_g_free (&value_to_free);
		}

		read_bridge_vlans (netplan,
		                   "BRIDGE_PORT_VLANS",
		                   s_port,
		                   NM_SETTING_BRIDGE_PORT_VLANS);
	}

	return s_port;
}
#endif

#if 0  /* TODO: Team device support */
static NMSetting *
make_team_port_setting (NetplanNetDefinition *nd)
{
	NMSetting *s_port;
	gs_free char *value = NULL;

	value = svGetValueStr_cp (netplan, "TEAM_PORT_CONFIG");
	if (!value)
		return NULL;

	s_port = nm_setting_team_port_new ();
	g_object_set (s_port,
	              NM_SETTING_TEAM_PORT_CONFIG,
	              value,
	              NULL);
	return s_port;
}
#endif


#if 0   /* TODO: VLAN Support */
static void
parse_prio_map_list (NMSettingVlan *s_vlan,
                     NetplanNetDefinition *nd,
                     const char *key,
                     NMVlanPriorityMap map)
{
	gs_free char *value = NULL;
	gs_free const char **list = NULL;
	const char *const *iter;
	const char *v;

	v = svGetValueStr (netplan, key, &value);
	if (!v)
		return;
	list = nm_utils_strsplit_set (v, ",");

	for (iter = list; iter && *iter; iter++) {
		if (!strchr (*iter, ':'))
			continue;
		if (!nm_setting_vlan_add_priority_str (s_vlan, map, *iter))
			PARSE_WARNING ("invalid %s priority map item '%s'", key, *iter);
	}
}

static NMSetting *
make_vlan_setting (NetplanNetDefinition *nd,
                   const char *file,
                   GError **error)
{
	gs_unref_object NMSettingVlan *s_vlan = NULL;
	gs_free char *parent = NULL;
	gs_free char *iface_name = NULL;
	gs_free char *value = NULL;
	const char *v = NULL;
	int vlan_id = -1;
	guint32 vlan_flags = 0;
	int gvrp, reorder_hdr;

	v = svGetValueStr (netplan, "VLAN_ID", &value);
	if (v) {
		vlan_id = _nm_utils_ascii_str_to_int64 (v, 10, 0, 4095, -1);
		if (vlan_id == -1) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Invalid VLAN_ID '%s'", v);
			return NULL;
		}
	}

	/* Need DEVICE if we don't have a separate VLAN_ID property */
	iface_name = svGetValueStr_cp (netplan, "DEVICE");
	if (!iface_name && vlan_id < 0) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Missing DEVICE property; cannot determine VLAN ID.");
		return NULL;
	}

	s_vlan = NM_SETTING_VLAN (nm_setting_vlan_new ());

	/* Parent interface from PHYSDEV takes precedence if it exists */
	parent = svGetValueStr_cp (netplan, "PHYSDEV");

	if (iface_name) {
		v = strchr (iface_name, '.');
		if (v) {
			/* eth0.43; PHYSDEV is assumed from it if unknown */
			if (!parent) {
				parent = g_strndup (iface_name, v - iface_name);
				if (g_str_has_prefix (parent, "vlan")) {
					/* Like initscripts, if no PHYSDEV and we get an obviously
					 * invalid parent interface from DEVICE, fail.
					 */
					nm_clear_g_free (&parent);
				}
			}
			v++;
		} else {
			/* format like vlan43; PHYSDEV must be set */
			if (g_str_has_prefix (iface_name, "vlan"))
				v = iface_name + 4;
		}

		if (v) {
			int device_vlan_id;

			/* Grab VLAN ID from interface name; this takes precedence over the
			 * separate VLAN_ID property for backwards compat.
			 */
			device_vlan_id = _nm_utils_ascii_str_to_int64 (v, 10, 0, 4095, -1);
			if (device_vlan_id != -1)
				vlan_id = device_vlan_id;
		}
	}

	if (vlan_id < 0) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Failed to determine VLAN ID from DEVICE or VLAN_ID.");
		return NULL;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_ID, vlan_id, NULL);

	if (parent == NULL) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		                     "Failed to determine VLAN parent from DEVICE or PHYSDEV");
		return NULL;
	}
	g_object_set (s_vlan, NM_SETTING_VLAN_PARENT, parent, NULL);

	vlan_flags |= NM_VLAN_FLAG_REORDER_HEADERS;

	gvrp = svGetValueBoolean (netplan, "GVRP", -1);
	if (gvrp > 0)
		vlan_flags |= NM_VLAN_FLAG_GVRP;

	nm_clear_g_free (&value);
	v = svGetValueStr (netplan, "VLAN_FLAGS", &value);
	if (v) {
		gs_free const char **strv = NULL;
		const char *const *ptr;

		strv = nm_utils_strsplit_set (v, ", ");
		for (ptr = strv; ptr && *ptr; ptr++) {
			if (nm_streq (*ptr, "GVRP") && gvrp == -1)
				vlan_flags |= NM_VLAN_FLAG_GVRP;
			if (nm_streq (*ptr, "LOOSE_BINDING"))
				vlan_flags |=  NM_VLAN_FLAG_LOOSE_BINDING;
			if (nm_streq (*ptr, "NO_REORDER_HDR"))
				vlan_flags &= ~NM_VLAN_FLAG_REORDER_HEADERS;
		}
	}

	reorder_hdr = svGetValueBoolean (netplan, "REORDER_HDR", -1);
	if (   reorder_hdr != -1
	    && reorder_hdr != NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS))
		PARSE_WARNING ("REORDER_HDR key is deprecated, use VLAN_FLAGS");

	if (svGetValueBoolean (netplan, "MVRP", FALSE))
		vlan_flags |= NM_VLAN_FLAG_MVRP;

	g_object_set (s_vlan, NM_SETTING_VLAN_FLAGS, vlan_flags, NULL);

	parse_prio_map_list (s_vlan, netplan, "VLAN_INGRESS_PRIORITY_MAP", NM_VLAN_INGRESS_MAP);
	parse_prio_map_list (s_vlan, netplan, "VLAN_EGRESS_PRIORITY_MAP", NM_VLAN_EGRESS_MAP);

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
	g_return_val_if_fail (netplan != NULL, NULL);

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
#endif

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
	 * nm_connection_verify() later.
	 */
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
	v = svGetValueStr (nd, "SUBCHANNELS", &value);
	if (v) {
		*out_spec = g_strdup_printf ("%s:"NM_MATCH_SPEC_S390_SUBCHANNELS_TAG"%s", type, v);
		return connection;
	}
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
                           const char *test_type,     /* for unit tests only */
                           char **out_unhandled,
                           GError **error,
                           gboolean *out_ignore_error)
{
	NetplanNetDefinition *netdef = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_free char *type = NULL;
	//char *devtype, *bootproto;
	NMSetting *s_ip4, *s_ip6;
	//NMSetting *s_tc, *s_proxy, *s_port, *s_dcb = NULL, *s_user, *s_sriov;
	NMSetting *s_match;
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

	ret = netplan_parse_yaml (filename, error);
	if (ret && network_file)
		ret = netplan_parse_yaml (network_file, error);
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
	if (!svGetValueBoolean (main_netplan, "NM_CONTROLLED", TRUE)) {
		connection = create_unhandled_connection (filename, main_netplan, "unmanaged", out_unhandled);
		if (!connection) {
			NM_SET_OUT (out_ignore_error, TRUE);
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "NM_CONTROLLED was false but device was not uniquely identified; device will be managed");
		}
		return g_steal_pointer (&connection);
	}

	/* iBFT is handled by nm-initrd-generator during boot. */
	bootproto = svGetValueStr_cp (main_netplan, "BOOTPROTO");
	if (bootproto && !g_ascii_strcasecmp (bootproto, "ibft")) {
		NM_SET_OUT (out_ignore_error, TRUE);
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
		             "Ignoring iBFT configuration");
		g_free (bootproto);
		return NULL;
	}
	g_free (bootproto);

	devtype = svGetValueStr_cp (main_netplan, "DEVICETYPE");
	if (devtype) {
		if (!strcasecmp (devtype, TYPE_TEAM))
			type = g_strdup (TYPE_TEAM);
		else if (!strcasecmp (devtype, TYPE_TEAM_PORT)) {
			gs_free char *device = NULL;

			type = svGetValueStr_cp (main_netplan, "TYPE");
			device = svGetValueStr_cp (main_netplan, "DEVICE");

			if (type) {
				/* nothing to do */
			} else if (device && nd->type == NETPLAN_DEF_TYPE_VLAN)
				type = g_strdup (TYPE_VLAN);
			else
				type = g_strdup (TYPE_ETHERNET);
		}
		g_free (devtype);
	}
	if (!type) {
		gs_free char *t = NULL;

		/* Team and TeamPort types are also accepted by the mere
		 * presence of TEAM_CONFIG/TEAM_MASTER. They don't require
		 * DEVICETYPE. */
		t = svGetValueStr_cp (main_netplan, "TEAM_CONFIG");
		if (t)
			type = g_strdup (TYPE_TEAM);
	}

	if (!type)
		type = svGetValueStr_cp (main_netplan, "TYPE");

	if (!type) {
		gs_free char *tmp = NULL;
		char *device;

		if ((tmp = svGetValueStr_cp (main_netplan, "IPV6TUNNELIPV4"))) {
			NM_SET_OUT (out_ignore_error, TRUE);
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Ignoring unsupported connection due to IPV6TUNNELIPV4");
			return NULL;
		}

		device = svGetValueStr_cp (main_netplan, "DEVICE");
		if (!device) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "File '%s' had neither TYPE nor DEVICE keys.", filename);
			return NULL;
		}

		if (!strcmp (device, "lo")) {
			NM_SET_OUT (out_ignore_error, TRUE);
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_INVALID_CONNECTION,
			             "Ignoring loopback device config.");
			g_free (device);
			return NULL;
		}
#endif

#if 0
	} else {
		/* Check for IBM s390 CTC devices and call them Ethernet */
		if (g_strcmp0 (type, "CTC") == 0) {
			g_free (type);
			type = g_strdup (TYPE_ETHERNET);
		}
	}
#endif
	g_hash_table_iter_init (&iter, netdefs);
	g_hash_table_iter_next (&iter, &key, (gpointer) &netdef);
	if (!netdef) {
		_LOGE ("invalid netdef");
		return NULL;
	}
	_LOGT ("netplan netdef %s : %d", (char *) key, netdef->type);


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
#if 0  /* skip for now... */
	case NETPLAN_DEF_TYPE_VLAN:
		connection = vlan_connection_from_netplan (filename, netdef, error);
		break;
#endif
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

#if 0
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

	s_port = make_bridge_port_setting (main_netplan);
	if (s_port)
		nm_connection_add_setting (connection, s_port);

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
                            const char *test_type,
                            char **out_unhandled,
                            GError **error)
{
	return connection_from_file_full (filename,
	                                  network_file,
	                                  test_type,
	                                  out_unhandled,
	                                  error,
	                                  NULL);
}
