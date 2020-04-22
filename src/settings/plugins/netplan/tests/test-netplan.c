// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager settings service - netplan plugin
 *
 * Copyright (C) 2020 Canonical, Ltd.
 * Author: Lukas Märdian <lukas.maerdian@canoncial.com>
 */

#include "nm-default.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <linux/pkt_sched.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <netplan/parse.h>

#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-user.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-8021x.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-ppp.h"
#include "nm-setting-vpn.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-setting-serial.h"
#include "nm-setting-vlan.h"
#include "nm-setting-dcb.h"
#include "nm-core-internal.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

#include "NetworkManagerUtils.h"

#include "settings/plugins/netplan/nms-netplan-reader.h"
#include "settings/plugins/netplan/nms-netplan-writer.h"
#include "settings/plugins/netplan/nms-netplan-utils.h"

#include "nm-test-utils-core.h"

#define TEST_NETPLAN_DIR        NM_BUILD_SRCDIR"/src/settings/plugins/netplan/tests/yaml"
#define TEST_SCRATCH_DIR        NM_BUILD_BUILDDIR"/src/settings/plugins/netplan/tests/yaml"
#define TEST_SCRATCH_DIR_TMP    TEST_SCRATCH_DIR"/tmp"

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_SETTINGS
#define _NMLOG_PREFIX_NAME "test-netplan"
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
_log_keyfile (NMConnection *con)
{
	gs_unref_keyfile GKeyFile *kf = NULL;
	gs_free char *str = NULL;
	kf = nm_keyfile_write (con, NULL, NULL, NULL);
	str = g_key_file_to_data (kf, NULL, NULL);
	printf("===== Keyfile =====\n%s\n===== Keyfile End =====\n", str);
}

static void
_clear_all_netdefs (void)
{
	// Clear all netdefs before each test, so we only access the connection under test.
	if(netdefs) {
		guint n = g_hash_table_size (netdefs);
		// TODO: make sure that any dynamically allocated netdef data is freed
		g_hash_table_remove_all (netdefs);
		_LOGT ("cleared %u prior netdefs", n);
	}
}

static NMConnection *
_connection_from_file (const char *filename,
                       const char *network_file,
                       const char *netdef_id,
                       char **out_unhandled)
{
	NMConnection *connection;
	GError *error = NULL;
	char *unhandled_fallback = NULL;

	g_assert (!out_unhandled || !*out_unhandled);

	/* Clear netdefs before reading new data from file */
	_clear_all_netdefs ();
	connection = nmtst_connection_from_file (filename, network_file, netdef_id,
	                                         out_unhandled ?: &unhandled_fallback, &error);
	g_assert_no_error (error);
	g_assert (!unhandled_fallback);

	if (out_unhandled && *out_unhandled)
		nmtst_assert_connection_verifies (connection);
	else
		nmtst_assert_connection_verifies_without_normalization (connection);
	return connection;
}

/* dummy path for an "expected" file, meaning: don't check for expected
 * written netplan file. */
static const char NO_EXPECTED[1];

static void
_assert_expected_content (NMConnection *connection, const char *filename, const char *expected)
{
	gs_free char *content_expectd = NULL;
	gs_free char *content_written = NULL;
	GError *error = NULL;
	gsize len_expectd = 0;
	gsize len_written = 0;
	gboolean success;
	const char *uuid = NULL;

	g_assert (NM_IS_CONNECTION (connection));
	g_assert (filename);
	g_assert (g_file_test (filename, G_FILE_TEST_EXISTS));

	g_assert (expected);
	if (expected == NO_EXPECTED)
		return;

	success = g_file_get_contents (filename, &content_written, &len_written, &error);
	nmtst_assert_success (success, error);

	success = g_file_get_contents (expected, &content_expectd, &len_expectd, &error);
	nmtst_assert_success (success, error);

	{
		gsize i, j;

		for (i = 0; i < len_expectd; ) {
			if (content_expectd[i] != '$') {
				i++;
				continue;
			}
			if (g_str_has_prefix (&content_expectd[i], "${UUID}")) {
				GString *str;

				if (!uuid) {
					uuid = nm_connection_get_uuid (connection);
					g_assert (uuid);
				}

				j = strlen (uuid);

				str = g_string_new_len (content_expectd, len_expectd);
				g_string_erase (str, i, NM_STRLEN ("${UUID}"));
				g_string_insert_len (str, i, uuid, j);

				g_free (content_expectd);
				len_expectd = str->len;
				content_expectd = g_string_free (str, FALSE);
				i += j;
				continue;
			}

			/* other '$' is not supported. If need be, support escaping of
			 * '$' via '$$'. */
			g_assert_not_reached ();
		}
	}

	if (   len_expectd != len_written
	    || memcmp (content_expectd, content_written, len_expectd) != 0) {
		if (   g_getenv ("NMTST_NETPLAN_UPDATE_EXPECTED")
		    || nm_streq0 (g_getenv ("NM_TEST_REGENERATE"), "1")) {
			if (uuid) {
				gs_free char *search = g_strdup_printf ("UUID=%s\n", uuid);
				const char *s;
				gsize i;
				GString *str;

				s = content_written;
				while (TRUE) {
					s = strstr (s, search);
					g_assert (s);
					if (   s == content_written
					    || s[-1] == '\n')
						break;
					s += strlen (search);
				}

				i = s - content_written;

				str = g_string_new_len (content_written, len_written);
				g_string_erase (str, i, strlen (search));
				g_string_insert (str, i, "UUID=${UUID}\n");

				len_written = str->len;
				content_written = g_string_free (str, FALSE);
			}
			success = g_file_set_contents (expected, content_written, len_written, &error);
			nmtst_assert_success (success, error);
		} else {
			g_error ("The content of \"%s\" (%zu) differs from \"%s\" (%zu). Set NMTST_NETPLAN_UPDATE_EXPECTED=yes to update the files inplace\n\n>>>%s<<<\n\n>>>%s<<<\n",
			         filename, len_written,
			         expected, len_expectd,
			         content_written,
			         content_expectd);
		}
	}
}

static void
_assert_reread_same (NMConnection *connection, NMConnection *reread)
{
	nmtst_assert_connection_verifies_without_normalization (reread);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
_writer_new_connection_no_reread (NMConnection *connection,
                                  const char *netplan_dir,
                                  char **out_filename,
                                  const char *expected)
{
	gboolean success;
	GError *error = NULL;
	char *filename = NULL;
	gs_unref_object NMConnection *con_verified = NULL;

	g_assert (NM_IS_CONNECTION (connection));
	g_assert (netplan_dir);

	/* Duplicate connection and clear current netdefs, to continue testing with a clean state. */
	con_verified = nmtst_connection_duplicate_and_normalize (connection);
	_clear_all_netdefs();

	success = nms_netplan_writer_write_connection (con_verified,
	                                               netplan_dir,
	                                               NULL,
	                                               NULL,
	                                               NULL,
	                                               &filename,
	                                               NULL,
	                                               NULL,
	                                               &error);
	nmtst_assert_success (success, error);
	g_assert (filename && filename[0]);

	_assert_expected_content (con_verified, filename, expected);

	if (out_filename)
		*out_filename = filename;
	else
		g_free (filename);

}

static void
_writer_new_connection_reread (NMConnection *connection,
                               const char *netplan_dir,
                               char **out_filename,
                               const char *expected,
                               NMConnection **out_reread,
                               gboolean *out_reread_same)
{
	gboolean success;
	GError *error = NULL;
	char *filename = NULL;
	gs_unref_object NMConnection *con_verified = NULL;
	gs_unref_object NMConnection *reread_copy = NULL;
	NMConnection **reread = out_reread ?: ((nmtst_get_rand_uint32 () % 2) ? &reread_copy : NULL);

	g_assert (NM_IS_CONNECTION (connection));
	g_assert (netplan_dir);

	/* Duplicate connection and clear current netdefs, to continue testing with a clean state. */
	con_verified = nmtst_connection_duplicate_and_normalize (connection);
	_clear_all_netdefs();

	success = nms_netplan_writer_write_connection (con_verified,
	                                               netplan_dir,
	                                               NULL,
	                                               NULL,
	                                               NULL,
	                                               &filename,
	                                               reread,
	                                               out_reread_same,
	                                               &error);
	nmtst_assert_success (success, error);
	g_assert (filename && filename[0]);

	if (reread)
		nmtst_assert_connection_verifies_without_normalization (*reread);

	_assert_expected_content (con_verified, filename, expected);

	if (out_filename)
		*out_filename = filename;
	else
		g_free (filename);

}

static void
_writer_new_connec_exp (NMConnection *connection,
                        const char *netplan_dir,
                        const char *expected,
                        char **out_filename)
{
	gs_unref_object NMConnection *reread = NULL;
	gboolean reread_same = FALSE;

	_writer_new_connection_reread (connection, netplan_dir, out_filename, expected, &reread, &reread_same);
	_assert_reread_same (connection, reread);
	g_assert (reread_same);
}

static void
_writer_new_connection (NMConnection *connection,
                        const char *netplan_dir,
                        char **out_filename)
{
	_writer_new_connec_exp (connection, netplan_dir, NO_EXPECTED, out_filename);
}

/*****************************************************************************/

static void
test_read_basic_dhcp (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connection = _connection_from_file (TEST_NETPLAN_DIR"/basic-dhcp.yaml",
	                                    NULL, NULL, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert_true (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System basic-dhcp.yaml");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert_true (nm_setting_connection_get_autoconnect (s_con));
	g_assert_cmpint (nm_setting_connection_get_autoconnect_retries (s_con), ==, -1);

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert_true (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* ===== IPv4 SETTING ===== */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	g_assert_true (s_ip4);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip4), ==, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	g_assert_true (nm_setting_ip_config_get_never_default (s_ip4) == FALSE);

	/* ===== IPv6 SETTING ===== */
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert_true (s_ip6);
	g_assert_cmpstr (nm_setting_ip_config_get_method (s_ip6), ==, NM_SETTING_IP6_CONFIG_METHOD_AUTO);
	g_assert_true (nm_setting_ip_config_get_never_default (s_ip6) == FALSE);

	g_object_unref (connection);
}

static void
test_read_ethernet_match_mac (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe };

	connection = _connection_from_file (TEST_NETPLAN_DIR"/ethernet-match-mac.yaml",
	                                    NULL, NULL, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert_true (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "System ethernet-match-mac.yaml");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert_true (nm_setting_connection_get_autoconnect (s_con));
	g_assert_cmpint (nm_setting_connection_get_autoconnect_retries (s_con), ==, -1);

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert_true (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* MAC address */
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert_true (mac);
	g_assert_true (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, ETH_ALEN));

	g_object_unref (connection);
}

static void
test_write_wired_basic (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GError *error = NULL;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "write-test",
	              NM_SETTING_CONNECTION_UUID, "dc6604ee-8924-4439-b9a3-ffda82e53427",
	              NM_SETTING_CONNECTION_STABLE_ID, "stable-id-test",
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "eth42",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, "de:ad:be:ef:ca:fe",
	              NM_SETTING_WIRED_WAKE_ON_LAN, NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);


	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR,
	                        TEST_NETPLAN_DIR"/exp-wired-basic.yaml",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	/* Verify Wake-on-LAN */
	s_wired = nm_connection_get_setting_wired (reread);
	g_assert_true (s_wired);
	g_assert_true (nm_setting_wired_get_wake_on_lan (s_wired) == NM_SETTING_WIRED_WAKE_ON_LAN_NONE);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

static void
test_write_wired_static (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	nmtst_auto_unlinkfile char *route6file = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	guint32 mtu = 1492;
	NMSettingIPConfig *s_ip4, *reread_s_ip4;
	NMSettingIPConfig *s_ip6, *reread_s_ip6;
	NMIPAddress *addr;
	NMIPAddress *addr6;
	NMIPRoute *route6;
	GError *error = NULL;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "write-test-static",
	              NM_SETTING_CONNECTION_UUID, "3f5705e4-bb5b-4e4d-a2f9-e8f44d508ee5",
	              NM_SETTING_CONNECTION_STABLE_ID, "stable-id-test-static",
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "eth42",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, "de:ad:be:ef:ca:fe",
	              NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "00:11:22:33:44:55",
	              // XXX: Netplan will change any flag to DEFAULT, except IGNORE
	              NM_SETTING_WIRED_WAKE_ON_LAN, NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT,
	              NM_SETTING_WIRED_MTU, mtu,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              //NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) 204,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	addr = nm_ip_address_new (AF_INET, "1.1.1.5", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.1");
	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.2");

	nm_setting_ip_config_add_dns_search (s_ip4, "foobar.com");
	nm_setting_ip_config_add_dns_search (s_ip4, "lab.foobar.com");

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NM_SETTING_IP_CONFIG_GATEWAY, "2001:dead:beef::1",
	              //NM_SETTING_IP_CONFIG_ROUTE_METRIC, (gint64) 204,
	              NULL);

	/* Add addresses */
	addr6 = nm_ip_address_new (AF_INET6, "1003:1234:abcd::1", 11, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	addr6 = nm_ip_address_new (AF_INET6, "2003:1234:abcd::2", 22, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	addr6 = nm_ip_address_new (AF_INET6, "3003:1234:abcd::3", 33, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip6, addr6);
	nm_ip_address_unref (addr6);

	/* Add routes */
	route6 = nm_ip_route_new (AF_INET6,
	                          "2222:aaaa:bbbb:cccc::", 64,
	                          "2222:aaaa:bbbb:cccc:dddd:eeee:5555:6666", 99, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip6, route6);
	nm_ip_route_unref (route6);

	route6 = nm_ip_route_new (AF_INET6, "::", 128, "2222:aaaa::9999", 1, &error);
	g_assert_no_error (error);
	//nm_ip_route_set_attribute (route6, NM_IP_ROUTE_ATTRIBUTE_CWND, g_variant_new_uint32 (100));
	//nm_ip_route_set_attribute (route6, NM_IP_ROUTE_ATTRIBUTE_MTU, g_variant_new_uint32 (1280));
	//nm_ip_route_set_attribute (route6, NM_IP_ROUTE_ATTRIBUTE_LOCK_CWND, g_variant_new_boolean (TRUE));
	//nm_ip_route_set_attribute (route6, NM_IP_ROUTE_ATTRIBUTE_FROM, g_variant_new_string ("2222::bbbb/32"));
	//nm_ip_route_set_attribute (route6, NM_IP_ROUTE_ATTRIBUTE_SRC, g_variant_new_string ("::42"));
	//nm_setting_ip_config_add_route (s_ip6, route6);
	nm_ip_route_unref (route6);

	/* DNS servers */
	nm_setting_ip_config_add_dns (s_ip6, "fade:0102:0103::face");
	nm_setting_ip_config_add_dns (s_ip6, "cafe:ffff:eeee:dddd:cccc:bbbb:aaaa:feed");

	/* DNS domains */
	// FIXME: How to differentiate ip4/ip6 search domains??
	//nm_setting_ip_config_add_dns_search (s_ip6, "foobar6.com");
	//nm_setting_ip_config_add_dns_search (s_ip6, "lab6.foobar.com");

	nmtst_assert_connection_verifies (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR,
	                        TEST_NETPLAN_DIR"/exp-wired-static.yaml",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	/* Verify Wake-on-LAN */
	s_wired = nm_connection_get_setting_wired (reread);
	g_assert_true (s_wired);
	// XXX: netplan can only set DEFAULT (wake-on-lan = true) or IGNORE (wake-on-lan = false)
	g_assert_true (nm_setting_wired_get_wake_on_lan (s_wired) == NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

static void
test_write_wired_static_routes (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	nmtst_auto_unlinkfile char *routefile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMIPAddress *addr;
	NMIPRoute *route;
	GError *error = NULL;
	gboolean reread_same = FALSE;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wired Static Routes",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, "31:33:33:37:be:cd",
	              NM_SETTING_WIRED_MTU, (guint32) 1492,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              //NM_SETTING_IP_CONFIG_DAD_TIMEOUT, 400,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	addr = nm_ip_address_new (AF_INET, "1.1.1.5", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* Write out routes */
	route = nm_ip_route_new (AF_INET, "1.2.3.0", 24, "222.173.190.239", 0, &error);
	/* XXX: Needs to be implemented in netplan */
	//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_WINDOW, g_variant_new_uint32 (3455));
	//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_ONLINK, g_variant_new_boolean (TRUE));
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip4, route);
	nm_ip_route_unref (route);

	route = nm_ip_route_new (AF_INET, "3.2.1.0", 24, "202.254.186.190", 77, &error);
	/* XXX: Needs to be implemented in netplan */
	//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_WINDOW, g_variant_new_uint32 (30000));
	//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_ONLINK, g_variant_new_boolean (FALSE));
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip4, route);
	nm_ip_route_unref (route);

	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.1");
	nm_setting_ip_config_add_dns (s_ip4, "4.2.2.2");

	nm_setting_ip_config_add_dns_search (s_ip4, "foobar.com");
	nm_setting_ip_config_add_dns_search (s_ip4, "lab.foobar.com");

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	nmtst_assert_connection_verifies (connection);
	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR,
	                        &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);
	/* XXX: improve test
	_writer_new_connection_reread (connection,
	                               TEST_SCRATCH_DIR,
	                               &testfile,
	                               NULL,//TEST_IFCFG_DIR"/ifcfg-Test_Write_Wired_Static_Routes.cexpected",
	                               &reread,
	                               &reread_same);
								   */
	/* ifcfg does not support setting onlink=0. It gets lost during write+re-read.
	 * Assert that it's missing, and patch it to check whether the rest of the
	 * connection equals. */
	/*
	g_assert (!reread_same);
	nmtst_assert_connection_verifies_without_normalization (reread);
	s_ip4 = nm_connection_get_setting_ip4_config (reread);
	g_assert (s_ip4);
	g_assert_cmpint (nm_setting_ip_config_get_num_routes (s_ip4), ==, 2);
	route = nm_setting_ip_config_get_route (s_ip4, 1);
	g_assert (route);
	g_assert (!nm_ip_route_get_attribute (route, NM_IP_ROUTE_ATTRIBUTE_ONLINK));
	nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_ONLINK, g_variant_new_boolean (FALSE));
	*/
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	//routefile = utils_get_route_path (testfile);
}

static NMIPRoutingRule *
_ip_routing_rule_new (int addr_family,
                      const char *str)
{
	NMIPRoutingRuleAsStringFlags flags = NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE;
	gs_free_error GError *local = NULL;
	NMIPRoutingRule *rule;

	if (addr_family != AF_UNSPEC) {
		if (addr_family == AF_INET)
			flags = NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET;
		else {
			g_assert (addr_family == AF_INET6);
			flags = NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6;
		}
	}

	rule = nm_ip_routing_rule_from_string (str,
	                                       NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
	                                       | flags,
	                                       NULL,
	                                       nmtst_get_rand_bool () ? &local : NULL);
	nmtst_assert_success (rule, local);

	if (addr_family != AF_UNSPEC)
		g_assert_cmpint (nm_ip_routing_rule_get_addr_family (rule), ==, addr_family);
	return rule;
}

static void
_ip_routing_rule_add_to_setting (NMSettingIPConfig *s_ip,
                                 const char *str)
{
	nm_auto_unref_ip_routing_rule NMIPRoutingRule *rule = NULL;

	rule = _ip_routing_rule_new (nm_setting_ip_config_get_addr_family (s_ip), str);
	nm_setting_ip_config_add_routing_rule (s_ip, rule);
}

static void
test_write_routing_rules (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Routing Rules",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));

	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	_ip_routing_rule_add_to_setting (s_ip4, "pref 10 from 0.0.0.0/0 table 1");
	_ip_routing_rule_add_to_setting (s_ip4, "priority 10 to 192.167.8.0/24 table 2");
	_ip_routing_rule_add_to_setting (s_ip6, "pref 10 from ::/0 table 10");
	_ip_routing_rule_add_to_setting (s_ip6, "pref 10 from ::/0 to 1:2:3::5/24 table 22");
	_ip_routing_rule_add_to_setting (s_ip6, "pref 10 from ::/0 to 1:3:3::5/128 table 55");

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection, TEST_SCRATCH_DIR, &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_read_write_wired_dhcp_send_hostname (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char * dhcp_hostname = "some-hostname";

	connection = _connection_from_file (TEST_NETPLAN_DIR"/dhcp-hostname.yaml",
	                                    NULL, NULL, NULL);

	/* Check dhcp-hostname and dhcp-send-hostname */
	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	g_assert (s_ip4);
	g_assert (s_ip6);
	g_assert (nm_setting_ip_config_get_dhcp_send_hostname (s_ip4) == TRUE);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip4), ==, "test-name4");
	g_assert (nm_setting_ip_config_get_dhcp_send_hostname (s_ip6) == TRUE);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip6), ==, "test-name6");

	/* Set dhcp-send-hostname=false dhcp-hostname="some-hostname" and write the connection. */
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, FALSE, NULL);
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, dhcp_hostname, NULL);
	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, FALSE, NULL);
	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, dhcp_hostname, NULL);

	_writer_new_connection (connection, TEST_SCRATCH_DIR, &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	/* Check dhcp-hostname and dhcp-send-hostname from the re-read connection. */
	s_ip4 = nm_connection_get_setting_ip4_config (reread);
	s_ip6 = nm_connection_get_setting_ip6_config (reread);
	g_assert (s_ip4);
	g_assert (s_ip6);
	g_assert (nm_setting_ip_config_get_dhcp_send_hostname (s_ip4) == FALSE);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip4), ==, dhcp_hostname);
	g_assert_cmpstr (nm_setting_ip_config_get_dhcp_hostname (s_ip6), ==, dhcp_hostname);
}

static void
test_write_wifi_band_a (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wi-Fi Band A",
	              NM_SETTING_CONNECTION_UUID, "eda52185-2feb-41d7-a34d-cf7ad470a590",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));
	ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "a",
	              NM_SETTING_WIRELESS_CHANNEL, 7,
	              NM_SETTING_WIRELESS_BSSID, "de:ad:be:ef:ca:fe",
	              NULL);
	g_bytes_unref (ssid);

	nmtst_assert_connection_verifies (connection);
	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR,
	                        TEST_NETPLAN_DIR"/wifi-band-a.yaml",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_wifi_band_bg (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	GBytes *ssid;
	const unsigned char ssid_data[] = { 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x53, 0x49, 0x44 };

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wi-Fi Band BG",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));
	ssid = g_bytes_new (ssid_data, sizeof (ssid_data));
	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NM_SETTING_WIRELESS_BAND, "bg",
	              NM_SETTING_WIRELESS_CHANNEL, 11,
	              NULL);
	g_bytes_unref (ssid);

	nmtst_assert_connection_verifies (connection);
	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR,
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_wifi_wowlan_mac_randomization (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GBytes *ssid;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "wowlan-macrandom",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wireless setting */
	s_wireless = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wireless));
	ssid = g_bytes_new ("open-net", 8);
	g_object_set (s_wireless,
	              //NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION, NM_SETTING_MAC_RANDOMIZATION_ALWAYS, // TODO: needs to be implemented in netplan
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              NM_SETTING_WIRELESS_SSID, ssid,
				  NM_SETTING_WIRELESS_WAKE_ON_WLAN, NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR,
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	/* Verify WoWLan & MAC address randomization */
	s_wireless = nm_connection_get_setting_wireless (reread);
	g_assert_true (s_wireless);
	g_assert_true (nm_setting_wireless_get_wake_on_wlan (s_wireless) == NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL);
	//g_assert_true (nm_setting_wireless_get_mac_address_randomization (s_wireless) == NM_SETTING_MAC_RANDOMIZATION_ALWAYS);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

static void
test_write_bond_main (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingWired *s_wired;
	NMIPAddress *addr;
	GError *error = NULL;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bond Main",
	              NM_SETTING_CONNECTION_UUID, "005688e7-ee1d-4ed4-9bfd-a088ba6e80a9",
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "bond0",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* bond setting */
	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bond));
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, "active-backup");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIN_LINKS, "1");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY, "layer2+3");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_AD_SELECT, "count");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, "1");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_INTERVAL, "1");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_IP_TARGET, "192.168.0.1,192.168.0.2");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_VALIDATE, "all");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS, "all");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_FAIL_OVER_MAC, "active");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, "2");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY_RESELECT, "better");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_RESEND_IGMP, "2");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LP_INTERVAL, "2");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY, "slave0");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	// cannot re-read because of missing slave0 definition
	_writer_new_connection_no_reread (connection,
	                                  TEST_SCRATCH_DIR_TMP,
	                                  &testfile,
	                                  TEST_NETPLAN_DIR"/exp-bond-main.yaml");
	/* Manually re-read with added slave (dummy) interfaces, to make the
	 * netplan parser happy. Explicitly choose the "bond0" netdef. */
	reread = _connection_from_file (testfile,
	                                TEST_NETPLAN_DIR"/add-slaves.yaml",
									"bond0",
	                                NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_bond_rr (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingWired *s_wired;
	NMIPAddress *addr;
	GError *error = NULL;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bond RR",
	              NM_SETTING_CONNECTION_UUID, "005688e7-ee1d-4ed4-9bfd-a088ba6e80a9",
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "bond-rr",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* bond setting */
	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bond));
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, "balance-rr");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MIIMON, "80");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_UPDELAY, "10");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_DOWNDELAY, "5");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, "2");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
	                        TEST_NETPLAN_DIR"/exp-bond-rr.yaml",
	                        &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_bond_lacp (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingBond *s_bond;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSettingWired *s_wired;
	NMIPAddress *addr;
	GError *error = NULL;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bond LACP",
	              NM_SETTING_CONNECTION_UUID, "005688e7-ee1d-4ed4-9bfd-a088ba6e80a9",
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "bond-lacp",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BOND_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* bond setting */
	s_bond = (NMSettingBond *) nm_setting_bond_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bond));
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_MODE, "802.3ad");
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_LACP_RATE, "fast");

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_MANUAL,
	              NM_SETTING_IP_CONFIG_GATEWAY, "1.1.1.1",
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);

	addr = nm_ip_address_new (AF_INET, "1.1.1.3", 24, &error);
	g_assert_no_error (error);
	nm_setting_ip_config_add_address (s_ip4, addr);
	nm_ip_address_unref (addr);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
	                        TEST_NETPLAN_DIR"/exp-bond-lacp.yaml",
	                        &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}


static void
test_write_modem_gsm_auto_eui64 (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingGsm *s_modem;
	NMSettingIPConfig *s_ip4;
	NMSettingIP6Config *s_ip6;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "gsm-auto",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
				  NM_SETTING_CONNECTION_INTERFACE_NAME, "cdc-wdm0",
	              NULL);

	/* Modem setting */
	s_modem = (NMSettingGsm *) nm_setting_gsm_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_modem));
	g_object_set (s_modem, NM_SETTING_GSM_AUTO_CONFIG, TRUE, NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIP6Config *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection, TEST_SCRATCH_DIR, &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	/* Verify auto-config was written & re-read correctly. */
	s_modem = nm_connection_get_setting_gsm (reread);
	g_assert_true (s_modem);
	g_assert_true (nm_setting_gsm_get_auto_config (s_modem));

	/* Verify eui64 was written & re-read correctly. */
	s_ip6 = (NMSettingIP6Config *) nm_connection_get_setting_ip6_config (reread);
	g_assert_true (s_ip6);
	g_assert_true (nm_setting_ip6_config_get_addr_gen_mode (s_ip6) == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

static void
test_write_modem_gsm (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingGsm *s_modem;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "gsm",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
				  NM_SETTING_CONNECTION_INTERFACE_NAME, "cdc-wdm0",
	              NULL);

	/* Modem setting */
	s_modem = (NMSettingGsm *) nm_setting_gsm_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_modem));
	g_object_set (s_modem,
	              NM_SETTING_GSM_AUTO_CONFIG, FALSE,
	              NM_SETTING_GSM_APN, "internet",
	              NM_SETTING_GSM_DEVICE_ID, "dev-123",
	              NM_SETTING_GSM_NETWORK_ID, "123456",
	              NM_SETTING_GSM_PIN, "0000",
	              NM_SETTING_GSM_SIM_ID, "sim-123",
	              NM_SETTING_GSM_SIM_OPERATOR_ID, "123456",
	              NM_SETTING_GSM_NUMBER, "*99#",
	              NM_SETTING_GSM_USERNAME, "user",
	              NM_SETTING_GSM_PASSWORD, "passw0rd",
	              NM_SETTING_GSM_MTU, 1600,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection, TEST_SCRATCH_DIR, &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

static void
test_write_modem_cdma (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingCdma *s_modem;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "cdma",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_CDMA_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "cdc-wdm0",
	              NULL);

	/* Modem setting */
	s_modem = (NMSettingCdma *) nm_setting_cdma_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_modem));
	g_object_set (s_modem,
	              NM_SETTING_GSM_NUMBER, "*99#",
	              NM_SETTING_GSM_USERNAME, "user",
	              NM_SETTING_GSM_PASSWORD, "passw0rd",
	              NM_SETTING_GSM_MTU, 1600,
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));
	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection, TEST_SCRATCH_DIR, &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

static void
test_example_field_wifi (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wireless;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	GBytes *ssid;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "H369AAB53B0",
	              NM_SETTING_CONNECTION_UUID, "cbe5d88b-b891-48e5-af35-3397891cea62",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              //NM_SETTING_CONNECTION_PERMISSIONS, "",
	              //NM_SETTING_CONNECTION_SECONDARIES, "",
	              NULL);

	/* Wireless setting */
	s_wireless = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wireless));
	ssid = g_bytes_new ("H369AAB53B0", 11);
	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_MAC_ADDRESS, "00:23:A7:FA:76:E4",
	              //NM_SETTING_WIRELESS_MAC_ADDRESS_BLACKLIST, "",
	              NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION, 0,
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              //NM_SETTING_WIRELESS_SEEN_BSSIDS, "",
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NULL);

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              //NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open", // XXX: This seems to be invalid: Only valid for WEP, not WPA-PSK
	              //NM_SETTING_WIRELESS_SECURITY_GROUP, "",
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              //NM_SETTING_WIRELESS_SECURITY_PAIRWISE, ""
	              //NM_SETTING_WIRELESS_SECURITY_PROTO, "",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "passw0rd",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              //TODO: dns-search=
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY,
	              //TODO: dns-search=
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR,
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

static void
test_example_field_lte (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	_clear_all_netdefs ();
	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "lte",
	              NM_SETTING_CONNECTION_UUID, "b22d8f0f-3f34-46bd-ac28-801fa87f1eb6",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "cdc-wdm0",
	              //NM_SETTING_CONNECTION_PERMISSIONS, "",
	              //NM_SETTING_CONNECTION_SECONDARIES, "",
	              NULL);

	/* Modem setting */
	s_gsm = (NMSettingGsm *) nm_setting_gsm_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_gsm));
	g_object_set (s_gsm,
	              NM_SETTING_GSM_APN, "bicsapn",
				  NM_SETTING_GSM_NUMBER, "*99#",
	              NULL);

	/* IP4 setting */
	s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip4));
	g_object_set (s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              //TODO: dns-search=
	              NULL);

	/* IP6 setting */
	s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_ip6));

	g_object_set (s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE, NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY,
	              //TODO: dns-search=
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR,
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_equals (connection, FALSE, reread, FALSE);
}

/*****************************************************************************/

#define TPATH "/settings/plugins/neptlan/"

NMTST_DEFINE ();

int main (int argc, char **argv)
{
	int errsv;

	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	if (g_mkdir_with_parents (TEST_SCRATCH_DIR_TMP, 0755) != 0) {
		errsv = errno;
		g_error ("failure to create test directory \"%s\": %s", TEST_SCRATCH_DIR_TMP, nm_strerror_native (errsv));
	}

	g_test_add_func (TPATH "basic-dhcp", test_read_basic_dhcp);
	g_test_add_func (TPATH "ethernet-match-mac", test_read_ethernet_match_mac);
	g_test_add_func (TPATH "read-dhcp-send-hostname", test_read_write_wired_dhcp_send_hostname);

	g_test_add_func (TPATH "wired/write/basic", test_write_wired_basic);
	g_test_add_func (TPATH "wired/write/static", test_write_wired_static);
	g_test_add_func (TPATH "wired/write/routes", test_write_wired_static_routes);
	g_test_add_func (TPATH "wired/write/routing-policy", test_write_routing_rules);

	g_test_add_func (TPATH "wifi/write/band-a", test_write_wifi_band_a);
	g_test_add_func (TPATH "wifi/write/band-bg", test_write_wifi_band_bg);
	g_test_add_func (TPATH "wifi/write/wowlan-macrandom", test_wifi_wowlan_mac_randomization);

	g_test_add_func (TPATH "bond/write/main" , test_write_bond_main);
	g_test_add_func (TPATH "bond/write/rr" , test_write_bond_rr);
	g_test_add_func (TPATH "bond/write/lacp" , test_write_bond_lacp);

	g_test_add_func (TPATH "modem/write/gsm-auto-eui64", test_write_modem_gsm_auto_eui64);
	g_test_add_func (TPATH "modem/write/gsm", test_write_modem_gsm);
	g_test_add_func (TPATH "modem/write/cdma", test_write_modem_cdma);

	g_test_add_func (TPATH "example/field/wifi", test_example_field_wifi);
	g_test_add_func (TPATH "example/field/lte", test_example_field_lte);

	return g_test_run ();
}
