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

static NMConnection *
_connection_from_file (const char *filename,
                       const char *network_file,
                       const char *test_type,
                       char **out_unhandled)
{
	NMConnection *connection;
	GError *error = NULL;
	char *unhandled_fallback = NULL;

	g_assert (!out_unhandled || !*out_unhandled);

	connection = nmtst_connection_from_file (filename, network_file, test_type,
	                                         out_unhandled ?: &unhandled_fallback, &error);
	g_assert_no_error (error);
	g_assert (!unhandled_fallback);

	if (out_unhandled && *out_unhandled)
		nmtst_assert_connection_verifies (connection);
	else
		nmtst_assert_connection_verifies_without_normalization (connection);
	return connection;
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

/* dummy path for an "expected" file, meaning: don't check for expected
 * written ifcfg file. */
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

	con_verified = nmtst_connection_duplicate_and_normalize (connection);

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

	_clear_all_netdefs ();
	connection = _connection_from_file (TEST_NETPLAN_DIR"/basic-dhcp.yaml",
	                                    TEST_NETPLAN_DIR"/wired-default.yaml",
										NULL, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert_true (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "wired-default");
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

	_clear_all_netdefs ();
	connection = _connection_from_file (TEST_NETPLAN_DIR"/ethernet-match-mac.yaml",
	                                    NULL, NULL, NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert_true (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "eth0");
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
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
				  NM_SETTING_CONNECTION_STABLE_ID, "stable-id-test",
				  NM_SETTING_CONNECTION_INTERFACE_NAME, "eth42",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, "de:ad:be:ef:ca:fe",
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

	_clear_all_netdefs ();
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

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
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
				  NM_SETTING_CONNECTION_STABLE_ID, "stable-id-test-static",
				  NM_SETTING_CONNECTION_INTERFACE_NAME, "eth42",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	g_object_set (s_wired,
	              NM_SETTING_WIRED_MAC_ADDRESS, "de:ad:be:ef:ca:fe",
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
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR,
	                        &testfile);

	_clear_all_netdefs ();
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

	g_test_add_func (TPATH "wired/write/basic", test_write_wired_basic);
	g_test_add_func (TPATH "wired/write/static", test_write_wired_static);

	return g_test_run ();
}
