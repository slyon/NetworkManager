// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager settings service - netplan plugin
 *
 * Lukas Märdian <lukas.maerdian@canoncial.com>
 * 
 * Copyright (C) 2020 Canonical, Ltd..
 */

#ifndef __NETPLAN_TEST_UTILS_H__
#define __NETPLAN_TEST_UTILS_H__

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

#define TEST_NETPLAN_WIFI_WPA_EAP_TLS_CA_CERT TEST_NETPLAN_DIR"/test_ca_cert.pem"
#define TEST_NETPLAN_WIFI_WPA_EAP_TLS_CLIENT_CERT TEST_NETPLAN_DIR"/test1_key_and_cert.pem"
#define TEST_NETPLAN_WIFI_WPA_EAP_TLS_PRIVATE_KEY TEST_NETPLAN_DIR"/test1_key_and_cert.pem"
#define TEST_NETPLAN_WIFI_WPA_EAP_PEAP_CA_CERT TEST_NETPLAN_DIR"/test_ca_cert.pem"

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

/*****************************************************************************/

static void
_add_ip_auto_settings (NMConnection *connection,
                       NMSettingIPConfig **s_ip4,
                       NMSettingIPConfig **s_ip6)
{
	/* IP4 setting */
	*s_ip4 = (NMSettingIPConfig *) nm_setting_ip4_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (*s_ip4));
	g_object_set (*s_ip4,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NULL);

	/* IP6 setting */
	*s_ip6 = (NMSettingIPConfig *) nm_setting_ip6_config_new ();
	nm_connection_add_setting (connection, NM_SETTING (*s_ip6));
	g_object_set (*s_ip6,
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NULL);
}

#endif /* __NETPLAN_TEST_UTILS_H__ */
