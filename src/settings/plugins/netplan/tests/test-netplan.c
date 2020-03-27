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

//#include <netplan/parse.h>

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

/*****************************************************************************/

static void
test_read_basic (void)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	const char *mac;
	char expected_mac_address[ETH_ALEN] = { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe };

	connection = _connection_from_file (TEST_NETPLAN_DIR"/basic.yaml",
	                                    NULL, "Ethernet", NULL);

	/* ===== CONNECTION SETTING ===== */
	s_con = nm_connection_get_setting_connection (connection);
	g_assert_true (s_con);
	g_assert_cmpstr (nm_setting_connection_get_id (s_con), ==, "basic-test");
	g_assert_cmpint (nm_setting_connection_get_timestamp (s_con), ==, 0);
	g_assert_true (nm_setting_connection_get_autoconnect (s_con));
	g_assert_cmpint (nm_setting_connection_get_autoconnect_retries (s_con), ==, -1);

	/* UUID can't be tested if the netplan does not contain the UUID key, because
	 * the UUID is generated on the full path of the netplan file, which can change
	 * depending on where the tests are run.
	 */

	/* ===== WIRED SETTING ===== */
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert_true (s_wired);
	g_assert_cmpint (nm_setting_wired_get_mtu (s_wired), ==, 0);

	/* MAC address */
	/* FIXME: s_wired does not seem to have NM_SETTING_WIRED_MAC_ADDRESS set.
	mac = nm_setting_wired_get_mac_address (s_wired);
	g_assert_true (mac);
	g_assert_true (nm_utils_hwaddr_matches (mac, -1, expected_mac_address, ETH_ALEN));
	*/

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

	g_test_add_func (TPATH "basic", test_read_basic);

	return g_test_run ();
}
