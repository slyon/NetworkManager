// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager settings service - netplan plugin
 *
 * Lukas Märdian <lukas.maerdian@canoncial.com>
 *
 * Copyright (C) 2020 Canonical, Ltd..
 */

#include "netplan-test-utils.h"

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

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);
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

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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
	/* TODO: Needs to be implemented in netplan. */
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
	/* FIXME: How to differentiate ip4/ip6 search domains in netplan? */
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

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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
	/* TODO: Needs to be implemented in netplan. */
	//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_WINDOW, g_variant_new_uint32 (3455));
	//nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_ONLINK, g_variant_new_boolean (TRUE));
	g_assert_no_error (error);
	nm_setting_ip_config_add_route (s_ip4, route);
	nm_ip_route_unref (route);

	route = nm_ip_route_new (AF_INET, "3.2.1.0", 24, "202.254.186.190", 77, &error);
	/* TODO: Needs to be implemented in netplan. */
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

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

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
test_write_wifi_main (void)
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
	guint32 mtu = 1492;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write WiFi Main",
	              NM_SETTING_CONNECTION_UUID, "d5515a99-c7f1-4fd3-bc49-ecfd5ba01c93",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wireless setting */
	s_wireless = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wireless));
	ssid = g_bytes_new ("my-net", 6);
	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_MAC_ADDRESS, "de:ad:be:ef:ca:fe",
	              NM_SETTING_WIRELESS_CLONED_MAC_ADDRESS, "00:11:22:33:44:55",
	              NM_SETTING_WIRELESS_MTU, mtu,
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NULL);

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "s0s3cr3t",
	              NULL);

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);
	nmtst_assert_connection_verifies (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
	                        TEST_NETPLAN_DIR"/exp-wifi-main.yaml",
	                        &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_wifi_hotspot (void)
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

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Hotspot",
	              NM_SETTING_CONNECTION_UUID, "68a4746f-9ad9-409e-8b80-c5944806a1a5",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              //NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "wlan0",
	              NULL);

	/* Wireless setting */
	s_wireless = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wireless));
	ssid = g_bytes_new ("hotspot-test", 12);
	g_object_set (s_wireless,
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_AP,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NULL);

	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));
	g_object_set (s_wsec,
	              NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk",
	              NM_SETTING_WIRELESS_SECURITY_PSK, "s0s3cr3t",
	              NULL);
	nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	nm_setting_wireless_security_add_group (s_wsec, "ccmp");
	nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");

	/* Add IP4/6 settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);
	g_object_set (s_ip4, NM_SETTING_IP_CONFIG_METHOD,
	              NM_SETTING_IP4_CONFIG_METHOD_SHARED,
	              NULL);
	g_object_set (s_ip6, NM_SETTING_IP_CONFIG_METHOD,
	              NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
	              NULL);
	nmtst_assert_connection_verifies (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
	                        TEST_NETPLAN_DIR"/exp-wifi-hotspot.yaml",
	                        &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_wifi_wpa_eap_tls (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	nmtst_auto_unlinkfile char *keyfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	gboolean success;
	GError *error = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WPA EAP-TLS",
	              NM_SETTING_CONNECTION_UUID, "aeb01292-957c-4f84-8f74-4a94d15b47b2",
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap",
	              /* TODO: Needs to be implemented in netplan. */
	              //NM_SETTING_WIRELESS_SECURITY_FILS, (int) NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED,
	              NULL);

	/* TODO: Needs to be implemented in netplan. */
	//nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	//nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	//nm_setting_wireless_security_add_group (s_wsec, "tkip");

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x, NM_SETTING_802_1X_IDENTITY, "Bill Smith", NULL);
	/* TODO: Needs to be implemented in netplan. */
	//g_object_set (s_8021x,
	//              NM_SETTING_802_1X_PHASE1_AUTH_FLAGS,
	//              (guint) (NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_0_DISABLE |
	//                       NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_1_DISABLE),
	//              NULL);

	nm_setting_802_1x_add_eap_method (s_8021x, "tls");

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_NETPLAN_WIFI_WPA_EAP_TLS_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_client_cert (s_8021x,
	                                             TEST_NETPLAN_WIFI_WPA_EAP_TLS_CLIENT_CERT,
	                                             NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             TEST_NETPLAN_WIFI_WPA_EAP_TLS_PRIVATE_KEY,
	                                             "test1",
	                                             NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);
	nmtst_assert_connection_verifies (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
	                        TEST_NETPLAN_DIR"/exp-wifi-eap-tls.yaml",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_wifi_wpa_eap_ttls_mschapv2 (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	nmtst_auto_unlinkfile char *keyfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSetting8021x *s_8021x;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	gboolean success;
	GError *error = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WPA EAP-TTLS (MSCHAPv2)",
	              NM_SETTING_CONNECTION_UUID, "2ac5e61f-990a-48b5-97a1-8c3e9e155fb4",
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);
	/* TODO: Needs to be implemented in netplan. */
	//nm_setting_wireless_security_add_proto (s_wsec, "wpa");
	//nm_setting_wireless_security_add_proto (s_wsec, "rsn");
	//nm_setting_wireless_security_add_pairwise (s_wsec, "tkip");
	//nm_setting_wireless_security_add_pairwise (s_wsec, "ccmp");
	//nm_setting_wireless_security_add_group (s_wsec, "tkip");
	//nm_setting_wireless_security_add_group (s_wsec, "ccmp");

	/* Wireless security setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	nm_setting_802_1x_add_eap_method (s_8021x, "ttls");

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, "Bill Smith",
	              NM_SETTING_802_1X_PASSWORD, ";alkdfja;dslkfjsad;lkfjsadf",
	              NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "foobar22",
	              NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2",
	              NULL);

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_NETPLAN_WIFI_WPA_EAP_TLS_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	nmtst_assert_success (success, error);

	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
	                        TEST_NETPLAN_DIR"/exp-wifi-eap-ttls.yaml",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_wifi_wpa_eap_peap (void)
{
	nmtst_auto_unlinkfile char *keyfile = NULL;
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;
	NMSetting8021x *s_8021x;
	gboolean success;
	GError *error = NULL;
	GBytes *ssid;
	const char *ssid_data = "blahblah";

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Wifi WPA EAP-PEAP (MSCHAPv2)",
	              NM_SETTING_CONNECTION_UUID, "24c60a6a-dfcd-4992-a454-2c7fab53cebc",
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	              NULL);

	/* Wifi setting */
	s_wifi = (NMSettingWireless *) nm_setting_wireless_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wifi));

	ssid = g_bytes_new (ssid_data, strlen (ssid_data));

	g_object_set (s_wifi,
	              NM_SETTING_WIRELESS_SSID, ssid,
	              NM_SETTING_WIRELESS_MODE, "infrastructure",
	              NULL);

	g_bytes_unref (ssid);

	/* Wireless security setting */
	s_wsec = (NMSettingWirelessSecurity *) nm_setting_wireless_security_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wsec));

	g_object_set (s_wsec, NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap", NULL);

	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

	/* 802.1x setting */
	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_8021x));

	g_object_set (s_8021x,
	              NM_SETTING_802_1X_IDENTITY, "Bob Saget",
	              NM_SETTING_802_1X_ANONYMOUS_IDENTITY, "barney",
	              NM_SETTING_802_1X_PASSWORD, "Kids, it was back in October 2008...",
	              /* TODO: Needs to be implemented in netplan. */
	              //NM_SETTING_802_1X_PHASE1_PEAPVER, "1",
	              //NM_SETTING_802_1X_PHASE1_PEAPLABEL, "1",
	              NM_SETTING_802_1X_PHASE2_AUTH, "mschapv2",
	              NULL);

	nm_setting_802_1x_add_eap_method (s_8021x, "peap");

	success = nm_setting_802_1x_set_ca_cert (s_8021x,
	                                         TEST_NETPLAN_WIFI_WPA_EAP_PEAP_CA_CERT,
	                                         NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                         NULL,
	                                         &error);
	nmtst_assert_success (success, error);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
	                        TEST_NETPLAN_DIR"/exp-wifi-eap-peap.yaml",
	                        &testfile);

	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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
	              /* TODO: Needs to be implemented in netplan. */
	              //NM_SETTING_WIRELESS_MAC_ADDRESS_RANDOMIZATION, NM_SETTING_MAC_RANDOMIZATION_ALWAYS,
	              NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	              NM_SETTING_WIRELESS_SSID, ssid,
				  NM_SETTING_WIRELESS_WAKE_ON_WLAN, NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL,
	              NULL);

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);
	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection,
	                        TEST_SCRATCH_DIR,
	                        &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	/* Verify WoWLan & MAC address randomization */
	s_wireless = nm_connection_get_setting_wireless (reread);
	g_assert_true (s_wireless);
	g_assert_true (nm_setting_wireless_get_wake_on_wlan (s_wireless) == NM_SETTING_WIRELESS_WAKE_ON_WLAN_ALL);
	/* TODO: Needs to be implemented in netplan. */
	//g_assert_true (nm_setting_wireless_get_mac_address_randomization (s_wireless) == NM_SETTING_MAC_RANDOMIZATION_ALWAYS);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_bridge_main (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingBridge *s_bridge;
	NMSettingIPConfig *s_ip4, *s_ip6;
	NMSettingWired *s_wired;
	NMIPAddress *addr;
	static const char *mac = "31:33:33:37:be:cd";
	GError *error = NULL;
	gs_unref_ptrarray GPtrArray *vlans = NULL;
	NMBridgeVlan *vlan;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bridge Main",
	              NM_SETTING_CONNECTION_UUID, "965e4838-253f-4291-9eda-6bb46cd4b6c8",
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "br0",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NULL);

	/* bridge setting */
	s_bridge = (NMSettingBridge *) nm_setting_bridge_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_bridge));

	/* TODO: Needs to be implemented in netplan. */
	//vlans = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_bridge_vlan_unref);
	//vlan = nm_bridge_vlan_new (10, 16);
	//nm_bridge_vlan_set_untagged (vlan, TRUE);
	//g_ptr_array_add (vlans, vlan);
	//vlan = nm_bridge_vlan_new (22, 22);
	//nm_bridge_vlan_set_pvid (vlan, TRUE);
	//nm_bridge_vlan_set_untagged (vlan, TRUE);
	//g_ptr_array_add (vlans, vlan);
	//vlan = nm_bridge_vlan_new (44, 0);
	//g_ptr_array_add (vlans, vlan);

	g_object_set (s_bridge,
	              NM_SETTING_BRIDGE_MAC_ADDRESS, mac,
	              NM_SETTING_BRIDGE_AGEING_TIME, 100,
	              NM_SETTING_BRIDGE_PRIORITY, 1024,
	              NM_SETTING_BRIDGE_FORWARD_DELAY, 10,
	              NM_SETTING_BRIDGE_HELLO_TIME, 5,
	              NM_SETTING_BRIDGE_MAX_AGE, 10,
	              NM_SETTING_BRIDGE_STP, TRUE,
	              /* TODO: Needs to be implemented in netplan. */
	              //NM_SETTING_BRIDGE_VLANS, vlans,
	              //NM_SETTING_BRIDGE_VLAN_FILTERING, TRUE,
	              //NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID, 4000,
	              //NM_SETTING_BRIDGE_GROUP_FORWARD_MASK, 19008,
	              NULL);

	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	nm_connection_add_setting (connection, nm_setting_proxy_new ());
	nmtst_assert_connection_verifies_without_normalization (connection);

	_writer_new_connec_exp (connection,
	                        TEST_SCRATCH_DIR_TMP,
							TEST_NETPLAN_DIR"/exp-bridge-main.yaml",
	                        &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
}

static void
test_write_bridge_port (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;
	NMSetting *s_port;
	guint32 i;
	//gs_unref_ptrarray GPtrArray *vlans = NULL;
	//NMBridgeVlan *vlan;

	connection = nm_simple_connection_new ();
	g_assert (connection);

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write Bridge Port",
	              NM_SETTING_CONNECTION_UUID, "d146971d-c5f4-4452-95f7-b8e9b9e4e310",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_MASTER, "br0",
	              NM_SETTING_CONNECTION_SLAVE_TYPE, NM_SETTING_BRIDGE_SETTING_NAME,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "slave0",
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));
	g_object_set (s_wired,
	              NM_SETTING_WIRED_WAKE_ON_LAN, NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
	              NULL);

	/* TODO: Needs to be implemented in netplan. */
	//vlans = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_bridge_vlan_unref);
	//vlan = nm_bridge_vlan_new (1, 0);
	//nm_bridge_vlan_set_untagged (vlan, TRUE);
	//g_ptr_array_add (vlans, vlan);
	//vlan = nm_bridge_vlan_new (4, 4094);
	//nm_bridge_vlan_set_untagged (vlan, TRUE);
	//g_ptr_array_add (vlans, vlan);
	//vlan = nm_bridge_vlan_new (2, 2);
	//nm_bridge_vlan_set_pvid (vlan, TRUE);
	//g_ptr_array_add (vlans, vlan);

	/* Bridge port */
	s_port = nm_setting_bridge_port_new ();
	nm_connection_add_setting (connection, s_port);
	g_object_set (s_port,
	              NM_SETTING_BRIDGE_PORT_PRIORITY, 50,
	              NM_SETTING_BRIDGE_PORT_PATH_COST, 33,
	              /* TODO: Needs to be implemented in netplan. */
	              //NM_SETTING_BRIDGE_PORT_VLANS, vlans,
	              NULL);

	nmtst_assert_connection_verifies (connection);

	_writer_new_connection_no_reread (connection,
	                                  TEST_SCRATCH_DIR_TMP,
	                                  &testfile,
	                                  TEST_NETPLAN_DIR"/exp-bridge-port.yaml");
	/* Manually re-read with added (dummy) bridge iface, to make the
	 * netplan parser happy. Explicitly choose the "slave0" netdef. */
	reread = _connection_from_file (testfile,
	                                TEST_NETPLAN_DIR"/add-bridge.yaml",
									"slave0",
	                                NULL);
	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);

	/* Re-read again, to verify the bridge-port parameters of "slave1"
	 * (from "add-bridge.yaml") still exist and were not overwritten. */
	reread = _connection_from_file (testfile,
	                                TEST_NETPLAN_DIR"/add-bridge.yaml",
									"slave1",
	                                NULL);
	s_port = NM_SETTING (nm_connection_get_setting_bridge_port (reread));
	g_assert_true (s_port);
	i = nm_setting_bridge_port_get_priority (NM_SETTING_BRIDGE_PORT(s_port));
	g_assert_cmpint (i, ==, 44);
}

static void
test_write_vlan (void)
{
	nmtst_auto_unlinkfile char *testfile = NULL;
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object NMConnection *reread = NULL;
	NMSettingConnection *s_con;
	NMSettingVlan *s_vlan;
	NMSettingWired *s_wired;
	NMSettingIPConfig *s_ip4;
	NMSettingIPConfig *s_ip6;

	connection = nm_simple_connection_new ();

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test Write VLAN",
	              NM_SETTING_CONNECTION_UUID, "0f9f128b-3f77-4ff3-806d-bc1e85621c99",
	              /* TODO: Needs to be implemented in netplan. */
	              //NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_VLAN_SETTING_NAME,
				  NM_SETTING_CONNECTION_INTERFACE_NAME, "enred",
	              NULL);

	/* Wired setting */
	s_wired = (NMSettingWired *) nm_setting_wired_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_wired));

	/* VLAN setting */
	s_vlan = (NMSettingVlan *) nm_setting_vlan_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_vlan));
	g_object_set (s_vlan,
	              NM_SETTING_VLAN_PARENT, "eno1",
	              NM_SETTING_VLAN_ID, 42,
	              /* TODO: Needs to be implemented in netplan. */
	              //NM_SETTING_VLAN_FLAGS, 1,
	              NULL);

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

	/* Cannot re-read because of missing eno1 definition. */
	_writer_new_connection_no_reread (connection,
	                                  TEST_SCRATCH_DIR_TMP,
	                                  &testfile,
	                                  TEST_NETPLAN_DIR"/exp-vlan-write.yaml");
	/* Manually re-read with added base (dummy) interfaces, to make the
	 * netplan parser happy. Explicitly choose the "enred" netdef. */
	reread = _connection_from_file (testfile,
	                                TEST_NETPLAN_DIR"/add-base-iface.yaml",
									"enred",
	                                NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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
	nm_setting_bond_add_option (s_bond, NM_SETTING_BOND_OPTION_PRIMARY, "eno1");

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

	/* Cannot re-read because of missing eno1 definition. */
	_writer_new_connection_no_reread (connection,
	                                  TEST_SCRATCH_DIR_TMP,
	                                  &testfile,
	                                  TEST_NETPLAN_DIR"/exp-bond-main.yaml");
	/* Manually re-read with added base (dummy) interfaces, to make the
	 * netplan parser happy. Explicitly choose the "bond0" netdef. */
	reread = _connection_from_file (testfile,
	                                TEST_NETPLAN_DIR"/add-base-iface.yaml",
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

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

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

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);

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

	/* Add generic IP4/6 DHCP settings. */
	_add_ip_auto_settings (connection, &s_ip4, &s_ip6);
	nmtst_assert_connection_verifies (connection);

	_writer_new_connection (connection, TEST_SCRATCH_DIR, &testfile);
	reread = _connection_from_file (testfile, NULL, NULL, NULL);

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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
	              /* XXX: AUTH_ALG=open seems to be invalid for WPA-PSK. */
	              //NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
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

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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

	nmtst_assert_connection_equals (connection, TRUE, reread, FALSE);
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

	g_test_add_func (TPATH "wifi/write/main", test_write_wifi_main);
	g_test_add_func (TPATH "wifi/write/hotspot", test_write_wifi_hotspot);
	g_test_add_func (TPATH "wifi/write/eap-tls", test_write_wifi_wpa_eap_tls);
	g_test_add_func (TPATH "wifi/write/eap-ttls", test_write_wifi_wpa_eap_ttls_mschapv2);
	g_test_add_func (TPATH "wifi/write/eap-peap", test_write_wifi_wpa_eap_peap);
	g_test_add_func (TPATH "wifi/write/band-a", test_write_wifi_band_a);
	g_test_add_func (TPATH "wifi/write/band-bg", test_write_wifi_band_bg);
	g_test_add_func (TPATH "wifi/write/wowlan-macrandom", test_wifi_wowlan_mac_randomization);

	g_test_add_func (TPATH "bridge/write/main", test_write_bridge_main);
	g_test_add_func (TPATH "bridge/write/port", test_write_bridge_port);

	g_test_add_func (TPATH "vlan/write/main", test_write_vlan);

	g_test_add_func (TPATH "bond/write/main", test_write_bond_main);
	g_test_add_func (TPATH "bond/write/rr", test_write_bond_rr);
	g_test_add_func (TPATH "bond/write/lacp", test_write_bond_lacp);

	/* Modem/GSM/CDMA/LTE tests can be re-enabled after netplan.io 0.101-0ubuntu3 is deployed
	g_test_add_func (TPATH "modem/write/gsm-auto-eui64", test_write_modem_gsm_auto_eui64);
	g_test_add_func (TPATH "modem/write/gsm", test_write_modem_gsm);
	g_test_add_func (TPATH "modem/write/cdma", test_write_modem_cdma);
	*/

	g_test_add_func (TPATH "example/field/wifi", test_example_field_wifi);
	//g_test_add_func (TPATH "example/field/lte", test_example_field_lte);

	return g_test_run ();
}
