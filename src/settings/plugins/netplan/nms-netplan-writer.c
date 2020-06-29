// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 * Lukas Märdian <lukas.maerdian@canonical.com>
 *
 * Copyright (C) 2019-2020 Canonical Ltd..
 */

#include "nm-default.h"

#include "nms-netplan-writer.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include <gio/gio.h>
#include <netplan/parse.h>

#include "nm-glib-aux/nm-enum-utils.h"
#include "nm-glib-aux/nm-io-utils.h"
#include "nm-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-8021x.h"
#include "nm-setting-proxy.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-vlan.h"
#include "nm-setting-user.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"
#include "nm-meta-setting.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

#include "nms-netplan-reader.h"
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

/*****************************************************************************/

static void
write_array_to_sequence (GArray* arr, GOutputStream* s, char* start)
{
	g_output_stream_printf(s, 0, NULL, NULL, "%s [", start);
	for (unsigned i = 0; i < arr->len; ++i) {
		g_output_stream_printf(s, 0, NULL, NULL, "%s",
								g_array_index(arr, char*, i));
		if (i < arr->len-1)
			g_output_stream_printf(s, 0, NULL, NULL, ", ");
	}
	g_output_stream_printf(s, 0, NULL, NULL, "]\n");
}

static struct HashToDict {
	GOutputStream* stream;
	char* indent;
} HashToDict;

static void
write_hashtable_to_dict (gpointer key, gpointer value, gpointer user_data)
{
	struct HashToDict* d = user_data;
	g_output_stream_printf(d->stream, 0, NULL, NULL, "%s%s: %s\n",
	                       d->indent, (char*)key, (char*)value);
}

#if 0  /* GCC Magic */
static void
save_secret_flags (GOutputStream *netplan, const char *key, NMSettingSecretFlags flags)

NM_SETTING_SECRET_FLAG_*


static void
set_secret (GOutputStream *netplan, GHashTable *secrets, const char *key, const char *value, const char *flags_key, NMSettingSecretFlags flags)
// TODO: check how to handle secret flags -- toggles for special behavior of secrets.
// TODO: set_secret(): we write secrets directly to the main YAML file for netplan
save_secret_flags (netplan, flags_key, flags);
g_hash_table_replace (secrets, g_strdup (key), g_strdup (value)


static gboolean
write_secrets (GOutputStream *netplan, GHashTable *secrets, GError **error)
// TODO: write_secrets(): we don't write secrets to a separate file for netplan...
nm_utils_strdict_get_keys (secrets, TRUE, &secrets_keys_n)
ifcfg-rh:
SV_KEY_TYPE_ANY


typedef struct {
	const NMSetting8021xSchemeVtable *vtable;
	const char *netplan_key;
} Setting8021xSchemeVtable;


// TODO: implement Phase2 auth blobs for 802.1x...
static const Setting8021xSchemeVtable setting_8021x_scheme_vtable[] = {
#define _D(_scheme_type, _netplan_key) \
	[(_scheme_type)] = { \
		.vtable       = &nm_setting_8021x_scheme_vtable[(_scheme_type)], \
		.netplan_key = ""_netplan_key"", \
	}
	_D (NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT,            "ca-certificate"),
	//_D (NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT,     "inner-ca-certificate"),
	_D (NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT,        "client-certificate"),
	//_D (NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT, "inner-client-certificate"),
	_D (NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY,        "client-key"),
	//_D (NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY, "IEEE_8021X_INNER_PRIVATE_KEY"),
#undef _D
};


static gboolean
write_object (NMSetting8021x *s_8021x, GOutputStream *netplan, GHashTable *secrets, GHashTable *blobs, const Setting8021xSchemeVtable *objtype, gboolean force_write, GError **error)

NM_SETTING_802_1X_CK_SCHEME_*
NM_SETTING_802_1X_CK_FORMAT_PKCS12 (der/p12/pem)
// TODO: netplan does not yet support saving binary certs instead of paths
g_hash_table_replace (blobs, new_file, g_bytes_ref (blob));
g_hash_table_replace (blobs, standard_file, NULL);


static gboolean
write_blobs (GHashTable *blobs, GError **error)

// TODO: netplan does not yet support saving binary blobs in yaml (802.1x certs)
nm_utils_file_set_contents (filename, (const char *) g_bytes_get_data (blob, NULL), g_bytes_get_size (blob), 0600, NULL, &write_error)


static gboolean
write_8021x_certs (NMSetting8021x *s_8021x, GHashTable *secrets, GHashTable *blobs, gboolean phase2, GOutputStream *netplan, GError **error)

NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT
NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT
NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY
NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY
NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT
NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT
#endif  /* GCC magic */

static gboolean
write_8021x_setting (NMConnection *connection,
                     GOutputStream *netplan,
                     GHashTable *secrets,
                     GHashTable *blobs,
                     gboolean wired,
                     GError **error)
{
	NMSetting8021x *s_8021x;
	NMSetting8021xAuthFlags auth_flags;
	const char *value;
	const char *match;
	gconstpointer ptr;
	GBytes* bytes;
	GString *phase2_auth;
	GString *str;
	guint32 i, num;
	gsize size;
	int vint;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	if (!s_8021x)
		return TRUE;

	/* If wired, write KEY_MGMT */
	if (wired)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "            key-management: %s\n", "802.1x");

	/* EAP method */
	if (nm_setting_802_1x_get_num_eap_methods (s_8021x)) {
		value = nm_setting_802_1x_get_eap_method (s_8021x, 0);
		// TODO: For 802.1x: NetworkManager has a bunch of extra "EAP" methods that we should support.
		// See eap_methods_table  in libnm-core/nm-setting-8021x.c
		if (!g_strcmp0(value, "peap") || !g_strcmp0(value, "tls") || !g_strcmp0(value, "ttls")) {
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "            method: %s\n", value);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Unsupported '%s' method in netplan", value);
			return FALSE;
		}
	}

	value = nm_setting_802_1x_get_phase2_auth (s_8021x);
	if (value)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "            phase2-auth: %s\n", value);

	value = nm_setting_802_1x_get_identity (s_8021x);
	if (value)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "            identity: %s\n", value);
	value = nm_setting_802_1x_get_anonymous_identity (s_8021x);
	if (value)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "            anonymous-identity: %s\n", value);

	value = nm_setting_802_1x_get_password (s_8021x);
	if (value)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "            password: %s\n", value);

#if 0 // TODO: 802.1x use set_secret instead of g_output_stream_printf()...
nm_setting_802_1x_get_password (s_8021x)
nm_setting_802_1x_get_password_flags (s_8021x)
ifcfg-rh:
set_secret (...)
IEEE_8021X_PASSWORD
IEEE_8021X_PASSWORD_FLAGS
#endif

#if 0 // TODO: 802.1x complex EAP / PEAP and other auth settings
nm_setting_802_1x_get_password_raw (s_8021x)
nm_setting_802_1x_get_password_raw_flags (s_8021x)
nm_setting_802_1x_get_phase1_peapver (s_8021x)
nm_setting_802_1x_get_phase1_peaplabel (s_8021x)
nm_setting_802_1x_get_pac_file (s_8021x)
nm_setting_802_1x_get_phase1_fast_provisioning (s_8021x)
nm_setting_802_1x_get_phase2_auth (s_8021x)
nm_setting_802_1x_get_phase2_autheap (s_8021x)
nm_setting_802_1x_get_phase1_auth_flags (s_8021x)
nm_setting_802_1x_auth_flags_get_type()
nm_setting_802_1x_get_subject_match (s_8021x))
nm_setting_802_1x_get_phase2_subject_match (s_8021x)
nm_setting_802_1x_get_num_altsubject_matches (s_8021x)
nm_setting_802_1x_get_altsubject_match (s_8021x, i)
nm_setting_802_1x_get_num_phase2_altsubject_matches (s_8021x)
nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, i)
nm_setting_802_1x_get_domain_suffix_match (s_8021x)
nm_setting_802_1x_get_phase2_domain_suffix_match (s_8021x)
nm_setting_802_1x_get_auth_timeout (s_8021x)
NM_SETTING_802_1X_AUTH_FLAGS_*
ifcfg-rh:
set_secret (...)
IEEE_8021X_PASSWORD_RAW
IEEE_8021X_PASSWORD_RAW_FLAGS
IEEE_8021X_PEAP_VERSION
IEEE_8021X_PEAP_FORCE_NEW_LABEL
IEEE_8021X_PAC_FILE
IEEE_8021X_FAST_PROVISIONING
IEEE_8021X_INNER_AUTH_METHODS
IEEE_8021X_PHASE1_AUTH_FLAGS
IEEE_8021X_SUBJECT_MATCH
IEEE_8021X_PHASE2_SUBJECT_MATCH
IEEE_8021X_ALTSUBJECT_MATCHES
IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES
IEEE_8021X_DOMAIN_SUFFIX_MATCH
IEEE_8021X_PHASE2_DOMAIN_SUFFIX_MATCH
IEEE_8021X_AUTH_TIMEOUT
#endif

#if 0 // TODO: 802.1x certs in binary / path
	if (!write_8021x_certs (s_8021x, secrets, blobs, FALSE, netplan, error))
		return FALSE;

	/* phase2/inner certs */
	if (!write_8021x_certs (s_8021x, secrets, blobs, TRUE, netplan, error))
		return FALSE;
#endif

	if (nm_setting_802_1x_get_ca_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		value = nm_setting_802_1x_get_ca_cert_path (s_8021x);
		if (value)
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "            ca-certificate: %s\n", value);
	}

	if (nm_setting_802_1x_get_client_cert_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		value = nm_setting_802_1x_get_client_cert_path (s_8021x);
		if (value)
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "            client-certificate: %s\n", value);
	}

	if (nm_setting_802_1x_get_private_key_scheme (s_8021x) == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		value = nm_setting_802_1x_get_private_key_path (s_8021x);
		if (value)
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "            client-key: %s\n", value);
	}

	value = nm_setting_802_1x_get_private_key_password (s_8021x);
	if (value)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "            client-key-password: %s\n", value);
	return TRUE;
}

static gboolean
write_wireless_security_setting (NMConnection *connection,
                                 GOutputStream *netplan,
                                 GHashTable *secrets,
                                 gboolean adhoc,
                                 GError **error)
{
	NMSettingWirelessSecurity *s_wsec;
	const char *key_mgmt, *key; //, *auth_alg, *proto, *cipher;
	const char *psk = NULL;
	gboolean wep = FALSE, wpa = FALSE, wpa_psk = FALSE; //, dynamic_wep = FALSE;
	//NMSettingWirelessSecurityWpsMethod wps_method;
	guint32 i;  //, num;
	//GString *str;

	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (!s_wsec) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
		return FALSE;
	}

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (s_wsec);
	nm_assert (key_mgmt);

	//auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);

	g_output_stream_printf (netplan, 0, NULL, NULL, "          auth:\n");

	if (!strcmp (key_mgmt, "none")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: none\n");
		wep = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-psk")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: psk\n");
		wpa = TRUE;
		wpa_psk = TRUE;
	/* TODO: Implement wireless auth SAE mode in netplan
	} else if (!strcmp (key_mgmt, "sae")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: sae\n");
		wpa = TRUE;
	*/
	} else if (!strcmp (key_mgmt, "ieee8021x")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: 802.1x\n");
		//dynamic_wep = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-eap")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: eap\n");
		wpa = TRUE;
	} else if (key_mgmt != NULL) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Invalid key_mgmt '%s' in '%s' setting",
		             key_mgmt, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
		return FALSE;
	}

#if 0 // TODO: Unravel this SECURITYMODE story: restricted | open | leap ???
nm_setting_wireless_security_get_leap_username (s_wsec)
nm_setting_wireless_security_get_leap_password (s_wsec)
nm_setting_wireless_security_get_leap_password_flags (s_wsec)
ifcfg-rh:
SECURITYMODE (restricted|open|leap)
IEEE_8021X_IDENTITY
IEEE_8021X_PASSWORD
IEEE_8021X_PASSWORD_FLAGS
#endif

#if 0 // TODO: support enabling WPS in netplan.
nm_setting_wireless_security_get_wps_method (s_wsec)
nm_setting_wireless_security_wps_method_get_type ()
ifcfg-rh:
WPA_METHOD
#endif

	/* WEP keys */

	/* And write the new ones out */
	if (wep) {
		NMWepKeyType key_type;
		//const char *key_type_str = NULL;

		key_type = nm_setting_wireless_security_get_wep_key_type (s_wsec);

		/* Default WEP TX key index */
		// TODO: Fix defaultkey / TX key ID for WEP.
		//svSetValueInt64 (netplan, "DEFAULTKEY", nm_setting_wireless_security_get_wep_tx_keyidx(s_wsec) + 1);

		// TODO: differentiate hex key vs. passphrase for WEP (see below)
		// NM_WEP_KEY_TYPE_KEY, NM_WEP_KEY_TYPE_PASSPHRASE, NM_WEP_KEY_TYPE_UNKNOWN

		for (i = 0; i < 4; i++) {
			key = nm_setting_wireless_security_get_wep_key (s_wsec, i);
			if (key) {
				gs_free char *ascii_key = NULL;
				//char tag[64];
				gboolean key_valid = TRUE;

				/* Passphrase needs a different netplan key since with WEP, there
				 * are some passphrases that are indistinguishable from WEP hex
				 * keys.
				 */
				if (key_type == NM_WEP_KEY_TYPE_UNKNOWN) {
					if (nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_KEY))
						key_type = NM_WEP_KEY_TYPE_KEY;
					else if (nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_PASSPHRASE))
						key_type = NM_WEP_KEY_TYPE_PASSPHRASE;
				}

				if (key_type == NM_WEP_KEY_TYPE_KEY) {
					/* Add 's:' prefix for ASCII keys */
					if (strlen (key) == 5 || strlen (key) == 13) {
						ascii_key = g_strdup_printf ("s:%s", key);
						key = ascii_key;
					}
				} else if (key_type != NM_WEP_KEY_TYPE_PASSPHRASE) {
					g_warn_if_reached ();
					key_valid = FALSE;
				}

				// TODO: use set_secret??
				if (key_valid) {
					g_output_stream_printf(netplan, 0, NULL, NULL,
					                       "          password: %s\n", key);
				}
			}
		}
	}

#if 0 // TODO: implement WPA ciphers
nm_setting_wireless_security_get_num_pairwise (s_wsec)
nm_setting_wireless_security_get_pairwise (s_wsec, i)
nm_setting_wireless_security_get_num_groups (s_wsec)
nm_setting_wireless_security_get_group (s_wsec, i)
ifcfg-rh:
CIPHER_PAIRWISE
CIPHER_GROUP
#endif

	if (wpa_psk) {
		psk = nm_setting_wireless_security_get_psk (s_wsec);
		if (!nm_utils_wpa_psk_valid (psk)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Invalid psk '%s' in '%s' setting",
			             key_mgmt, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME);
			return FALSE;
		}
		// TODO: Should we be using set_secret() here?
		g_output_stream_printf(netplan, 0, NULL, NULL,
		                       "          password: \"%s\"\n", psk);
	} else if (wpa) {
		if (!write_8021x_setting (connection,
		                          netplan,
		                          secrets,
		                          NULL, //GHashTable *blobs,
		                          FALSE,
		                          error))
			return FALSE;
	}

#if 0 // TODO: wireless security: implement PMF and FILS support
nm_setting_wireless_security_get_pmf (s_wsec)
nm_setting_wireless_security_pmf_get_type ()
nm_setting_wireless_security_get_fils (s_wsec)
nm_setting_wireless_security_fils_get_type ()
NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT
NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT
ifcfg-rh:
PMF
FILS
#endif

	return TRUE;
}

static char*
wowlan_flags_str (NMSettingWirelessWakeOnWLan flags, GError **error)
{
	GString *out = g_string_sized_new (200);
	for (unsigned i = 0; NETPLAN_WIFI_WOWLAN_TYPES[i].name != NULL; ++i) {
		if (flags & NETPLAN_WIFI_WOWLAN_TYPES[i].flag)
			g_string_append_printf (out, "%s, ", NETPLAN_WIFI_WOWLAN_TYPES[i].name);
	}
	if (out->len == 0) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Invalid WakeOnWLan flags: '0x%x' not supported by netplan.", flags);
		return g_string_free (out, TRUE);
	}

	// cut last ", "
	out = g_string_truncate (out, out->len-2);
	// returned string must be freed by caller
	return g_string_free (out, FALSE);
}

static gboolean
write_wireless_setting (NMConnection *connection,
                        GOutputStream *netplan,
                        GError **error)
{
	NMSettingWireless *s_wireless;
	GBytes *ssid;
	const guint8 *ssid_data;
	gsize ssid_len;
	const char *mode, *band, *bssid;
	const char *device_mac, *cloned_mac;
	guint32 mtu, i, wowlan, chan;
	gboolean adhoc = FALSE, hex_ssid = FALSE;
	//const char *const*macaddr_blacklist;
	GString *essid;

	// TODO: move type selection to a place that makes sense (wireless)
	//svSetValueStr (netplan, "TYPE", TYPE_WIRELESS);

	s_wireless = nm_connection_get_setting_wireless (connection);
	if (!s_wireless) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	// TODO: wireless: fix matching / blacklist / MAC setting
	device_mac = nm_setting_wireless_get_mac_address (s_wireless);
	if (device_mac)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      match: { macaddress: %s }\n", device_mac);

	cloned_mac = nm_setting_wireless_get_cloned_mac_address (s_wireless);
	if (cloned_mac)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      macaddress: %s\n", cloned_mac);

#if 0  // TODO: fix MAC setting, blacklist for wireless.
nm_setting_wireless_get_generate_mac_address_mask (s_wireless)
nm_setting_wireless_get_mac_address_blacklist (s_wireless)
ifcfg-rh:
GENERATE_MAC_ADDRESS_MASK
HWADDR_BLACKLIST
#endif

	mtu = nm_setting_wireless_get_mtu (s_wireless);
	if (mtu != 0)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      mtu: %d\n", mtu);

	wowlan = nm_setting_wireless_get_wake_on_wlan (s_wireless);
	if (wowlan != NM_SETTING_WIRELESS_WAKE_ON_WLAN_DEFAULT) {
		char *tmp = wowlan_flags_str(wowlan, error);
		if (!tmp)
			return FALSE;
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      wakeonwlan: [%s]\n", tmp);
		g_free (tmp);
	}

	ssid = nm_setting_wireless_get_ssid (s_wireless);
	if (!ssid) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing SSID in '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}
	ssid_data = g_bytes_get_data (ssid, &ssid_len);
	if (!ssid_len || ssid_len > 32) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Invalid SSID in '%s' setting", NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	/* If the SSID contains any non-printable characters, we need to use the
	 * hex notation of the SSID instead.
	 */
	// TODO: Make sure SSID with non-printable is well supported in netplan
	if (   ssid_len > 2
	    && ssid_data[0] == '0'
	    && ssid_data[1] == 'x') {
		hex_ssid = TRUE;
		for (i = 2; i < ssid_len; i++) {
			if (!g_ascii_isxdigit (ssid_data[i])) {
				hex_ssid = FALSE;
				break;
			}
		}
	}
	if (!hex_ssid) {
		for (i = 0; i < ssid_len; i++) {
			if (!g_ascii_isprint (ssid_data[i])) {
				hex_ssid = TRUE;
				break;
			}
		}
	}

	essid = g_string_sized_new (ssid_len * 2 + 3);
	if (hex_ssid) {

		/* Hex SSIDs don't get quoted */
		g_string_append (essid, "0x");
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf (essid, "%02X", ssid_data[i]);
	} else {
		nm_assert (ssid_len <= 32);
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf (essid, "%c", ssid_data[i]);
		g_string_append_printf (essid, "%c", '\0');
	}
	g_output_stream_printf (netplan, 0, NULL, NULL,
	                        "      access-points:\n");
	g_output_stream_printf (netplan, 0, NULL, NULL,
	                        "        %s:\n", essid->str);
	g_string_free(essid, TRUE);

	/* Write WiFi mode */
	mode = nm_setting_wireless_get_mode (s_wireless);
	if (nm_streq (mode, NM_SETTING_WIRELESS_MODE_INFRA))
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "          mode: %s\n", "infrastructure");
	else if (nm_streq (mode, NM_SETTING_WIRELESS_MODE_ADHOC)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "          mode: %s\n", "adhoc");
		adhoc = TRUE;
	} else if (nm_streq (mode, NM_SETTING_WIRELESS_MODE_AP))
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "          mode: %s\n", "ap");
	else if (mode != NULL) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Invalid mode '%s' in '%s' setting",
		             mode, NM_SETTING_WIRELESS_SETTING_NAME);
		return FALSE;
	}

	/* Write WiFi band, if set. */
	band = nm_setting_wireless_get_band (s_wireless);
	if (nm_str_not_empty (band)) {
		if (nm_streq (band, "a"))
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "          band: 5GHz\n");
		else if (nm_streq (band, "bg"))
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "          band: 2.4GHz\n");
		else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			            "Invalid band '%s' in '%s' setting",
			             band, NM_SETTING_WIRELESS_SETTING_NAME);
			return FALSE;
		}

		/* Write channel. Can only be set if band is known. */
		chan = nm_setting_wireless_get_channel (s_wireless);
		if (chan) {
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "          channel: %u\n", chan);
		}
	}

	/* Write BSSID, if set. */
	bssid = nm_setting_wireless_get_bssid (s_wireless);
	if (nm_str_not_empty (bssid)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "          bssid: %s\n", bssid);
	}

	if (nm_connection_get_setting_wireless_security (connection)) {
		if (!write_wireless_security_setting (connection, netplan, NULL, adhoc, error))
			return FALSE;
	}

	// TODO: add support for non-broadcast (hidden) SSID.
	// nm_setting_wireless_get_hidden (s_wireless)

#if 0 // TODO: implement wifi powersave mode selection.
nm_setting_wireless_get_powersave (s_wireless)
NM_SETTING_WIRELESS_POWERSAVE_*
ifcfg-rh:
POWERSAVE
#endif

#if 0 // TODO: implement wifi MAC address randomization in netplan
nm_setting_wireless_get_mac_address_randomization (s_wireless)
NM_SETTING_MAC_RANDOMIZATION_*
ifcfg-rh:
MAC_ADDRESS_RANDOMIZATION
#endif

	return TRUE;
}

static gboolean
write_modem_setting (NMConnection *connection,
                     GOutputStream *netplan,
                     GError **error,
                     const char* type)
{
	void *s_modem = NULL;
	const char* tmp;
	gboolean is_gsm = FALSE;
	guint32 mtu = 0;

	if (!strcmp(type, NM_SETTING_GSM_SETTING_NAME)) {
		is_gsm = TRUE;
		s_modem = (NMSettingGsm *) nm_connection_get_setting_gsm (connection);
	} else if (!strcmp(type, NM_SETTING_CDMA_SETTING_NAME))
		s_modem = (NMSettingCdma *) nm_connection_get_setting_cdma (connection);

	if (!s_modem) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", type);
		return FALSE;
	}

	/* Write GSM only features */
	if (is_gsm) {
		if (nm_setting_gsm_get_auto_config (s_modem))
			g_output_stream_printf (netplan, 0, NULL, NULL, "      auto-config: true\n");

		tmp = nm_setting_gsm_get_apn (s_modem);
		if (nm_str_not_empty(tmp))
			g_output_stream_printf (netplan, 0, NULL, NULL, "      apn: %s\n", tmp);

		tmp = nm_setting_gsm_get_device_id (s_modem);
		if (nm_str_not_empty(tmp))
			g_output_stream_printf (netplan, 0, NULL, NULL, "      device-id: %s\n", tmp);

		tmp = nm_setting_gsm_get_network_id (s_modem);
		if (nm_str_not_empty(tmp))
			g_output_stream_printf (netplan, 0, NULL, NULL, "      network-id: %s\n", tmp);

		tmp = nm_setting_gsm_get_pin (s_modem);
		if (nm_str_not_empty(tmp))
			g_output_stream_printf (netplan, 0, NULL, NULL, "      pin: %s\n", tmp);

		tmp = nm_setting_gsm_get_sim_id (s_modem);
		if (nm_str_not_empty(tmp))
			g_output_stream_printf (netplan, 0, NULL, NULL, "      sim-id: %s\n", tmp);

		tmp = nm_setting_gsm_get_sim_operator_id (s_modem);
		if (nm_str_not_empty(tmp))
			g_output_stream_printf (netplan, 0, NULL, NULL, "      sim-operator-id: %s\n", tmp);
	}

	/* Write GSM/CDMA features */
	tmp = is_gsm ? nm_setting_gsm_get_number (s_modem) : nm_setting_cdma_get_number (s_modem);
	if (nm_str_not_empty(tmp))
		g_output_stream_printf (netplan, 0, NULL, NULL, "      number: \"%s\"\n", tmp);

	tmp = is_gsm ? nm_setting_gsm_get_password (s_modem) : nm_setting_cdma_get_password (s_modem);
	if (nm_str_not_empty(tmp))
		g_output_stream_printf (netplan, 0, NULL, NULL, "      password: \"%s\"\n", tmp);

	tmp = is_gsm ? nm_setting_gsm_get_username (s_modem) : nm_setting_cdma_get_username (s_modem);
	if (nm_str_not_empty(tmp))
		g_output_stream_printf (netplan, 0, NULL, NULL, "      username: \"%s\"\n", tmp);

	mtu = is_gsm ? nm_setting_gsm_get_mtu (s_modem) : nm_setting_cdma_get_mtu (s_modem);
	if (mtu > 0)
		g_output_stream_printf (netplan, 0, NULL, NULL, "      mtu: \"%u\"\n", mtu);

	return TRUE;
}

#if 0 // TODO: implement infiniband!
static gboolean
write_infiniband_setting (NMConnection *connection, GOutputStream *netplan, GError **error)

NM_SETTING_INFINIBAND_SETTING_NAME
s_infiniband = nm_connection_get_setting_infiniband (connection);
nm_setting_infiniband_get_mac_address (s_infiniband)
nm_setting_infiniband_get_mtu (s_infiniband)
nm_setting_infiniband_get_transport_mode (s_infiniband)
nm_setting_infiniband_get_p_key (s_infiniband)
nm_setting_infiniband_get_parent (s_infiniband)
ifcfg-rh:
HWADDR
MTU
CONNECTED_MODE
PKEY
PKEY_ID
PHYSDEV
#endif

static gboolean
write_wired_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingWired *s_wired;
	//const char *const*s390_subchannels;
	guint32 mtu, wolan; // i, num_opts;
	//const char *const*macaddr_blacklist;
	const char *mac;

	// TODO: move type setting for ethernet devices
	//svSetValueStr (netplan, "TYPE", TYPE_ETHERNET);

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_WIRED_SETTING_NAME);
		return FALSE;
	}

	mac = nm_setting_wired_get_mac_address (s_wired);
	if (mac)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      match: { macaddress: %s }\n", mac);

	mac = nm_setting_wired_get_cloned_mac_address (s_wired);
	if (mac)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      macaddress: %s\n", mac);

	// TODO: dedup fields for mac-address to do MAC setting cleanly.
	// nm_setting_wired_get_generate_mac_address_mask (s_wired)

#if 0  // TODO: No MAC match blacklist in netplan. Do we need one?
nm_setting_wired_get_mac_address_blacklist (s_wired)
ifcfg-rh:
HWADDR_BLACKLIST
#endif

	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu != 0)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      mtu: %d\n", mtu);

	/* TODO: Implement all the different WoLAN flags in netplan. */
	wolan = nm_setting_wired_get_wake_on_lan (s_wired);
	if (wolan > NM_SETTING_WIRED_WAKE_ON_LAN_NONE &&
	    wolan < NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE)
		g_output_stream_printf (netplan, 0, NULL, NULL, "      wakeonlan: true\n");

#if 0 // TODO: implement s390 subchannels
nm_setting_wired_get_s390_subchannels (s_wired)
nm_setting_wired_get_s390_nettype (s_wired)
nm_setting_wired_get_s390_option_by_key (s_wired, "portname")
nm_setting_wired_get_s390_option_by_key (s_wired, "ctcprot")
nm_setting_wired_get_num_s390_options (s_wired)
nm_setting_wired_get_s390_option (s_wired, i, &s390_key, &s390_val)
ifcfg-rh:
SUBCHANNELS
NETTYPE
PORTNAME
CTCPROT
OPTIONS
#endif

	return TRUE;
}

#if 0 // TODO: add support for ethtool settings in netplan
static gboolean
write_ethtool_setting (NMConnection *connection, GOutputStream *netplan, GError **error)

s_ethtool = NM_SETTING_ETHTOOL (nm_connection_get_setting (connection, NM_TYPE_SETTING_ETHTOOL));
nm_setting_wired_get_auto_negotiate (s_wired)
nm_setting_wired_get_speed (s_wired)
nm_setting_wired_get_duplex (s_wired)
nm_setting_wired_get_wake_on_lan_password (s_wired)
nm_setting_wired_get_wake_on_lan (s_wired)
nms_netplan_utils_get_ethtool_name (ethtool_id)
NM_SETTING_WIRED_WAKE_ON_LAN_*
ifcfg-rh:
ETHTOOL_WAKE_ON_LAN
ETHTOOL_OPTS
#endif

#if 0 /* temp disable: only for team? REUSE */
static gboolean
write_wired_for_virtual (NMConnection *connection, GOutputStream *netplan)
{
	NMSettingWired *s_wired;
	gboolean has_wired = FALSE;

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		const char *device_mac, *cloned_mac;
		guint32 mtu;

		has_wired = TRUE;

		device_mac = nm_setting_wired_get_mac_address (s_wired);
		if (device_mac)
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "      match: { mac-address: %s }\n", device_mac);

		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      mac-address: %s\n", cloned_mac);

		// TODO: support generate_mac_address_mask
		//svSetValueStr (netplan, "GENERATE_MAC_ADDRESS_MASK",
		//               nm_setting_wired_get_generate_mac_address_mask (s_wired));

		mtu = nm_setting_wired_get_mtu (s_wired);
		if (mtu != 0)
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "      mtu: %d\n", mtu);
	}
	return has_wired;
}
#endif

static gboolean
write_vlan_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingVlan *s_vlan;
	//char *tmp;
	//guint32 vlan_flags = 0;
	//gsize s_buf_len;
	//char s_buf[50], *s_buf_ptr;

	s_vlan = nm_connection_get_setting_vlan (connection);
	if (!s_vlan) {
		g_set_error_literal (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		                     "Missing VLAN setting");
		return FALSE;
	}

	g_output_stream_printf (netplan, 0, NULL, NULL,
	                        "      id: %d\n", nm_setting_vlan_get_id (s_vlan));
	g_output_stream_printf (netplan, 0, NULL, NULL,
	                        "      link: %s\n", nm_setting_vlan_get_parent (s_vlan));

#if 0  /* TODO: add support for vlan flags / advanced settings */
nm_setting_vlan_get_flags (s_vlan)
NM_VLAN_FLAG_*
ifcfg-rh:
vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_INGRESS_MAP)
vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_EGRESS_MAP)
REORDER_HDR
GVRP
VLAN_FLAGS
MVRP
VLAN_INGRESS_PRIORITY_MAP
VLAN_EGRESS_PRIORITY_MAP
#endif

	return TRUE;
}

static const struct {
	const char *option;
	const char *netplan_name;
} bond_options_mapping[] = {
	{ NM_SETTING_BOND_OPTION_MODE, "mode" },
	{ NM_SETTING_BOND_OPTION_LACP_RATE, "lacp-rate" },
	{ NM_SETTING_BOND_OPTION_MIIMON, "mii-monitor-interval" },
	{ NM_SETTING_BOND_OPTION_MIN_LINKS, "min-links" },
	{ NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY, "transmit-hash-policy" },
	{ NM_SETTING_BOND_OPTION_AD_SELECT, "ad-select" },
	{ NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, "all-slaves-active" },
	{ NM_SETTING_BOND_OPTION_ARP_INTERVAL, "arp-interval" },
	{ NM_SETTING_BOND_OPTION_ARP_IP_TARGET, "arp-ip-targets" },
	{ NM_SETTING_BOND_OPTION_ARP_VALIDATE, "arp-validate" },
	{ NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS, "arp-all-targets" },
	{ NM_SETTING_BOND_OPTION_UPDELAY, "up-delay" },
	{ NM_SETTING_BOND_OPTION_DOWNDELAY, "down-delay" },
	{ NM_SETTING_BOND_OPTION_FAIL_OVER_MAC, "fail-over-mac-policy" },
	{ NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, "gratuitous-arp" },
	{ NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, "packets-per-slave" },
	{ NM_SETTING_BOND_OPTION_PRIMARY_RESELECT, "primary-reselect-policy" },
	{ NM_SETTING_BOND_OPTION_RESEND_IGMP, "resend-igmp" },
	{ NM_SETTING_BOND_OPTION_LP_INTERVAL, "learn-packet-interval" },
	{ NM_SETTING_BOND_OPTION_PRIMARY, "primary" },
	// TODO: Needs to be implemented in netplan
	//#define NM_SETTING_BOND_OPTION_ACTIVE_SLAVE      "active_slave"
	//#define NM_SETTING_BOND_OPTION_AD_ACTOR_SYS_PRIO "ad_actor_sys_prio"
	//#define NM_SETTING_BOND_OPTION_AD_ACTOR_SYSTEM   "ad_actor_system"
	//#define NM_SETTING_BOND_OPTION_AD_USER_PORT_KEY  "ad_user_port_key"
	//#define NM_SETTING_BOND_OPTION_NUM_UNSOL_NA      "num_unsol_na"
	//#define NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB    "tlb_dynamic_lb"
	//#define NM_SETTING_BOND_OPTION_USE_CARRIER       "use_carrier"
};

static void
_match_bond_option_to_netplan (GString *bond_options, const char *option, const char *value)
{
	guint i;
	const char *name = NULL;

	for (i = 0; i < G_N_ELEMENTS (bond_options_mapping); i++) {
		if (nm_streq (option, bond_options_mapping[i].option)) {
			name = bond_options_mapping[i].netplan_name;
			break;
		}
	}

	/* Special handling for non-string/non-uint types. */
	if (nm_streq (option, NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE))
		value = nm_streq (value, "1") ? "true" : NULL; //default is false
	else if (nm_streq (option, NM_SETTING_BOND_OPTION_ARP_IP_TARGET))
		value = (strlen (value) > 0) ? g_strdup_printf ("[%s]", value) : NULL;

	if (!name)
		_LOGW("Bond option needs implementation: %s (%s)", option, value);
	else if (value)
		g_string_append_printf (bond_options, "        %s: %s\n", name, value);
}

static gboolean
write_bond_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingBond *s_bond;
	guint32 i, num_opts;

	s_bond = nm_connection_get_setting_bond (connection);
	if (!s_bond) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_BOND_SETTING_NAME);
		return FALSE;
	}

	num_opts = nm_setting_bond_get_num_options (s_bond);
	if (num_opts) {
		nm_auto_free_gstring GString *str = NULL;
		const char *name, *value;

		str = g_string_sized_new (64);
		for (i = 0; i < num_opts; i++) {
			nm_setting_bond_get_option (s_bond, i, &name, &value);
			_match_bond_option_to_netplan (str, name, value);
		}

		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      parameters:\n%s", str->str);
	}

	return TRUE;
}

#if 0 // TODO: implement team devices in netplan
static gboolean
write_team_setting (NMConnection *connection, GOutputStream *netplan, GError **error)

s_team = nm_connection_get_setting_team (connection);
nm_setting_team_get_config (s_team)
write_wired_for_virtual (connection, netplan)
ifcfg-rh:
TEAM_CONFIG
#endif

static guint32
get_setting_default_uint (NMSetting *setting, const char *prop)
{
	GParamSpec *pspec;
	GValue val = G_VALUE_INIT;
	guint32 ret = 0;

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), prop);
	nm_assert (pspec);
	g_value_init (&val, pspec->value_type);
	g_param_value_set_default (pspec, &val);
	nm_assert (G_VALUE_HOLDS_UINT (&val));
	ret = g_value_get_uint (&val);
	g_value_unset (&val);
	return ret;
}

#if 0 /* temp disable: unused? */
static gboolean
get_setting_default_boolean (NMSetting *setting, const char *prop)
{
	GParamSpec *pspec;
	GValue val = G_VALUE_INIT;
	gboolean ret = 0;

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), prop);
	nm_assert (pspec);
	g_value_init (&val, pspec->value_type);
	g_param_value_set_default (pspec, &val);
	nm_assert (G_VALUE_HOLDS_BOOLEAN (&val));
	ret = g_value_get_boolean (&val);
	g_value_unset (&val);
	return ret;
}
#endif

#if 0 // TODO: Implement bridge VLANs printif settings.
static gboolean
write_bridge_vlans (NMSetting *setting, const char *property_name, GOutputStream *netplan, const char *key, GError **error)

vlan_str = nm_bridge_vlan_to_str (vlan, error)
nm_utils_escaped_tokens_escape_gstr_assert (vlan_str, ",", string)
#endif

static gboolean
write_bridge_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingBridge *s_bridge;
	guint32 i;
	//gboolean b;
	GString *opts;
	const char *mac;

	s_bridge = nm_connection_get_setting_bridge (connection);
	if (!s_bridge) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_BRIDGE_SETTING_NAME);
		return FALSE;
	}

	mac = nm_setting_bridge_get_mac_address (s_bridge);
	if (mac)
			g_output_stream_printf (netplan, 0, NULL, NULL,
			                        "      macaddress: %s\n", mac);

	/* Bridge options */
	opts = g_string_sized_new (32);

	if (nm_setting_bridge_get_stp (s_bridge)) {
		g_string_append_printf (opts, "        stp: %s\n", "yes");

		i = nm_setting_bridge_get_forward_delay (s_bridge);
		if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_FORWARD_DELAY))
			g_string_append_printf (opts, "        forward-delay: %u\n", i);

		g_string_append_printf (opts, "        priority: %u\n", nm_setting_bridge_get_priority (s_bridge));

		i = nm_setting_bridge_get_hello_time (s_bridge);
		if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_HELLO_TIME)) {
			g_string_append_printf (opts, "        hello-time: %u\n", i);
		}

		i = nm_setting_bridge_get_max_age (s_bridge);
		if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_MAX_AGE)) {
			g_string_append_printf (opts, "        max-age: %u\n", i);
		}
	}

	i = nm_setting_bridge_get_ageing_time (s_bridge);
	if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_AGEING_TIME)) {
		g_string_append_printf (opts, "        ageing-time: %u\n", i);
	}

#if 0  // TODO: group_fw_mask for bridges.
	i = nm_setting_bridge_get_group_forward_mask (s_bridge);
	if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_GROUP_FORWARD_MASK)) {
		g_string_append_printf (opts, "        group_fwd_mask: %u", i);
	}
#endif

#if 0 // TODO: implement multicast snooping seting for bridges.
	b = nm_setting_bridge_get_multicast_snooping (s_bridge);
	if (b != get_setting_default_boolean (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_MULTICAST_SNOOPING)) {
		if (opts->len)
			g_string_append_c (opts, ' ');
		g_string_append_printf (opts, "multicast_snooping=%u", (guint32) b);
	}
#endif

#if 0 // TODO: implement bridge vlan filtering
	b = nm_setting_bridge_get_vlan_filtering (s_bridge);
	if (b != get_setting_default_boolean (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_VLAN_FILTERING)) {
		if (opts->len)
			g_string_append_c (opts, ' ');
		g_string_append_printf (opts, "vlan_filtering=%u", (guint32) b);
	}

	i = nm_setting_bridge_get_vlan_default_pvid (s_bridge);
	if (i != get_setting_default_uint (NM_SETTING (s_bridge), NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID)) {
		if (opts->len)
			g_string_append_c (opts, ' ');
		g_string_append_printf (opts, "default_pvid=%u", i);
	}
#endif

	if (opts->len)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      parameters:\n%s", opts->str);
	g_string_free (opts, TRUE);

#if 0 // TODO: Bridge VLANS magic???
	if (!write_bridge_vlans ((NMSetting *) s_bridge,
	                         NM_SETTING_BRIDGE_VLANS,
	                         netplan,
	                         "BRIDGE_VLANS",
	                         error))
		return FALSE;
#endif

	// TODO: org for output the right type of device.
	//svSetValueStr (netplan, "TYPE", TYPE_BRIDGE);

	return TRUE;
}

static gboolean
write_bridge_port_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	/* TODO: Might need reorg in netplan to support in member device bond/bridge params.
	 *   We need to make sure bridge-port params do not get overwritten in netplan, when
	 *   multiple YAML files are read, which define the same bridge master ID. */
	NMSettingBridgePort *s_port;
	NMSettingConnection *s_con;
	guint32 i;
	GString *string;
	const char *master, *iface;

	s_con = nm_connection_get_setting_connection (connection);
	s_port = nm_connection_get_setting_bridge_port (connection);
	if (!s_port)
		return TRUE;

	iface = nm_setting_connection_get_interface_name (s_con);
	if (!iface) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_CONNECTION_INTERFACE_NAME);
		return FALSE;
	}

	/* Bridge options */
	string = g_string_sized_new (32);

	i = nm_setting_bridge_port_get_priority (s_port);
	if (i != get_setting_default_uint (NM_SETTING (s_port), NM_SETTING_BRIDGE_PORT_PRIORITY))
		g_string_append_printf (string, "        port-priority:\n          %s: %u\n", iface, i);

	i = nm_setting_bridge_port_get_path_cost (s_port);
	if (i != get_setting_default_uint (NM_SETTING (s_port), NM_SETTING_BRIDGE_PORT_PATH_COST)) {
		g_string_append_printf (string, "        path-cost:\n          %s: %u\n", iface, i);
	}

#if 0 // TODO: need hairpin mode support in networkd/netplan
	if (nm_setting_bridge_port_get_hairpin_mode (s_port)) {
		if (string->len)
			g_string_append_c (string, ' ');
		g_string_append_printf (string, "hairpin_mode=1");
	}
#endif

	master = nm_setting_connection_get_master (s_con);
	if (!master) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_CONNECTION_MASTER);
		return FALSE;
	}

	if (string->len) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  bridges:\n    %s:\n      interfaces: [%s]\n      parameters:\n%s",
		                        master, iface, string->str);
	}
	g_string_free (string, TRUE);

#if 0 // TODO: Bridge VLANS
	if (!write_bridge_vlans ((NMSetting *) s_port,
	                         NM_SETTING_BRIDGE_PORT_VLANS,
	                         netplan,
	                         "BRIDGE_PORT_VLANS",
	                         error))
		return FALSE;
#endif

	return TRUE;
}

#if 0 // TODO: implement Team port settings.
static gboolean
write_team_port_setting (NMConnection *connection, GOutputStream *netplan, GError **error)

s_port = nm_connection_get_setting_team_port (connection)
nm_setting_team_port_get_config (s_port)
ifcfg-rh:
TEAM_PORT_CONFIG
#endif

#if 0 // TODO: Implement DCB.
static gboolean
write_dcb_setting (NMConnection *connection, GOutputStream *netplan, GError **error)

KEY_DCB_[APP|PFC|PG]_*
s_dcb = nm_connection_get_setting_dcb (connection)
nm_setting_dcb_get_app_fcoe_flags (s_dcb)
nm_setting_dcb_get_app_fcoe_priority (s_dcb)
nm_setting_dcb_get_app_fcoe_mode (s_dcb)
nm_setting_dcb_get_app_iscsi_flags (s_dcb)
nm_setting_dcb_get_app_iscsi_priority (s_dcb)
nm_setting_dcb_get_app_fip_flags (s_dcb)
nm_setting_dcb_get_app_fip_priority (s_dcb)
nm_setting_dcb_get_priority_flow_control_flags (s_dcb)
nm_setting_dcb_get_priority_flow_control)
nm_setting_dcb_get_priority_group_flags (s_dcb)
nm_setting_dcb_get_priority_group_id()
nm_setting_dcb_get_priority_group_bandwidth()
nm_setting_dcb_get_priority_bandwidth()
nm_setting_dcb_get_priority_strict_bandwidth()
nm_setting_dcb_get_priority_traffic_class()
NM_SETTING_DCB_FLAG_ENABLE
ifcfg-rh:
write_dcb_app (...)
write_dcb_flags (...)
write_dcb_uint_array (...)
write_dcb_percent_array (...)
write_dcb_bool_array (...)
DCB
KEY_DCB_APP_FCOE_MODE
APP_FCOE
APP_ISCSI
APP_FIP
PFC
KEY_DCB_PFC_UP
PG
KEY_DCB_PG_ID
KEY_DCB_PG_PCT
KEY_DCB_PG_UPPCT
KEY_DCB_PG_STRICT
KEY_DCB_PG_UP2TC
#endif

static void
write_connection_setting (NMSettingConnection *s_con, GOutputStream *netplan)
{
	//guint32 n, i;
	//GString *str;
	//const char *master, *master_iface = NULL, *type;
	//int vint;
	//gint32 vint32;
	//NMSettingConnectionMdns mdns;
	//NMSettingConnectionLlmnr llmnr;
	//guint32 vuint32;
	const char *tmp;

	g_output_stream_printf (netplan, 0, NULL, NULL, "      networkmanager:\n");
	g_output_stream_printf (netplan, 0, NULL, NULL,
	                        "        name: %s\n", nm_setting_connection_get_id(s_con));
	g_output_stream_printf (netplan, 0, NULL, NULL,
	                        "        uuid: %s\n", nm_setting_connection_get_uuid (s_con));
	tmp = nm_setting_connection_get_stable_id (s_con);
	if (tmp)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "        stable-id: %s\n", tmp);

	// TODO: MOVE to header to identify the device / connection it is under
	tmp = nm_setting_connection_get_interface_name (s_con);
	if (tmp)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "        device: %s\n", tmp);

#if 0  // TODO: hook up autoconnect ???
nm_setting_connection_get_autoconnect (s_con)
nm_setting_connection_get_autoconnect_priority (s_con)
nm_setting_connection_get_autoconnect_retries (s_con)
nm_setting_connection_get_multi_connect (s_con)
nm_setting_connection_get_connection_type (s_con)
_nm_connection_type_is_master (type)
nm_setting_connection_get_autoconnect_slaves (s_con)
nm_setting_connection_get_lldp (s_con)
NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_*
NM_CONNECTION_MULTI_CONNECT_*
NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_*
NM_SETTING_CONNECTION_LLDP_*
ifcfg-rh:
ONBOOT
AUTOCONNECT_PRIORITY
AUTOCONNECT_RETRIES
MULTI_CONNECT
AUTOCONNECT_SLAVES
LLDP
#endif

#if 0 // TODO: handle user permissions for connections
nm_setting_connection_get_num_permissions (s_con)
nm_setting_connection_get_permission (s_con, i, NULL, &puser, NULL)
nm_setting_connection_get_zone (s_con)
ifcfg-rh:
USERS
ZONE
#endif

#if 0
nm_setting_connection_get_master (s_con)
nm_manager_iface_for_uuid (nm_manager_get (), master)
nm_setting_connection_is_slave_type (s_con, NM_SETTING_*_SETTING_NAME)
nm_setting_connection_get_slave_type (s_con)
ifcfg-rh:
MASTER_UUID
MASTER
SLAVE
BRIDGE_UUID
BRIDGE
TEAM_MASTER_UUID
TEAM_MASTER
OVS_PORT_UUID
OVS_PORT
#endif

#if 0 // TODO: use devicetype code for bridgeport detection
nm_setting_connection_is_slave_type (s_con, NM_SETTING_TEAM_SETTING_NAME)
NM_SETTING_TEAM_SETTING_NAME
ifcfg-rh:
DEVICETYPE (TYPE_TEAM|TYPE_TEAM_PORT)
#endif

#if 0  // TODO: secondary connection UUIDs
nm_setting_connection_get_num_secondaries (s_con)
nm_setting_connection_get_secondary (s_con, i)
nm_setting_connection_get_gateway_ping_timeout (s_con)
nm_setting_connection_get_metered (s_con)
nm_setting_connection_get_auth_retries (s_con)
nm_setting_connection_get_wait_device_timeout (s_con)
NM_METERED_*
ifcfg-rh:
SECONDARY_UUIDS
GATEWAY_PING_TIMEOUT
CONNECTION_METERED
AUTH_RETRIES
DEVTIMEOUT
#endif

#if 0  // TODO: mdns & llmnr
nm_setting_connection_get_mdns (s_con)
nm_setting_connection_get_llmnr (s_con)
NM_SETTING_CONNECTION_MDNS_*
NM_SETTING_CONNECTION_LLMNR_*
ifcfg-rh:
MDNS
LLMNR
#endif
}

static char *
get_route_attributes_string (NMIPRoute *route, int family)
{
	gs_free const char **names = NULL;
	GVariant *attr, *lock;
	GString *str;
	guint i, len;

	names = _nm_ip_route_get_attribute_names (route, TRUE, &len);
	if (!len)
		return NULL;

	str = g_string_new ("");

	for (i = 0; i < len; i++) {
		attr = nm_ip_route_get_attribute (route, names[i]);

		if (!nm_ip_route_attribute_validate (names[i], attr, family, NULL, NULL))
			continue;

		if (NM_IN_STRSET (names[i], NM_IP_ROUTE_ATTRIBUTE_WINDOW,
		                            NM_IP_ROUTE_ATTRIBUTE_CWND,
		                            NM_IP_ROUTE_ATTRIBUTE_INITCWND,
		                            NM_IP_ROUTE_ATTRIBUTE_INITRWND,
		                            NM_IP_ROUTE_ATTRIBUTE_MTU)) {
			char lock_name[256];

			nm_sprintf_buf (lock_name, "lock-%s", names[i]);
			lock = nm_ip_route_get_attribute (route, lock_name);

			g_string_append_printf (str,
			                        "%s %s%u",
			                        names[i],
			                        (lock && g_variant_get_boolean (lock)) ? "lock " : "",
			                        g_variant_get_uint32 (attr));
		} else if (strstr (names[i], "lock-")) {
			const char *n = &(names[i])[NM_STRLEN ("lock-")];

			attr = nm_ip_route_get_attribute (route, n);
			if (!attr) {
				g_string_append_printf (str,
				                        "%s lock 0",
				                        n);
			} else {
				/* we also have a corresponding attribute with the numeric value. The
				 * lock setting is handled above. */
			}
		} else if (nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_TOS)) {
			g_string_append_printf (str, "%s 0x%02x", names[i], (unsigned) g_variant_get_byte (attr));
		} else if (nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_TABLE)) {
			g_string_append_printf (str, "%s %u", names[i], (unsigned) g_variant_get_uint32 (attr));
		} else if (nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_ONLINK)) {
			if (g_variant_get_boolean (attr))
				g_string_append (str, "onlink");
		} else if (NM_IN_STRSET (names[i], NM_IP_ROUTE_ATTRIBUTE_SRC,
		                                   NM_IP_ROUTE_ATTRIBUTE_FROM)) {
			char *arg = nm_streq (names[i], NM_IP_ROUTE_ATTRIBUTE_SRC) ? "src" : "from";

			g_string_append_printf (str, "%s %s", arg, g_variant_get_string (attr, NULL));
		} else {
			g_warn_if_reached ();
			continue;
		}
		if (names[i + 1])
			g_string_append_c (str, ' ');
	}

	return g_string_free (str, FALSE);
}

static gboolean
write_route_settings (NMSettingIPConfig *s_ip, GArray *out_routes)
{
	NMIPRoute *route;
	guint32 i, num;
	int addr_family;
	GHashTable *tbl;

	addr_family = nm_setting_ip_config_get_addr_family (s_ip);

	num = nm_setting_ip_config_get_num_routes (s_ip);
	if (num == 0)
		return FALSE;

	for (i = 0; i < num; i++) {
		tbl = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
		gs_free char *options = NULL;
		const char *next_hop;
		gint64 metric;

		route = nm_setting_ip_config_get_route (s_ip, i);
		next_hop = nm_ip_route_get_next_hop (route);
		metric = nm_ip_route_get_metric (route);
		options = get_route_attributes_string (route, addr_family);

		g_hash_table_insert (tbl, "to", g_strdup_printf("%s/%u",
		                     nm_ip_route_get_dest (route),
		                     nm_ip_route_get_prefix (route)));
		if (next_hop)
			g_hash_table_insert (tbl, "via", g_strdup(next_hop));
		if (metric >= 0)
			g_hash_table_insert (tbl, "metric", g_strdup_printf("%u",
			                     (guint) metric));

		g_array_append_val (out_routes, tbl);
#if 0  // TODO: implementing route options
		if (options) {
			g_string_append_c (contents, ' ');
			g_string_append (contents, options);
		}
#endif
	}

	return TRUE;
}

#if 0  // TODO: implement proxy support.
static gboolean
write_proxy_setting (NMConnection *connection, GOutputStream *netplan, GError **error)

s_proxy = nm_connection_get_setting_proxy (connection)
nm_setting_proxy_get_method (s_proxy)
nm_setting_proxy_get_pac_url (s_proxy)
nm_setting_proxy_get_pac_script (s_proxy)
nm_setting_proxy_get_browser_only (s_proxy)
NM_SETTING_PROXY_METHOD_*
ifcfg-rh:
BROWSER_ONLY
PAC_URL
PAC_SCRIPT
PROXY_METHOD
#endif

#if 0  // TODO: implement user permission settings
static gboolean
write_user_setting (NMConnection *connection, GOutputStream *netplan, GError **error)

s_user = NM_SETTING_USER (nm_connection_get_setting (connection, NM_TYPE_SETTING_USER))
nm_setting_user_get_keys (s_user, &len)
nms_netplan_utils_user_key_encode (key, str)
nm_setting_user_get_data (s_user, key)
ifcfg-rh:
SV_KEY_TYPE_USER
#endif

#if 0  // TODO: implement SR-IOV settings
static void
write_sriov_setting (NMConnection *connection, GHashTable *netplan)

s_sriov = NM_SETTING_SRIOV (nm_connection_get_setting (connection, NM_TYPE_SETTING_SRIOV))
nm_setting_sriov_get_total_vfs (s_sriov)
nm_setting_sriov_get_autoprobe_drivers (s_sriov)
nm_setting_sriov_get_num_vfs (s_sriov)
nm_setting_sriov_get_vf (s_sriov, i)
nm_sriov_vf_get_index (vf)
nm_utils_sriov_vf_to_str (vf, TRUE, NULL)
NM_TERNARY_DEFAULT
ifcfg-rh:
SV_KEY_TYPE_SRIOV_VF
SRIOV_TOTAL_VFS
SRIOV_AUTOPROBE_DRIVERS
SRIOV_VF%u
#endif

#if 0 // TODO: implement TC settings for netplan
static gboolean
write_tc_setting (NMConnection *connection, GHashTable *netplan, GError **error)

s_tc = nm_connection_get_setting_tc_config (connection)
nm_setting_tc_config_get_num_qdiscs (s_tc)
nm_setting_tc_config_get_qdisc (s_tc, i)
nm_utils_tc_qdisc_to_str (qdisc, error)
nm_setting_tc_config_get_num_tfilters (s_tc)
nm_setting_tc_config_get_tfilter (s_tc, i)
nm_utils_tc_tfilter_to_str (tfilter, error)
ifcfg-rh
SV_KEY_TYPE_TC
QDISC
FILTER
#endif

static gboolean
write_match_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingMatch *s_match;
	nm_auto_free_gstring GString *str = NULL;
	guint i, num;

	s_match = (NMSettingMatch *) nm_connection_get_setting (connection, NM_TYPE_SETTING_MATCH);
	if (!s_match)
		return TRUE;

	num = nm_setting_match_get_num_interface_names (s_match);
	for (i = 0; i < num; i++) {
		const char *name;

		name = nm_setting_match_get_interface_name (s_match, i);
		if (!name || !name[0])
			continue;

		if (!str)
			str = g_string_new ("");
		else
			g_string_append_c (str, ' ');
		nm_utils_escaped_tokens_escape_gstr (name, NM_ASCII_SPACES, str);
	}

	if (str) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      match:\n");
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "        name: %s\n", str->str);
	}

	return TRUE;
}

#if 0  // TODO: implement DNS options (edns0, etc.)
static void
write_res_options (GHashTable *netplan, NMSettingIPConfig *s_ip, const char *var)

nm_setting_ip_config_get_num_dns_options (s_ip)
nm_setting_ip_config_get_dns_option (s_ip, i)
#endif

static void
write_ip4_setting_dhcp_hostname (NMSettingIPConfig *s_ip4,
                                 GHashTable *dhcp_overrides)
{
	const char *hostname;

	hostname = nm_setting_ip_config_get_dhcp_hostname (s_ip4);
	if (hostname)
		g_hash_table_insert (dhcp_overrides, "hostname", g_strdup(hostname));

	if (!nm_setting_ip_config_get_dhcp_send_hostname (s_ip4))
		g_hash_table_insert (dhcp_overrides, "send-hostname", g_strdup("no"));
}

static gboolean
write_ip4_setting (NMConnection *connection,
                   GOutputStream *netplan,
                   GArray *addresses,
                   GArray *nameservers,
                   GArray *searches,
                   GArray *routes,
                   GHashTable *dhcp_overrides,
                   GError **error)
{
	NMSettingIPConfig *s_ip4;
	const char *value;
	//char *tmp;
	//char tag[64];
	//int j;
	guint i, num, n;
	//gint64 route_metric;
	//NMIPRouteTableSyncMode route_table;
	//int priority;
	//int timeout;
	const char *method = NULL;
	const char *gateway = NULL;
	//gboolean has_netmask;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return TRUE;

	method = nm_setting_ip_config_get_method (s_ip4);

	/* Missing IP4 setting is assumed to be DHCP */
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	num = nm_setting_ip_config_get_num_addresses (s_ip4);

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      dhcp4: yes\n");
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		// Do nothing:
		// Static addresses addressed below.
	}
#if 0  /* TODO: implement setting statically assigned IPs: append to GArray for addresses */
	} else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL))
		link_local &= 0x2;
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_SHARED))
		// TODO: implement connection sharing.
#endif

	/* Write out IPADDR<n>, PREFIX<n>, GATEWAY<n> for current IP addresses
	 * without labels. Unset obsolete NETMASK<n>.
	 */

	for (i = n = 0; i < num; i++) {
		NMIPAddress *addr;
		GString *address;

		address = g_string_sized_new(50);

		addr = nm_setting_ip_config_get_address (s_ip4, i);

		if (i > 0) {
			GVariant *label;

			label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
			if (label)
				continue;
		}
		g_string_printf(address, "%s/%d",
		                nm_ip_address_get_address (addr),
		                nm_ip_address_get_prefix (addr));
		value = g_string_free(address, FALSE);
		g_array_append_val (addresses, value);
	}

	gateway = nm_setting_ip_config_get_gateway (s_ip4);
	if (gateway)
		g_output_stream_printf(netplan, 0, NULL, NULL,
		                       "      gateway4: %s\n", gateway);

	num = nm_setting_ip_config_get_num_dns (s_ip4);
	for (i = 0; i < num; i++) {
		const char *dns;
		dns = nm_setting_ip_config_get_dns (s_ip4, i);
		g_array_append_val(nameservers, dns);
	}

	num = nm_setting_ip_config_get_num_dns_searches (s_ip4);
	for (i = 0; i < num; i++) {
		const char *search;
		search = nm_setting_ip_config_get_dns_search (s_ip4, i);
		g_array_append_val (searches, search);
	}

	write_ip4_setting_dhcp_hostname (s_ip4, dhcp_overrides);
#if 0  // TODO: default-route toggles and peer, dhcp settings.
nm_setting_ip_config_get_never_default (s_ip4)
nm_setting_ip_config_get_ignore_auto_dns (s_ip4)
nm_setting_ip_config_get_ignore_auto_routes (s_ip4)
nm_setting_ip_config_get_dhcp_hostname (s_ip4)
nm_setting_ip4_config_get_dhcp_fqdn (NM_SETTING_IP4_CONFIG (s_ip4))
nm_setting_ip_config_get_dhcp_send_hostname (s_ip4)
nm_setting_ip4_config_get_dhcp_client_id (NM_SETTING_IP4_CONFIG (s_ip4))
nm_setting_ip_config_get_dhcp_timeout (s_ip4)
ifcfg-rh:
DEFROUTE
PEERDNS
PEERROUTES
DHCP_HOSTNAME
DHCP_FQDN
DHCP_SEND_HOSTNAME
DHCP_CLIENT_ID
IPV4_DHCP_TIMEOUT
#endif

	write_route_settings (s_ip4, routes);

#if 0  // TODO: Implement route settings here for ipv4
nm_setting_ip_config_get_may_fail (s_ip4)
nm_setting_ip_config_get_route_metric (s_ip4)
nm_setting_ip_config_get_route_table (s_ip4)
nm_setting_ip_config_get_dad_timeout (s_ip4)
write_route_settings (s_ip4)
nm_setting_ip_config_get_dns_priority (s_ip4)
ifcfg-rh:
write_route_file_svformat (svFileGetName (netplan)
write_res_options (netplan, s_ip4, "RES_OPTIONS")
IPV4_FAILURE_FATAL
IPV4_ROUTE_METRIC
IPV4_ROUTE_TABLE
ACD_TIMEOUT
ARPING_WAIT
IPV4_DNS_PRIORITY
RES_OPTIONS
#endif

	return TRUE;
}

#if 0 /* temp disable; write addresses: */
static void
write_ip4_aliases (NMConnection *connection, GArray *addresses, const char *base_netplan_path)
{
	NMSettingIPConfig *s_ip4;
	gs_free char *base_netplan_dir = NULL, *base_netplan_name = NULL;
	//const char *base_name;
	int i, num, base_netplan_name_len; //, base_name_len;
	//GDir *dir;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (!s_ip4)
		return;

	num = nm_setting_ip_config_get_num_addresses (s_ip4);
	for (i = 0; i < num; i++) {
		NMIPAddress *addr;
		GString *ip_addr;
		const char *address;

		addr = nm_setting_ip_config_get_address (s_ip4, i);

		ip_addr = g_string_sized_new(50);
		g_string_printf (ip_addr, "%s/%d",
		                 nm_ip_address_get_address (addr),
		                 nm_ip_address_get_prefix (addr));

		address = g_string_free(ip_addr, FALSE);
		g_array_append_val(addresses, address);
	}
}
#endif

static void
write_ip6_setting_dhcp_hostname (NMSettingIPConfig *s_ip6,
                                 GHashTable *dhcp_overrides)
{
	const char *hostname;

	hostname = nm_setting_ip_config_get_dhcp_hostname (s_ip6);
	if (hostname)
		g_hash_table_insert (dhcp_overrides, "hostname", g_strdup(hostname));

	if (!nm_setting_ip_config_get_dhcp_send_hostname (s_ip6))
		g_hash_table_insert (dhcp_overrides, "send-hostname", g_strdup("no"));
}

static gboolean
write_ip6_setting (NMConnection *connection,
                   GOutputStream *netplan,
                   GArray *addresses,
                   GArray *nameservers,
                   GArray *searches,
                   GArray *routes,
                   GHashTable *dhcp_overrides,
                   GError **error)
{
	NMSettingIPConfig *s_ip6;
	const char *value;
	guint i, num; //, num4;
	//int priority;
	NMIPAddress *addr;
	const char *dns;
	const char *gateway = NULL;
	//gint64 route_metric;
	//NMIPRouteTableSyncMode route_table;
	GString *ip_str;
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6)
		return TRUE;

	gateway = nm_setting_ip_config_get_gateway (s_ip6);
	if (gateway)
		g_output_stream_printf(netplan, 0, NULL, NULL,
		                       "      gateway6: %s\n", gateway);

	value = nm_setting_ip_config_get_method (s_ip6);
	nm_assert (value);
	if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_IGNORE)) {
		return TRUE;
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
		// TODO: set optional flag in netplan
		return TRUE;
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_AUTO)) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "      dhcp6: yes\n");
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_DHCP)) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "      dhcp6: yes\n");
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
		// TODO: implement addresses: [] separately; below
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL)) {
		// TODO: set optional flag in netplan
	} else if (!strcmp (value, NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		// TODO: implement sharing
	}

#if 0  // TODO: implement DUID selection in netplan
nm_setting_ip6_config_get_dhcp_duid (NM_SETTING_IP6_CONFIG (s_ip6))
ifcfg-rh:
DHCPV6_DUID
#endif

	write_ip6_setting_dhcp_hostname (s_ip6, dhcp_overrides);
	// TODO: Write out dhcp_overrides to GOutputStream

	/* Write out IP addresses */
	num = nm_setting_ip_config_get_num_addresses (s_ip6);
	for (i = 0; i < num; i++) {
		ip_str = g_string_new (NULL);
		addr = nm_setting_ip_config_get_address (s_ip6, i);
		g_string_printf (ip_str, "%s/%u",
		                 nm_ip_address_get_address (addr),
		                 nm_ip_address_get_prefix (addr));
		value = g_string_free(ip_str, FALSE);
		g_array_append_val(addresses, value);
	}

	/* Write out DNS - 'DNS' key is used both for IPv4 and IPv6 */
	//s_ip4 = nm_connection_get_setting_ip4_config (connection);
	num = nm_setting_ip_config_get_num_dns (s_ip6);
	for (i = 0; i < num; i++) {
		dns = nm_setting_ip_config_get_dns (s_ip6, i);
		g_array_append_val(nameservers, dns);
	}

	/* Write out DNS domains */
	num = nm_setting_ip_config_get_num_dns_searches (s_ip6);
	for (i = 0; i < num; i++) {
		value = nm_setting_ip_config_get_dns_search (s_ip6, i);
		g_array_append_val (searches, value);
	}

	/* handle IPV6_DEFROUTE */
	/* IPV6_DEFROUTE has the opposite meaning from 'never-default' */
	if (nm_setting_ip_config_get_never_default (s_ip6)) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "      dhcp6-overrides:\n");
		g_output_stream_printf(netplan, 0, NULL, NULL, "        use-routes: no\n");
	}

#if 0  // TODO: more about "optional" (see above)
nm_setting_ip_config_get_may_fail (s_ip6) ? "no" : "yes")
ifcfg-rh:
IPV6_FAILURE_FATAL
#endif

#if 0  // TODO: Implement proper writing of the metric value to netplan YAML
	route_metric = nm_setting_ip_config_get_route_metric (s_ip6);
	if (route_metric != -1)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      metric: %ld\n", route_metric);
#endif

	write_route_settings (s_ip6, routes);

#if 0  // TODO: Implement this route as a formal route (rather than gatewayN) to set route table
// TODO: Implement RouteTable= (networkd)  for DHCP.
route_table = nm_setting_ip_config_get_route_table (s_ip6)
ifcfg-rh:
IPV6_ROUTE_TABLE
#endif

	/* IPv6 Privacy Extensions */
	switch (nm_setting_ip6_config_get_ip6_privacy (NM_SETTING_IP6_CONFIG (s_ip6))) {
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR:
		// TODO: not implemented; for now fallback to always use temporary
	case NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR:
		g_output_stream_printf(netplan, 0, NULL, NULL, "      ipv6-privacy: yes\n");
	break;
	default:
	break;
	}

	/* IPv6 Address generation mode */
	addr_gen_mode = nm_setting_ip6_config_get_addr_gen_mode (NM_SETTING_IP6_CONFIG (s_ip6));
	if (addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY)
		g_output_stream_printf(netplan, 0, NULL, NULL,
		                       "      ipv6-address-generation: stable-privacy\n");
	else if (addr_gen_mode == NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64)
		g_output_stream_printf(netplan, 0, NULL, NULL,
		                       "      ipv6-address-generation: eui64\n");

#if 0  // TODO: Support interface identifier. (not in netplan yet)
nm_setting_ip6_config_get_token (NM_SETTING_IP6_CONFIG (s_ip6))
ifcfg-rh:
IPV6_TOKEN
#endif

#if 0  // TODO: Implement priority for connections (probably NM-specific)
nm_setting_ip_config_get_dns_priority (s_ip6)
ifcfg-rh:
write_res_options (netplan, s_ip6, "IPV6_RES_OPTIONS")
IPV6_DNS_PRIORITY
#endif

	return TRUE;
}

static void
write_ip_routing_rules (NMConnection *connection,
                        GOutputStream *netplan)
{
	//gsize idx = 0;
	int is_ipv4, tmp;
	long int li;
	GString *routing_policy;

	routing_policy = g_string_sized_new (200);

	for (is_ipv4 = 1; is_ipv4 >= 0; is_ipv4--) {
		const int addr_family = is_ipv4 ? AF_INET : AF_INET6;
		NMSettingIPConfig *s_ip;
		guint i, num;
		guint8 to_len, from_len;
		const char *to = NULL, *from = NULL;

		s_ip = nm_connection_get_setting_ip_config (connection, addr_family);
		if (!s_ip)
			continue;

		num = nm_setting_ip_config_get_num_routing_rules (s_ip);
		for (i = 0; i < num; i++) {
			NMIPRoutingRule *rule = nm_setting_ip_config_get_routing_rule (s_ip, i);
			gs_free const char *s = NULL;
			//char key[64];
			to = nm_ip_routing_rule_get_to (rule);
			to_len = nm_ip_routing_rule_get_to_len (rule);
			from = nm_ip_routing_rule_get_from (rule);
			from_len = nm_ip_routing_rule_get_from_len (rule);

			/* Fallback to from=ALL, iff neither "to" nor "from" are set.
			 * As done in nm_ip_routing_rule_to_string() */
			if (!to && !from) {
				from = is_ipv4 ? "0.0.0.0" : "::";
				from_len = 0;
			}

			/* Netplan expects either "to" or "from" to be set. */
			if (to)
				g_string_append_printf (routing_policy,
				                        "        - to: %s/%u\n", to, to_len);
			else if (from)
				g_string_append_printf (routing_policy,
			                            "        - from: %s/%u\n", from, from_len);
			else
				nm_assert_not_reached ();

			if (to && from)
				g_string_append_printf (routing_policy,
				                        "          from: %s/%u\n", from, from_len);

			tmp = nm_ip_routing_rule_get_table (rule);
			if (tmp)
				g_string_append_printf (routing_policy, "          table: %d\n", tmp);

			tmp = nm_ip_routing_rule_get_fwmark (rule);
			if (tmp)
				g_string_append_printf (routing_policy, "          mark: %d\n", tmp);

			tmp = nm_ip_routing_rule_get_tos (rule);
			if (tmp)
				g_string_append_printf (routing_policy, "          type-of-service: %d\n", tmp);

			li = nm_ip_routing_rule_get_priority (rule);
			if (li)
				g_string_append_printf (routing_policy, "          priority: %ld\n", li);
		}
	}

	if (routing_policy->len > 0)
		g_output_stream_printf(netplan, 0, NULL, NULL,
		                       "      routing-policy:\n%s", routing_policy->str);

	g_string_free (routing_policy, TRUE);
}

static gboolean
do_write_construct (NMConnection *connection,
                    GOutputStream *netplan,
                    GError **error)
{
	NMSettingConnection *s_con;
	//NMSettingIPConfig *s_ip4;
	//NMSettingIPConfig *s_ip6;
	const char *type = NULL, *id = NULL;
	GString *id_str = NULL;
	GArray *addresses, *nameservers, *searches, *routes;
	GHashTable *dhcp4_overrides, *dhcp6_overrides;

	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS);

	addresses = g_array_new (TRUE, FALSE, sizeof(char *));
	nameservers = g_array_new (TRUE, FALSE, sizeof(char *));
	searches = g_array_new (TRUE, FALSE, sizeof(char *));
	routes = g_array_new (TRUE, FALSE, sizeof(GHashTable *));
	dhcp6_overrides = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
	dhcp4_overrides = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

	if (!nms_netplan_writer_can_write_connection (connection, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);

	type = nm_setting_connection_get_connection_type (s_con);
	if (!type) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing connection type!");
		return FALSE;
	}

	g_output_stream_printf (netplan, 0, NULL, NULL,
	                        "network:\n  version: 2\n  renderer: NetworkManager\n");

	id = nm_connection_get_interface_name (connection);
	/* Fallback to "NM-<UUID>" based naming, if ifname is not set. */
	if (!nm_str_not_empty (id)) {
		id_str = g_string_new (nm_connection_get_uuid (connection));
		id_str = g_string_prepend(id_str, "NM-");
		id = g_string_free(id_str, FALSE);
	}

	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
		// TODO: Implement PPPoE support.
		if (nm_connection_get_setting_pppoe (connection)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Can't write connection type '%s'",
			             NM_SETTING_PPPOE_SETTING_NAME);
			return FALSE;
		}

		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  ethernets:\n    %s:\n", id);
		if (!write_wired_setting (connection, netplan, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_VLAN_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  vlans:\n    %s:\n", id);
		if (!write_vlan_setting (connection, netplan, error))
			return FALSE;
	} else if (NM_IN_STRSET (type, NM_SETTING_GSM_SETTING_NAME, NM_SETTING_CDMA_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  modems:\n    %s:\n", id);
		if (!write_modem_setting (connection, netplan, error, type))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  wifis:\n    %s:\n", id);
		if (!write_wireless_setting (connection, netplan, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
#if 0
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  ethernets:\n    %s:\n", id);
		if (!write_infiniband_setting (connection, netplan, error))
#endif
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_BOND_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  bonds:\n    %s:\n", id);
		if (!write_bond_setting (connection, netplan, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_TEAM_SETTING_NAME)) {
#if 0
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  ethernets:\n    %s:\n", id);
		if (!write_team_setting (connection, netplan, error))
#endif
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  bridges:\n    %s:\n", id);
		if (!write_bridge_setting (connection, netplan, error))
			return FALSE;
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Can't write connection type '%s'", type);
		return FALSE;
	}

	//if (!write_team_port_setting (connection, netplan, error))
	//    return FALSE;

	//if (!write_dcb_setting (connection, netplan, error))
	//    return FALSE;

	//if (!write_proxy_setting (connection, netplan, error))
	//    return FALSE;

	//if (!write_ethtool_setting (connection, netplan, error))
	//    return FALSE;

	//if (!write_user_setting (connection, netplan, error))
	//    return FALSE;

	if (!write_match_setting (connection, netplan, error))
		return FALSE;

	//write_sriov_setting (connection, netplan);

	//if (!write_tc_setting (connection, netplan, error))
	//    return FALSE;

	if (!write_ip4_setting (connection,
	                        netplan,
	                        addresses,
	                        nameservers,
	                        searches,
	                        routes,
	                        dhcp4_overrides,
	                        error))
		return FALSE;

	if (!write_ip6_setting (connection,
	                        netplan,
	                        addresses,
	                        nameservers,
	                        searches,
	                        routes,
	                        dhcp6_overrides,
	                        error))
		return FALSE;

	/**
	 * Write IP4 & IP6 addresses in CIDR format
	 */
	if (addresses->len > 0)
		write_array_to_sequence(addresses, netplan, "      addresses:");

	/**
	 * Write IP4 & IP6 DNS nameserver addresses and search
	 */
	if (nameservers->len > 0 || searches->len > 0)
		g_output_stream_printf(netplan, 0, NULL, NULL, "      nameservers:\n");
	if (nameservers->len > 0)
		write_array_to_sequence(nameservers, netplan, "        addresses:");
	if (searches->len > 0)
		write_array_to_sequence(searches, netplan, "        search:");

	/**
	 * Write dhcp6-overrides
	 */
	if (g_hash_table_size(dhcp6_overrides) > 0) {
		struct HashToDict htd;
		htd.stream = netplan;
		htd.indent = g_strdup("        ");
		g_output_stream_printf(netplan, 0, NULL, NULL, "      dhcp6-overrides:\n");
		g_hash_table_foreach(dhcp6_overrides, write_hashtable_to_dict, &htd);
		g_free(htd.indent);
	}

	/**
	 * Write dhcp4-overrides
	 */
	if (g_hash_table_size(dhcp4_overrides) > 0) {
		struct HashToDict htd;
		htd.stream = netplan;
		htd.indent = g_strdup("        ");
		g_output_stream_printf(netplan, 0, NULL, NULL, "      dhcp4-overrides:\n");
		g_hash_table_foreach(dhcp4_overrides, write_hashtable_to_dict, &htd);
		g_free(htd.indent);
	}

	/**
	 * Write pre-filled IP4 & IP6 routes mapping
	 */
	if (routes->len > 0) {
		g_output_stream_printf (netplan, 0, NULL, NULL, "      routes:\n");
		GHashTable *tbl = NULL;
		for (unsigned i = 0; i < routes->len; ++i) {
			tbl = g_array_index(routes, GHashTable*, i);
			size_t len = 3;
			char* keys[3] = { "to", "via", "metric" };
			char* indent = NULL;
			char* v = NULL;
			for (unsigned j = 0; j < len; ++j) {
				indent = (!j) ? "      - " : "        ";
				v = (char*) g_hash_table_lookup(tbl, keys[j]);
				if (v)
					g_output_stream_printf (netplan, 0, NULL, NULL,
					                        "%s%s: %s\n", indent, keys[j], v);
			}
		}
	}

	/**
	 * Write routing rules (routing-policy)
	 */
	write_ip_routing_rules (connection, netplan);

	write_connection_setting (s_con, netplan);

	/**
	 * Write bridge-port settings, by adding the master bridge interface
	 * to the YAML. It will be merged with its own YAML definition, when
	 * the YAML files are read and combined/merged.
	 * This adds a new "bridges:" section to the YAML, so this code needs
	 * to run after all settings for the current netdef have been written. */
	if (!write_bridge_port_setting (connection, netplan, error))
		return FALSE;

	//NM_SET_OUT (out_netplan, g_steal_pointer (&netplan));
	return TRUE;
}

static gboolean
do_write_to_disk (NMConnection *connection,
                  GOutputStream *netplan,
                  GHashTable *blobs,
                  GHashTable *secrets,
                  gboolean route_ignore,
                  GOutputStream *route_content_svformat,
                  GString *route_content,
                  GString *route6_content,
                  GError **error)
{
	gboolean ret = FALSE;
	/* From here on, we persist data to disk. Before, it was all in-memory
	 * only. But we loaded the netplan files from disk, and managled our
	 * new settings (in-memory). */

	ret = g_output_stream_close (netplan, NULL, error);
        // TODO: Do we need to take more steps to ensure writes to disk?

	return ret;
}

gboolean
nms_netplan_writer_write_connection (NMConnection *connection,
                                     const char *netplan_dir,
                                     const char *filename,
                                     NMSNetplanWriterAllowFilenameCb allow_filename_cb,
                                     gpointer allow_filename_user_data,
                                     char **out_filename,
                                     NMConnection **out_reread,
                                     gboolean *out_reread_same,
                                     GError **error)
{
	GOutputStream *netplan;
	//gboolean ret = TRUE;
	nm_auto_free_gstring GString *route_content = NULL;
	nm_auto_free_gstring GString *filename_str = NULL;
	gboolean route_ignore = FALSE;
	gs_unref_hashtable GHashTable *secrets = NULL;
	gs_unref_hashtable GHashTable *blobs = NULL;
	GFile *netplan_yaml;
	char *netplan_yaml_path;

	nm_assert (!out_reread || !*out_reread);


	if (!filename) {
		/* Create new YAML config file */
		filename_str = g_string_sized_new (120);
		/* TODO: Should we mark connections (YAML files) with definitions of
		 *   physical VS virtual interfaces (e.g. bridge, bond, ...)? To be
		 *   able to load physical connections prior to virtual connections,
		 *   which might contain references to those physical ifaces and could
		 *   thus break libnetplan's YAML parser. */
		g_string_printf (filename_str, "NM-%s.yaml", nm_connection_get_uuid (connection));

		netplan_yaml_path = g_build_filename (netplan_dir,
		                                      filename_str->str,
		                                      NULL);

		/* Only return the filename if this is a newly written netplan */
		if (out_filename)
			*out_filename = g_strdup(netplan_yaml_path);
	} else {
		/* Update given YAML config file */
		netplan_yaml_path = g_strdup(filename);
	}

	netplan_yaml = g_file_new_for_path (netplan_yaml_path);
	_LOGT ("write: path %s / %s / %p", netplan_dir, g_file_get_path(netplan_yaml),
	       out_filename);

	netplan = (GOutputStream *) g_file_replace (netplan_yaml,
	                                            NULL, FALSE,
	                                            G_FILE_CREATE_REPLACE_DESTINATION,
	                                            NULL, error);
	if (error && *error)
		_LOGT ("netplan: %s", (*error)->message);

	if (!netplan)
		return FALSE;

	if (!do_write_construct (connection,
	                         netplan,
	                         error))
		return FALSE;

	_LOGT ("write: write connection %s (%s) to file \"%s\"",
	       nm_connection_get_id (connection),
	       nm_connection_get_uuid (connection),
	       netplan_yaml_path);

	if (!do_write_to_disk (connection,
	                       netplan,
	                       blobs,
	                       secrets,
	                       route_ignore,
	                       NULL, NULL, NULL,
	                       error))
		return FALSE;

	/* Note that we just wrote the connection to disk, and re-read it from there.
	 * That is racy if somebody else modifies the connection.
	 * That race is why we must not tread a failure to re-read the profile
	 * as an error.
	 *
	 * FIXME: a much better solution might be, to re-read the connection only based
	 * on the in-memory representation of what we collected above. But the reader
	 * does not yet allow to inject the configuration. */
	if (   out_reread
	    || out_reread_same) {
		gs_unref_object NMConnection *reread = NULL;
		gboolean reread_same = FALSE;
		gs_free_error GError *local = NULL;
		gs_free char *unhandled = NULL;

		reread = connection_from_file (netplan_yaml_path,
		                               &unhandled,
		                               &local,
		                               NULL);
		nm_assert ((NM_IS_CONNECTION (reread) && !local) || (!reread && local));

		if (!reread) {
			_LOGW ("write: failure to re-read connection \"%s\": %s",
			       netplan_yaml_path, local->message);
		} else if (unhandled) {
			g_clear_object (&reread);
			_LOGW ("write: failure to re-read connection \"%s\": %s",
			       netplan_yaml_path, "connection is unhandled");
		} else {
			if (out_reread_same) {
				reread_same = nm_connection_compare (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT);
				if (!reread_same) {
					_LOGD ("write: connection %s (%s) was modified by persisting it to \"%s\" ",
					       nm_connection_get_id (connection),
					       nm_connection_get_uuid (connection),
					       netplan_yaml_path);
				}
			}
		}

		NM_SET_OUT (out_reread, g_steal_pointer (&reread));
		NM_SET_OUT (out_reread_same, reread_same);
	}

	return TRUE;
}

gboolean
nms_netplan_writer_can_write_connection (NMConnection *connection, GError **error)
{
	const char *type, *id;

	type = nm_connection_get_connection_type (connection);
	_LOGD ("MATT: writing \"%s\"", type);
	if (NM_IN_STRSET (type,
	                  NM_SETTING_VLAN_SETTING_NAME,
	                  NM_SETTING_WIRELESS_SETTING_NAME,
	                  NM_SETTING_GSM_SETTING_NAME,
	                  NM_SETTING_CDMA_SETTING_NAME,
	                  NM_SETTING_BOND_SETTING_NAME,
	                  //NM_SETTING_TEAM_SETTING_NAME,
	                  NM_SETTING_BRIDGE_SETTING_NAME))
		return TRUE;
	if (nm_streq0 (type, NM_SETTING_WIRED_SETTING_NAME)
	    && !nm_connection_get_setting_pppoe (connection))
		return TRUE;

	id = nm_connection_get_id (connection);
	g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
	             "The netplan plugin cannot write the connection %s%s%s (type %s%s%s)",
	             NM_PRINT_FMT_QUOTE_STRING (id),
	             NM_PRINT_FMT_QUOTE_STRING (type));
	return FALSE;
}
