// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd..
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

#if 0  /* GCC Magic */
static void
save_secret_flags (GOutputStream *netplan,
                   const char *key,
                   NMSettingSecretFlags flags)
{
#if 0 // TODO: we don't do secret_flags yet.
	GString *str;

	g_return_if_fail (netplan != NULL);
	g_return_if_fail (key != NULL);

	if (flags == NM_SETTING_SECRET_FLAG_NONE) {
		svUnsetValue (netplan, key);
		return;
	}

	/* Convert flags bitfield into string representation */
	str = g_string_sized_new (20);
	if (flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)
		g_string_append (str, SECRET_FLAG_AGENT);

	if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED) {
		if (str->len)
			g_string_append_c (str, ' ');
		g_string_append (str, SECRET_FLAG_NOT_SAVED);
	}

	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		if (str->len)
			g_string_append_c (str, ' ');
		g_string_append (str, SECRET_FLAG_NOT_REQUIRED);
	}

	svSetValueStr (netplan, key, str->len ? str->str : NULL);
	g_string_free (str, TRUE);
#endif
}

static void
set_secret (GOutputStream *netplan,
            GHashTable *secrets,
            const char *key,
            const char *value,
            const char *flags_key,
            NMSettingSecretFlags flags)
{
	// TODO: check how to handle secret flags -- toggles for special behavior of secrets.
#if 0 // TODO: set_secret(): we write secrets directly to the main YAML file for netplan
	/* Clear the secret from the netplan and the associated "keys" file */
	svUnsetValue (netplan, key);

	/* Save secret flags */
	save_secret_flags (netplan, flags_key, flags);

	/* Only write the secret if it's system owned and supposed to be saved */
	if (flags != NM_SETTING_SECRET_FLAG_NONE)
		value = NULL;

	g_hash_table_replace (secrets, g_strdup (key), g_strdup (value));
#endif
}

static gboolean
write_secrets (GOutputStream *netplan,
               GHashTable *secrets,
               GError **error)
{
#if 0  // TODO: write_secrets(): we don't write secrets to a separate file for netplan...
	nm_auto_shvar_file_close shvarFile *keyfile = NULL;
	gs_free const char **secrets_keys = NULL;
	guint i, secrets_keys_n;
	GError *local = NULL;
	gboolean any_secrets = FALSE;

	keyfile = utils_get_keys_netplan (svFileGetName (netplan), TRUE);
	if (!keyfile) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Failure to create secrets file for '%s'", svFileGetName (netplan));
		return FALSE;
	}

	/* we purge all existing secrets. */
	svUnsetAll (keyfile, SV_KEY_TYPE_ANY);

	secrets_keys = nm_utils_strdict_get_keys (secrets, TRUE, &secrets_keys_n);
	for (i = 0; i < secrets_keys_n; i++) {
		const char *k = secrets_keys[i];
		const char *v = g_hash_table_lookup (secrets, k);

		if (v) {
			svSetValueStr (keyfile, k, v);
			any_secrets = TRUE;
		}
	}

	if (!any_secrets)
		(void) unlink (svFileGetName (keyfile));
	else if (!svWriteFile (keyfile, 0600, &local)) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Failure to write secrets to '%s': %s", svFileGetName (keyfile), local->message);
		return FALSE;
	}
#endif
	return TRUE;
}

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
write_object (NMSetting8021x *s_8021x,
              GOutputStream *netplan,
              GHashTable *secrets,
              GHashTable *blobs,
              const Setting8021xSchemeVtable *objtype,
              gboolean force_write,
              GError **error)
{
	NMSetting8021xCKScheme scheme;
	const char *value = NULL;
	const char *password = NULL;
	const char *extension;
	char *standard_file;

	g_return_val_if_fail (netplan != NULL, FALSE);
	g_return_val_if_fail (objtype != NULL, FALSE);

	scheme = (*(objtype->vtable->scheme_func))(s_8021x);
	switch (scheme) {
	case NM_SETTING_802_1X_CK_SCHEME_UNKNOWN:
		break;
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		value = (*(objtype->vtable->path_func))(s_8021x);
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		value = (*(objtype->vtable->uri_func))(s_8021x);
		break;
	default:
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Unhandled certificate object scheme");
		return FALSE;
	}

	/* Set the password for certificate/private key. */
	//nm_sprintf_buf (secret_flags, "%s_PASSWORD_FLAGS", objtype->netplan_key);
	//flags = (*(objtype->vtable->pwflag_func))(s_8021x);
	//set_secret (netplan, secrets, secret_name, password, secret_flags, flags);
	password = (*(objtype->vtable->passwd_func))(s_8021x);
	if (password)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "          %s-password: \"%s\"\n",
			                objtype->netplan_key, password);

	/* If the object path was specified, prefer that over any raw cert data that
	 * may have been sent.
	 */
	if (value) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
				        "          %s: %s\n",
				        objtype->netplan_key, value);
		return TRUE;
	}

#if 0 // TODO: netplan does not yet support saving binary certs instead of paths
	if (!objtype->vtable->format_func)
		extension = "der";
	else if (objtype->vtable->format_func (s_8021x) == NM_SETTING_802_1X_CK_FORMAT_PKCS12)
		extension = "p12";
	else
		extension = "pem";

	/* If it's raw certificate data, write the data out to the standard file */
	if (blob) {
		char *new_file;

		new_file = utils_cert_path (svFileGetName (netplan), objtype->vtable->file_suffix, extension);
		g_hash_table_replace (blobs, new_file, g_bytes_ref (blob));
		svSetValueStr (netplan, objtype->netplan_key, new_file);
		return TRUE;
	}

	/* If certificate/private key wasn't sent, the connection may no longer be
	 * 802.1x and thus we clear out the paths and certs.
	 *
	 * Since no cert/private key is now being used, delete any standard file
	 * that was created for this connection, but leave other files alone.
	 * Thus, for example,
	 * /etc/sysconfig/network-scripts/ca-cert-Test_Write_Wifi_WPA_EAP-TLS.der
	 * will be deleted, but /etc/pki/tls/cert.pem will not.
	 */
	standard_file = utils_cert_path (svFileGetName (netplan), objtype->vtable->file_suffix, extension);
	g_hash_table_replace (blobs, standard_file, NULL);
	svSetValue (netplan, objtype->netplan_key, force_write ? "" : NULL);
#endif
	return FALSE;
}

static gboolean
write_blobs (GHashTable *blobs, GError **error)
{
	GHashTableIter iter;
	const char *filename;
	GBytes *blob;

#if 0 // TODO: netplan does not yet support saving binary blobs in yaml (802.1x certs)
	if (!blobs)
		return TRUE;

	g_hash_table_iter_init (&iter, blobs);
	while (g_hash_table_iter_next (&iter, (gpointer *) &filename, (gpointer *) &blob)) {
		GError *write_error = NULL;

		if (!blob) {
			(void) unlink (filename);
			continue;
		}

		/* Write the raw certificate data out to the standard file so that we
		 * can use paths from now on instead of pushing around the certificate
		 * data itself.
		 */
		if (!nm_utils_file_set_contents (filename,
		                                 (const char *) g_bytes_get_data (blob, NULL),
		                                 g_bytes_get_size (blob),
		                                 0600,
		                                 NULL,
		                                 &write_error)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Could not write certificate to file \"%s\": %s",
			             filename,
			             write_error->message);
			return FALSE;
		}
	}
#endif

	return TRUE;
}

static gboolean
write_8021x_certs (NMSetting8021x *s_8021x,
                   GHashTable *secrets,
                   GHashTable *blobs,
                   gboolean phase2,
                   GOutputStream *netplan,
                   GError **error)
{
	const Setting8021xSchemeVtable *pk_otype = NULL;
	gs_free char *value_to_free = NULL;

	/* CA certificate */
	if (!write_object (s_8021x, netplan, secrets, blobs,
	                   phase2
	                       ? &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CA_CERT]
	                       : &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CA_CERT],
	                   FALSE,
	                   error))
		return FALSE;

	/* Private key */
	if (phase2)
		pk_otype = &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_PRIVATE_KEY];
	else
		pk_otype = &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PRIVATE_KEY];

	/* Save the private key */
	if (!write_object (s_8021x, netplan, secrets, blobs, pk_otype, FALSE, error))
		return FALSE;

	/* Save the client certificate.
	 * If there is a private key, always write a property for the
	 * client certificate even if it is empty, so that the reader
	 * doesn't have to read the private key file to determine if it
	 * is a PKCS #12 one which serves also as client certificate.
	 */
	if (!write_object (s_8021x, netplan, secrets, blobs,
	                   phase2
	                       ? &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_PHASE2_CLIENT_CERT]
	                       : &setting_8021x_scheme_vtable[NM_SETTING_802_1X_SCHEME_TYPE_CLIENT_CERT],
	                   FALSE, // XXX: may need adjustment; ifcfg-rh uses a conditional here.
	                   error))
		return FALSE;

	return TRUE;
}
#endif  /* GCC magic */

#if 0  /* temp disable: unused?? */
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
				        "        key-management: %s\n", "802.1x");

	/* EAP method */
	if (nm_setting_802_1x_get_num_eap_methods (s_8021x)) {
		value = nm_setting_802_1x_get_eap_method (s_8021x, 0);
		// TODO: For 802.1x: NetworkManager has a bunch of extra "EAP" methods that we should support.
		// See eap_methods_table  in libnm-core/nm-setting-8021x.c
		if (!g_strcmp0(value, "peap") || !g_strcmp0(value, "tls") || !g_strcmp0(value, "ttls")) {
			g_output_stream_printf (netplan, 0, NULL, NULL,
					        "        method: %s\n", value);
		} else {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Unsupported '%s' method in netplan", value);
		}
		return FALSE;
	}

	g_output_stream_printf (netplan, 0, NULL, NULL,
			        "        identity: %s\n",
	                        nm_setting_802_1x_get_identity (s_8021x));

	g_output_stream_printf (netplan, 0, NULL, NULL,
			        "        anonymous-identity: %s\n",
	                        nm_setting_802_1x_get_anonymous_identity (s_8021x));

	g_output_stream_printf (netplan, 0, NULL, NULL,
			        "        password: %s\n",
			        nm_setting_802_1x_get_password(s_8021x));

#if 0 // TODO: 802.1x use set_secret instead of g_output_stream_printf()...
	set_secret (netplan,
	            secrets,
	            "IEEE_8021X_PASSWORD",
	            nm_setting_802_1x_get_password (s_8021x),
	            "IEEE_8021X_PASSWORD_FLAGS",
	            nm_setting_802_1x_get_password_flags (s_8021x));
#endif

#if 0 // TODO: 802.1x complex EAP / PEAP and other auth settings
	tmp = NULL;
	bytes = nm_setting_802_1x_get_password_raw (s_8021x);
	if (bytes) {
		ptr = g_bytes_get_data (bytes, &size);
		tmp = nm_utils_bin2hexstr (ptr, size, -1);
	}
	set_secret (netplan,
	            secrets,
	            "IEEE_8021X_PASSWORD_RAW",
	            tmp,
	            "IEEE_8021X_PASSWORD_RAW_FLAGS",
	            nm_setting_802_1x_get_password_raw_flags (s_8021x));
	g_free (tmp);

	/* PEAP version */
	value = nm_setting_802_1x_get_phase1_peapver (s_8021x);
	svUnsetValue (netplan, "IEEE_8021X_PEAP_VERSION");
	if (value && (!strcmp (value, "0") || !strcmp (value, "1")))
		svSetValueStr (netplan, "IEEE_8021X_PEAP_VERSION", value);

	/* Force new PEAP label */
	value = nm_setting_802_1x_get_phase1_peaplabel (s_8021x);
	svUnsetValue (netplan, "IEEE_8021X_PEAP_FORCE_NEW_LABEL");
	if (value && !strcmp (value, "1"))
		svSetValueStr (netplan, "IEEE_8021X_PEAP_FORCE_NEW_LABEL", "yes");

	/* PAC file */
	value = nm_setting_802_1x_get_pac_file (s_8021x);
	svUnsetValue (netplan, "IEEE_8021X_PAC_FILE");
	if (value)
		svSetValueStr (netplan, "IEEE_8021X_PAC_FILE", value);

	/* FAST PAC provisioning */
	value = nm_setting_802_1x_get_phase1_fast_provisioning (s_8021x);
	svUnsetValue (netplan, "IEEE_8021X_FAST_PROVISIONING");
	if (value) {
		if (strcmp (value, "1") == 0)
			svSetValueStr (netplan, "IEEE_8021X_FAST_PROVISIONING", "allow-unauth");
		else if (strcmp (value, "2") == 0)
			svSetValueStr (netplan, "IEEE_8021X_FAST_PROVISIONING", "allow-auth");
		else if (strcmp (value, "3") == 0)
			svSetValueStr (netplan, "IEEE_8021X_FAST_PROVISIONING", "allow-unauth allow-auth");
	}

	/* Phase2 auth methods */
	svUnsetValue (netplan, "IEEE_8021X_INNER_AUTH_METHODS");
	phase2_auth = g_string_new (NULL);

	value = nm_setting_802_1x_get_phase2_auth (s_8021x);
	if (value) {
		tmp = g_ascii_strup (value, -1);
		g_string_append (phase2_auth, tmp);
		g_free (tmp);
	}

	value = nm_setting_802_1x_get_phase2_autheap (s_8021x);
	if (value) {
		if (phase2_auth->len)
			g_string_append_c (phase2_auth, ' ');

		tmp = g_ascii_strup (value, -1);
		g_string_append_printf (phase2_auth, "EAP-%s", tmp);
		g_free (tmp);
	}

	auth_flags = nm_setting_802_1x_get_phase1_auth_flags (s_8021x);
	if (auth_flags == NM_SETTING_802_1X_AUTH_FLAGS_NONE) {
		svUnsetValue (netplan, "IEEE_8021X_PHASE1_AUTH_FLAGS");
	} else {
		svSetValueEnum (netplan, "IEEE_8021X_PHASE1_AUTH_FLAGS",
		                nm_setting_802_1x_auth_flags_get_type(),
		                auth_flags);
	}

	svSetValueStr (netplan, "IEEE_8021X_INNER_AUTH_METHODS",
	               phase2_auth->len ? phase2_auth->str : NULL);

	g_string_free (phase2_auth, TRUE);

	svSetValueStr (netplan, "IEEE_8021X_SUBJECT_MATCH",
	               nm_setting_802_1x_get_subject_match (s_8021x));

	svSetValueStr (netplan, "IEEE_8021X_PHASE2_SUBJECT_MATCH",
	               nm_setting_802_1x_get_phase2_subject_match (s_8021x));

	svUnsetValue (netplan, "IEEE_8021X_ALTSUBJECT_MATCHES");
	str = g_string_new (NULL);
	num = nm_setting_802_1x_get_num_altsubject_matches (s_8021x);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		match = nm_setting_802_1x_get_altsubject_match (s_8021x, i);
		g_string_append (str, match);
	}
	if (str->len > 0)
		svSetValueStr (netplan, "IEEE_8021X_ALTSUBJECT_MATCHES", str->str);
	g_string_free (str, TRUE);

	svUnsetValue (netplan, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES");
	str = g_string_new (NULL);
	num = nm_setting_802_1x_get_num_phase2_altsubject_matches (s_8021x);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		match = nm_setting_802_1x_get_phase2_altsubject_match (s_8021x, i);
		g_string_append (str, match);
	}
	if (str->len > 0)
		svSetValueStr (netplan, "IEEE_8021X_PHASE2_ALTSUBJECT_MATCHES", str->str);
	g_string_free (str, TRUE);

	svSetValueStr (netplan, "IEEE_8021X_DOMAIN_SUFFIX_MATCH",
	               nm_setting_802_1x_get_domain_suffix_match (s_8021x));
	svSetValueStr (netplan, "IEEE_8021X_PHASE2_DOMAIN_SUFFIX_MATCH",
	               nm_setting_802_1x_get_phase2_domain_suffix_match (s_8021x));

	vint = nm_setting_802_1x_get_auth_timeout (s_8021x);
	svSetValueInt64_cond (netplan, "IEEE_8021X_AUTH_TIMEOUT", vint > 0, vint);
#endif

#if 0 // TODO: 802.1x certs in binary / path
	if (!write_8021x_certs (s_8021x, secrets, blobs, FALSE, netplan, error))
		return FALSE;

	/* phase2/inner certs */
	if (!write_8021x_certs (s_8021x, secrets, blobs, TRUE, netplan, error))
		return FALSE;
#endif

	return TRUE;
}
#endif

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
	gboolean wep = FALSE, wpa = FALSE; //, dynamic_wep = FALSE;
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
	g_assert (key_mgmt);

	//auth_alg = nm_setting_wireless_security_get_auth_alg (s_wsec);

	g_output_stream_printf (netplan, 0, NULL, NULL, "          auth:\n");

	if (!strcmp (key_mgmt, "none")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: none\n");
		wep = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-psk")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: psk\n");
		wpa = TRUE;
	} else if (!strcmp (key_mgmt, "sae")) {
		// TODO: Implement wireless auth SAE mode in netplan
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: sae\n");
		wpa = TRUE;
	} else if (!strcmp (key_mgmt, "ieee8021x")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: 802.1x\n");
		//dynamic_wep = TRUE;
	} else if (!strcmp (key_mgmt, "wpa-eap")) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "            key-management: eap\n");
		wpa = TRUE;
	}

#if 0 // TODO: Unravel this SECURITYMODE story: restricted | open | leap ???
	svUnsetValue (netplan, "SECURITYMODE");
	if (auth_alg) {
		if (!strcmp (auth_alg, "shared"))
			svSetValueStr (netplan, "SECURITYMODE", "restricted");
		else if (!strcmp (auth_alg, "open"))
			svSetValueStr (netplan, "SECURITYMODE", "open");
		else if (!strcmp (auth_alg, "leap")) {
			svSetValueStr (netplan, "SECURITYMODE", "leap");
			svSetValueStr (netplan, "IEEE_8021X_IDENTITY",
			               nm_setting_wireless_security_get_leap_username (s_wsec));
			set_secret (netplan,
			            secrets,
			            "IEEE_8021X_PASSWORD",
			            nm_setting_wireless_security_get_leap_password (s_wsec),
			            "IEEE_8021X_PASSWORD_FLAGS",
			            nm_setting_wireless_security_get_leap_password_flags (s_wsec));
		}
	}
#endif

#if 0 // TODO: support enabling WPS in netplan.
	/* WPS */
	wps_method = nm_setting_wireless_security_get_wps_method (s_wsec);
	if (wps_method == NM_SETTING_WIRELESS_SECURITY_WPS_METHOD_DEFAULT)
		svUnsetValue (netplan, "WPS_METHOD");
	else
		svSetValueEnum (netplan, "WPS_METHOD", nm_setting_wireless_security_wps_method_get_type (), wps_method);
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

#if 0 // TODO: differentiate hex key vs. passphrase in netplan for WEP (see below)
		switch (key_type) {
		case NM_WEP_KEY_TYPE_KEY:
			key_type_str = "key";
			break;
		case NM_WEP_KEY_TYPE_PASSPHRASE:
			key_type_str = "passphrase";
			break;
		case NM_WEP_KEY_TYPE_UNKNOWN:
			break;
		}
		svSetValue (netplan, "KEY_TYPE", key_type_str);
#endif

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
	/* WPA Pairwise ciphers */
	str = g_string_new (NULL);
	num = nm_setting_wireless_security_get_num_pairwise (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_pairwise (s_wsec, i);

		/* Don't write out WEP40 or WEP104 if for some reason they are set; they
		 * are not valid pairwise ciphers.
		 */
		if (strcmp (cipher, "wep40") && strcmp (cipher, "wep104")) {
			tmp = g_ascii_strup (cipher, -1);
			g_string_append (str, tmp);
			g_free (tmp);
		}
	}
	if (strlen (str->str) && (dynamic_wep == FALSE))
		svSetValueStr (netplan, "CIPHER_PAIRWISE", str->str);
	g_string_free (str, TRUE);

	/* WPA Group ciphers */
	svUnsetValue (netplan, "CIPHER_GROUP");
	str = g_string_new (NULL);
	num = nm_setting_wireless_security_get_num_groups (s_wsec);
	for (i = 0; i < num; i++) {
		if (i > 0)
			g_string_append_c (str, ' ');
		cipher = nm_setting_wireless_security_get_group (s_wsec, i);
		tmp = g_ascii_strup (cipher, -1);
		g_string_append (str, tmp);
		g_free (tmp);
	}
	if (strlen (str->str) && (dynamic_wep == FALSE))
		svSetValueStr (netplan, "CIPHER_GROUP", str->str);
	g_string_free (str, TRUE);
#endif

	if (wpa)
		psk = nm_setting_wireless_security_get_psk (s_wsec);

	// XXX: Should be using set_secret() here?
	// FIXME: Add quotes IFF type=WPA-PSK AND length=8-63, otherwise 64 HEX chars
	//        see: https://github.com/CanonicalLtd/netplan/commit/2427ab267b24daa3504345be4ee6be7f286056a3
	g_output_stream_printf(netplan, 0, NULL, NULL,
			       "          password: %s\n", psk);

#if 0 // TODO: wireless security: implement PMF and FILS support
	if (nm_setting_wireless_security_get_pmf (s_wsec) == NM_SETTING_WIRELESS_SECURITY_PMF_DEFAULT)
		svUnsetValue (netplan, "PMF");
	else {
		svSetValueEnum (netplan, "PMF", nm_setting_wireless_security_pmf_get_type (),
		                nm_setting_wireless_security_get_pmf (s_wsec));
	}

	if (nm_setting_wireless_security_get_fils (s_wsec) == NM_SETTING_WIRELESS_SECURITY_FILS_DEFAULT)
		svUnsetValue (netplan, "FILS");
	else {
		svSetValueEnum (netplan, "FILS", nm_setting_wireless_security_fils_get_type (),
		                nm_setting_wireless_security_get_fils (s_wsec));
	}
#endif

	return TRUE;
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
	const char *mode; //, *bssid;
	const char *device_mac, *cloned_mac;
	guint32 mtu, i; //, chan;
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

#if 0	// TODO: fix MAC setting, blacklist for wireless.
	svSetValueStr (netplan, "GENERATE_MAC_ADDRESS_MASK",
	               nm_setting_wireless_get_generate_mac_address_mask (s_wireless));

	svUnsetValue (netplan, "HWADDR_BLACKLIST");
	macaddr_blacklist = nm_setting_wireless_get_mac_address_blacklist (s_wireless);
	if (macaddr_blacklist[0]) {
		char *blacklist_str;

		blacklist_str = g_strjoinv (" ", (char **) macaddr_blacklist);
		svSetValueStr (netplan, "HWADDR_BLACKLIST", blacklist_str);
		g_free (blacklist_str);
	}
#endif

	mtu = nm_setting_wireless_get_mtu (s_wireless);
	if (mtu != 0)
		g_output_stream_printf (netplan, 0, NULL, NULL,
				        "      mtu: %d\n", mtu);

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

#if 0 // TODO: implement channel, band, bssid selection in netplan
	svUnsetValue (netplan, "CHANNEL");
	svUnsetValue (netplan, "BAND");
	chan = nm_setting_wireless_get_channel (s_wireless);
	if (chan) {
		svSetValueInt64 (netplan, "CHANNEL", chan);
	} else {
		/* Band only set if channel is not, since channel implies band */
		svSetValueStr (netplan, "BAND", nm_setting_wireless_get_band (s_wireless));
	}

	bssid = nm_setting_wireless_get_bssid (s_wireless);
	svSetValueStr (netplan, "BSSID", bssid);
#endif

	if (nm_connection_get_setting_wireless_security (connection)) {
		if (!write_wireless_security_setting (connection, netplan, NULL, adhoc, error))
			return FALSE;
	}

	// TODO: add support for non-broadcast (hidden) SSID.
	//svSetValueStr (netplan, "SSID_HIDDEN", nm_setting_wireless_get_hidden (s_wireless) ? "yes" : NULL);

#if 0 // TODO: implement wifi powersave mode selection.
	switch (nm_setting_wireless_get_powersave (s_wireless)) {
	case NM_SETTING_WIRELESS_POWERSAVE_IGNORE:
		svSetValueStr (netplan, "POWERSAVE", "ignore");
		break;
	case NM_SETTING_WIRELESS_POWERSAVE_DISABLE:
		svSetValueStr (netplan, "POWERSAVE", "disable");
		break;
	case NM_SETTING_WIRELESS_POWERSAVE_ENABLE:
		svSetValueStr (netplan, "POWERSAVE", "enable");
		break;
	default:
	case NM_SETTING_WIRELESS_POWERSAVE_DEFAULT:
		svUnsetValue (netplan, "POWERSAVE");
		break;
	}
#endif

#if 0 // TODO: implement wifi MAC address randomization in netplan
	switch (nm_setting_wireless_get_mac_address_randomization (s_wireless)) {
	case NM_SETTING_MAC_RANDOMIZATION_NEVER:
		svSetValueStr (netplan, "MAC_ADDRESS_RANDOMIZATION", "never");
		break;
	case NM_SETTING_MAC_RANDOMIZATION_ALWAYS:
		svSetValueStr (netplan, "MAC_ADDRESS_RANDOMIZATION", "always");
		break;
	case NM_SETTING_MAC_RANDOMIZATION_DEFAULT:
	default:
		svSetValueStr (netplan, "MAC_ADDRESS_RANDOMIZATION", "default");
		break;
	}
#endif

	return TRUE;
}

#if 0 // TODO: implement infiniband!
static gboolean
write_infiniband_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingInfiniband *s_infiniband;
	const char *mac, *transport_mode, *parent;
	guint32 mtu;
	int p_key;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_INFINIBAND_SETTING_NAME);
		return FALSE;
	}

	mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	svSetValueStr (netplan, "HWADDR", mac);

	mtu = nm_setting_infiniband_get_mtu (s_infiniband);
	svSetValueInt64_cond (netplan, "MTU", mtu != 0, mtu);

	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);
	svSetValueBoolean (netplan, "CONNECTED_MODE", nm_streq (transport_mode, "connected"));

	p_key = nm_setting_infiniband_get_p_key (s_infiniband);
	if (p_key != -1) {
		svSetValueStr (netplan, "PKEY", "yes");
		svSetValueInt64 (netplan, "PKEY_ID", p_key);

		parent = nm_setting_infiniband_get_parent (s_infiniband);
		if (parent)
			svSetValueStr (netplan, "PHYSDEV", parent);
	}

	svSetValueStr (netplan, "TYPE", TYPE_INFINIBAND);

	return TRUE;
}
#endif

static gboolean
write_wired_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingWired *s_wired;
	//const char *const*s390_subchannels;
	guint32 mtu; // i, num_opts;
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
	//svSetValueStr (netplan, "GENERATE_MAC_ADDRESS_MASK",
	//               nm_setting_wired_get_generate_mac_address_mask (s_wired));

#if 0  // TODO: No MAC match blacklist in netplan. Do we need one?
	macaddr_blacklist = nm_setting_wired_get_mac_address_blacklist (s_wired);
	if (macaddr_blacklist[0]) {
		gs_free char *blacklist_str = NULL;

		blacklist_str = g_strjoinv (" ", (char **) macaddr_blacklist);
		svSetValueStr (netplan, "HWADDR_BLACKLIST", blacklist_str);
	} else
		svUnsetValue (netplan, "HWADDR_BLACKLIST");
#endif

	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu != 0)
		g_output_stream_printf (netplan, 0, NULL, NULL,
				        "      mtu: %d\n", mtu);

#if 0 // TODO: implement s390 subchannels 
	s390_subchannels = nm_setting_wired_get_s390_subchannels (s_wired);

	{
		gs_free char *tmp = NULL;
		gsize len = NM_PTRARRAY_LEN (s390_subchannels);

		if (len == 2) {
			tmp = g_strdup_printf ("%s,%s",
			                       s390_subchannels[0],
			                       s390_subchannels[1]);
		} else if (len == 3) {
			tmp = g_strdup_printf ("%s,%s,%s",
			                       s390_subchannels[0],
			                       s390_subchannels[1],
			                       s390_subchannels[2]);
		}

		svSetValueStr (netplan, "SUBCHANNELS", tmp);
	}

	svSetValueStr (netplan, "NETTYPE",
	               nm_setting_wired_get_s390_nettype (s_wired));

	svSetValueStr (netplan, "PORTNAME",
	               nm_setting_wired_get_s390_option_by_key (s_wired, "portname"));

	svSetValueStr (netplan, "CTCPROT",
	               nm_setting_wired_get_s390_option_by_key (s_wired, "ctcprot"));

	svUnsetValue (netplan, "OPTIONS");
	num_opts = nm_setting_wired_get_num_s390_options (s_wired);
	if (s390_subchannels && num_opts) {
		nm_auto_free_gstring GString *tmp = NULL;

		for (i = 0; i < num_opts; i++) {
			const char *s390_key, *s390_val;

			nm_setting_wired_get_s390_option (s_wired, i, &s390_key, &s390_val);

			/* portname is handled separately */
			if (NM_IN_STRSET (s390_key, "portname", "ctcprot"))
				continue;

			if (strchr (s390_key, '=')) {
				/* this key cannot be expressed. But after all, it's not valid anyway
				 * and the connection shouldn't even verify. */
				continue;
			}

			if (!tmp)
				tmp = g_string_sized_new (30);
			else
				g_string_append_c (tmp, ' ');
			nm_utils_escaped_tokens_escape_gstr (s390_key, NM_ASCII_SPACES, tmp);
			g_string_append_c (tmp, '=');
			nm_utils_escaped_tokens_escape_gstr (s390_val, NM_ASCII_SPACES, tmp);
		}
		if (tmp)
			svSetValueStr (netplan, "OPTIONS", tmp->str);
	}
#endif

	return TRUE;
}

#if 0 // TODO: add support for ethtool settings in netplan
static gboolean
write_ethtool_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingWired *s_wired;
	NMSettingEthtool *s_ethtool;
	const char *duplex;
	guint32 speed;
	GString *str = NULL;
	gboolean auto_negotiate;
	NMSettingWiredWakeOnLan wol;
	const char *wol_password;

	s_wired = nm_connection_get_setting_wired (connection);
	s_ethtool = NM_SETTING_ETHTOOL (nm_connection_get_setting (connection, NM_TYPE_SETTING_ETHTOOL));

	if (!s_wired && !s_ethtool) {
		svUnsetValue (netplan, "ETHTOOL_WAKE_ON_LAN");
		svUnsetValue (netplan, "ETHTOOL_OPTS");
		return TRUE;
	}

	if (s_wired) {
		auto_negotiate = nm_setting_wired_get_auto_negotiate (s_wired);
		speed = nm_setting_wired_get_speed (s_wired);
		duplex = nm_setting_wired_get_duplex (s_wired);

		/* autoneg off + speed 0 + duplex NULL, means we want NM
		 * to skip link configuration which is default. So write
		 * down link config only if we have auto-negotiate true or
		 * a valid value for one among speed and duplex.
		 */
		if (auto_negotiate) {
			str = g_string_sized_new (64);
			g_string_printf (str, "autoneg on");
		} else if (speed || duplex) {
			str = g_string_sized_new (64);
			g_string_printf (str, "autoneg off");
		}
		if (speed)
			g_string_append_printf (str, " speed %u", speed);
		if (duplex)
			g_string_append_printf (str, " duplex %s", duplex);

		wol = nm_setting_wired_get_wake_on_lan (s_wired);
		wol_password = nm_setting_wired_get_wake_on_lan_password (s_wired);

		svSetValue (netplan, "ETHTOOL_WAKE_ON_LAN",
		              wol == NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE
		            ? "ignore"
		            : NULL);
		if (!NM_IN_SET (wol, NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE,
		                     NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT)) {
			if (!str)
				str = g_string_sized_new (30);
			else
				g_string_append (str, " ");

			g_string_append (str, "wol ");

			if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_PHY))
				g_string_append (str, "p");
			if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST))
				g_string_append (str, "u");
			if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST))
				g_string_append (str, "m");
			if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST))
				g_string_append (str, "b");
			if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_ARP))
				g_string_append (str, "a");
			if (NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
				g_string_append (str, "g");

			if (!NM_FLAGS_ANY (wol, NM_SETTING_WIRED_WAKE_ON_LAN_ALL))
				g_string_append (str, "d");

			if (wol_password && NM_FLAGS_HAS (wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC))
				g_string_append_printf (str, "s sopass %s", wol_password);
		}
	} else
		svUnsetValue (netplan, "ETHTOOL_WAKE_ON_LAN");

	if (s_ethtool) {
		NMEthtoolID ethtool_id;
		NMSettingConnection *s_con;
		const char *iface = NULL;

		s_con = nm_connection_get_setting_connection (connection);
		if (s_con) {
			iface = nm_setting_connection_get_interface_name (s_con);
			if (   iface
			    && (   !iface[0]
			        || !NM_STRCHAR_ALL (iface, ch,    (ch >= 'a' && ch <= 'z')
			                                       || (ch >= 'A' && ch <= 'Z')
			                                       || (ch >= '0' && ch <= '9')
			                                       || NM_IN_SET (ch, '_'))))
				iface = NULL;
		}

		if (!str)
			str = g_string_sized_new (30);
		else
			g_string_append (str, " ; ");
		g_string_append (str, "-K ");
		g_string_append (str, iface ?: "net0");

		for (ethtool_id = _NM_ETHTOOL_ID_FEATURE_FIRST; ethtool_id <= _NM_ETHTOOL_ID_FEATURE_LAST; ethtool_id++) {
			const NMEthtoolData *ed = nm_ethtool_data[ethtool_id];
			NMTernary val;

			nm_assert (nms_netplan_utils_get_ethtool_name (ethtool_id));

			val = nm_setting_ethtool_get_feature (s_ethtool, ed->optname);
			if (val == NM_TERNARY_DEFAULT)
				continue;

			g_string_append_c (str, ' ');
			g_string_append (str, nms_netplan_utils_get_ethtool_name (ethtool_id));
			g_string_append (str, val == NM_TERNARY_TRUE ? " on" : " off");
		}
	}

	if (str) {
		svSetValueStr (netplan, "ETHTOOL_OPTS", str->str);
		g_string_free (str, TRUE);
	} else
		svUnsetValue (netplan, "ETHTOOL_OPTS");

	return TRUE;
}
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
	vlan_flags = nm_setting_vlan_get_flags (s_vlan);
	svSetValueBoolean (netplan, "REORDER_HDR", NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS));
	svSetValueBoolean (netplan, "GVRP", NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_GVRP));

	nm_utils_strbuf_init (s_buf, &s_buf_ptr, &s_buf_len);

	if (NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_LOOSE_BINDING))
		nm_utils_strbuf_append_str (&s_buf_ptr, &s_buf_len, "LOOSE_BINDING");
	if (!NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_REORDER_HEADERS))
		nm_utils_strbuf_append (&s_buf_ptr, &s_buf_len, "%sNO_REORDER_HDR", s_buf[0] ? "," : "");

	svSetValueStr (netplan, "VLAN_FLAGS", s_buf);

	svSetValueBoolean (netplan, "MVRP", NM_FLAGS_HAS (vlan_flags, NM_VLAN_FLAG_MVRP));

	tmp = vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_INGRESS_MAP);
	svSetValueStr (netplan, "VLAN_INGRESS_PRIORITY_MAP", tmp);
	g_free (tmp);

	tmp = vlan_priority_maplist_to_stringlist (s_vlan, NM_VLAN_EGRESS_MAP);
	svSetValueStr (netplan, "VLAN_EGRESS_PRIORITY_MAP", tmp);
	g_free (tmp);
#endif

	return TRUE;
}

static const struct {
	const char *option;
	const char *netplan_name;
} bond_options_mapping[] = {
	{ NM_SETTING_BOND_OPTION_MIIMON, "mii-monitor-interval" },
	{ NM_SETTING_BOND_OPTION_UPDELAY, "up-delay" },
	{ NM_SETTING_BOND_OPTION_DOWNDELAY, "down-delay" },
	{ NM_SETTING_BOND_OPTION_ARP_INTERVAL, "arp-interval" },
	{ NM_SETTING_BOND_OPTION_ARP_IP_TARGET, "arp-ip-targets" },
	{ NM_SETTING_BOND_OPTION_ARP_VALIDATE, "arp-validate" },
	{ NM_SETTING_BOND_OPTION_PRIMARY, "primary-slave" },
	{ NM_SETTING_BOND_OPTION_PRIMARY_RESELECT, "primary-reselect-policy" },
	{ NM_SETTING_BOND_OPTION_FAIL_OVER_MAC, "fail-over-mac-policy" },
//#define NM_SETTING_BOND_OPTION_USE_CARRIER       "use_carrier"
	{ NM_SETTING_BOND_OPTION_AD_SELECT, "ad-select" },
	{ NM_SETTING_BOND_OPTION_XMIT_HASH_POLICY, "transmit-hash-policy" },
	{ NM_SETTING_BOND_OPTION_RESEND_IGMP, "resend-igmp" },
	{ NM_SETTING_BOND_OPTION_LACP_RATE, "lacp-rate" },
	{ NM_SETTING_BOND_OPTION_ALL_SLAVES_ACTIVE, "all-slaves-active" },
	{ NM_SETTING_BOND_OPTION_ARP_ALL_TARGETS, "arp-all-targets" },
	{ NM_SETTING_BOND_OPTION_MIN_LINKS, "min-links" },
	{ NM_SETTING_BOND_OPTION_NUM_GRAT_ARP, "gratuitous-arp" },
//#define NM_SETTING_BOND_OPTION_NUM_UNSOL_NA      "num_unsol_na"
	{ NM_SETTING_BOND_OPTION_PACKETS_PER_SLAVE, "packets-per-slave" },
//#define NM_SETTING_BOND_OPTION_TLB_DYNAMIC_LB    "tlb_dynamic_lb"
	{ NM_SETTING_BOND_OPTION_LP_INTERVAL, "learn-packet-interval" },
};

static void
_match_bond_option_to_netplan (GString *bond_options, const char *option, const char *value)
{
	guint i;
	const char *name = option;

	for (i = 0; i < G_N_ELEMENTS (bond_options_mapping); i++) {
		if (nm_streq (option, bond_options_mapping[i].option))
			name = bond_options_mapping[i].netplan_name;
	}

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
{
	NMSettingTeam *s_team;
	const char *config;

	s_team = nm_connection_get_setting_team (connection);
	if (!s_team) {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Missing '%s' setting", NM_SETTING_TEAM_SETTING_NAME);
		return FALSE;
	}

	config = nm_setting_team_get_config (s_team);
	svSetValueStr (netplan, "TEAM_CONFIG", config);

	*wired = write_wired_for_virtual (connection, netplan);

	return TRUE;
}
#endif

static guint32
get_setting_default_uint (NMSetting *setting, const char *prop)
{
	GParamSpec *pspec;
	GValue val = G_VALUE_INIT;
	guint32 ret = 0;

	pspec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), prop);
	g_assert (pspec);
	g_value_init (&val, pspec->value_type);
	g_param_value_set_default (pspec, &val);
	g_assert (G_VALUE_HOLDS_UINT (&val));
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
	g_assert (pspec);
	g_value_init (&val, pspec->value_type);
	g_param_value_set_default (pspec, &val);
	g_assert (G_VALUE_HOLDS_BOOLEAN (&val));
	ret = g_value_get_boolean (&val);
	g_value_unset (&val);
	return ret;
}
#endif

static gboolean
write_bridge_vlans (NMSetting *setting,
                    const char *property_name,
                    GOutputStream *netplan,
                    const char *key,
                    GError **error)
{
#if 0 // TODO: Implement bridge VLANs printif settings.
	gs_unref_ptrarray GPtrArray *vlans = NULL;
	NMBridgeVlan *vlan;
	GString *string;
	guint i;

	g_object_get (setting, property_name, &vlans, NULL);

	if (!vlans || !vlans->len) {
		svUnsetValue (netplan, key);
		return TRUE;
	}

	string = g_string_new ("");
	for (i = 0; i < vlans->len; i++) {
		gs_free char *vlan_str = NULL;

		vlan = vlans->pdata[i];
		vlan_str = nm_bridge_vlan_to_str (vlan, error);
		if (!vlan_str)
			return FALSE;
		if (string->len > 0)
			g_string_append (string, ",");
		nm_utils_escaped_tokens_escape_gstr_assert (vlan_str, ",", string);
	}

	svSetValueStr (netplan, key, string->str);
	g_string_free (string, TRUE);
#endif

	return TRUE;
}

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
	// TODO: Probably needs reorg in netplan to support in member device bond/bridge params.
	NMSettingBridgePort *s_port;
	guint32 i;
	GString *string;

	s_port = nm_connection_get_setting_bridge_port (connection);
	if (!s_port)
		return TRUE;

	/* Bridge options */
	string = g_string_sized_new (32);

	i = nm_setting_bridge_port_get_priority (s_port);
	if (i != get_setting_default_uint (NM_SETTING (s_port), NM_SETTING_BRIDGE_PORT_PRIORITY))
		g_string_append_printf (string, "        priority: %u", i);

	i = nm_setting_bridge_port_get_path_cost (s_port);
	if (i != get_setting_default_uint (NM_SETTING (s_port), NM_SETTING_BRIDGE_PORT_PATH_COST)) {
		if (string->len)
			g_string_append_c (string, ' ');
		g_string_append_printf (string, "        path-cost: %u", i);
	}

#if 0 // TODO: need hairpin mode support in networkd/netplan
	if (nm_setting_bridge_port_get_hairpin_mode (s_port)) {
		if (string->len)
			g_string_append_c (string, ' ');
		g_string_append_printf (string, "hairpin_mode=1");
	}
#endif

	if (string->len)
		g_output_stream_printf (netplan, 0, NULL, NULL,
				        "      parameters:\n%s", string->str);
	g_string_free (string, TRUE);

	if (!write_bridge_vlans ((NMSetting *) s_port,
	                         NM_SETTING_BRIDGE_PORT_VLANS,
	                         netplan,
	                         "BRIDGE_PORT_VLANS",
	                         error))
		return FALSE;

	return TRUE;
}

#if 0 // TODO: implement Team port settings.
static gboolean
write_team_port_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingTeamPort *s_port;
	const char *config;

	s_port = nm_connection_get_setting_team_port (connection);
	if (!s_port)
		return TRUE;

	config = nm_setting_team_port_get_config (s_port);
	svSetValueStr (netplan, "TEAM_PORT_CONFIG", config);

	return TRUE;
}
#endif

#if 0 // TODO: Implement DCB.
static gboolean
write_dcb_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingDcb *s_dcb;
	NMSettingDcbFlags flags;

	s_dcb = nm_connection_get_setting_dcb (connection);
	if (!s_dcb) {
		static const char *clear_keys[] = {
		    "DCB",
		    KEY_DCB_APP_FCOE_ENABLE,
		    KEY_DCB_APP_FCOE_ADVERTISE,
		    KEY_DCB_APP_FCOE_WILLING,
		    KEY_DCB_APP_FCOE_MODE,
		    KEY_DCB_APP_ISCSI_ENABLE,
		    KEY_DCB_APP_ISCSI_ADVERTISE,
		    KEY_DCB_APP_ISCSI_WILLING,
		    KEY_DCB_APP_FIP_ENABLE,
		    KEY_DCB_APP_FIP_ADVERTISE,
		    KEY_DCB_APP_FIP_WILLING,
		    KEY_DCB_PFC_ENABLE,
		    KEY_DCB_PFC_ADVERTISE,
		    KEY_DCB_PFC_WILLING,
		    KEY_DCB_PFC_UP,
		    KEY_DCB_PG_ENABLE,
		    KEY_DCB_PG_ADVERTISE,
		    KEY_DCB_PG_WILLING,
		    KEY_DCB_PG_ID,
		    KEY_DCB_PG_PCT,
		    KEY_DCB_PG_UPPCT,
		    KEY_DCB_PG_STRICT,
		    KEY_DCB_PG_UP2TC,
		    NULL };
		const char **iter;

		for (iter = clear_keys; *iter; iter++)
			svUnsetValue (netplan, *iter);
		return TRUE;
	}

	svSetValueStr (netplan, "DCB", "yes");

	write_dcb_app (netplan, "APP_FCOE",
	               nm_setting_dcb_get_app_fcoe_flags (s_dcb),
	               nm_setting_dcb_get_app_fcoe_priority (s_dcb));
	if (nm_setting_dcb_get_app_fcoe_flags (s_dcb) & NM_SETTING_DCB_FLAG_ENABLE)
		svSetValueStr (netplan, KEY_DCB_APP_FCOE_MODE, nm_setting_dcb_get_app_fcoe_mode (s_dcb));
	else
		svUnsetValue (netplan, KEY_DCB_APP_FCOE_MODE);

	write_dcb_app (netplan, "APP_ISCSI",
	               nm_setting_dcb_get_app_iscsi_flags (s_dcb),
	               nm_setting_dcb_get_app_iscsi_priority (s_dcb));
	write_dcb_app (netplan, "APP_FIP",
	               nm_setting_dcb_get_app_fip_flags (s_dcb),
	               nm_setting_dcb_get_app_fip_priority (s_dcb));

	write_dcb_flags (netplan, "PFC", nm_setting_dcb_get_priority_flow_control_flags (s_dcb));
	write_dcb_bool_array (netplan, KEY_DCB_PFC_UP, s_dcb,
	                      nm_setting_dcb_get_priority_flow_control_flags (s_dcb),
	                      nm_setting_dcb_get_priority_flow_control);

	flags = nm_setting_dcb_get_priority_group_flags (s_dcb);
	write_dcb_flags (netplan, "PG", flags);
	write_dcb_uint_array (netplan, KEY_DCB_PG_ID, s_dcb, flags, nm_setting_dcb_get_priority_group_id);
	write_dcb_percent_array (netplan, KEY_DCB_PG_PCT, s_dcb, flags, nm_setting_dcb_get_priority_group_bandwidth);
	write_dcb_percent_array (netplan, KEY_DCB_PG_UPPCT, s_dcb, flags, nm_setting_dcb_get_priority_bandwidth);
	write_dcb_bool_array (netplan, KEY_DCB_PG_STRICT, s_dcb, flags, nm_setting_dcb_get_priority_strict_bandwidth);
	write_dcb_uint_array (netplan, KEY_DCB_PG_UP2TC, s_dcb, flags, nm_setting_dcb_get_priority_traffic_class);

	return TRUE;
}
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
	//const char *tmp;

	g_output_stream_printf (netplan, 0, NULL, NULL, "      networkmanager:\n");
	g_output_stream_printf (netplan, 0, NULL, NULL,
			        "        name: %s\n", nm_setting_connection_get_id(s_con));
	g_output_stream_printf (netplan, 0, NULL, NULL,
			        "        uuid: %s\n", nm_setting_connection_get_uuid (s_con));
	g_output_stream_printf (netplan, 0, NULL, NULL,
			        "        stable-id: %s\n", nm_setting_connection_get_stable_id (s_con));
	
	
	// TODO: MOVE to header to identify the device / connection it is under
	g_output_stream_printf (netplan, 0, NULL, NULL,
			        "        device: %s\n", nm_setting_connection_get_interface_name (s_con));

	// TODO: hook up autoconnect ???
	//g_output_stream_printf (netplan, "ONBOOT", nm_setting_connection_get_autoconnect (s_con));

#if 0
	vint = nm_setting_connection_get_autoconnect_priority (s_con);
	g_hash_table_insert (netplan, "AUTOCONNECT_PRIORITY",
	                      vint != NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT ?
	                      vint : NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT);

	vint = nm_setting_connection_get_autoconnect_retries (s_con);
	g_hash_table_insert (netplan, "AUTOCONNECT_RETRIES",
	                      vint != -1 ?
	                      vint: -1);

	vint = nm_setting_connection_get_multi_connect (s_con);
	g_hash_table_insert (netplan, "MULTI_CONNECT",
	                      vint != NM_CONNECTION_MULTI_CONNECT_DEFAULT ?
	                      vint: NM_CONNECTION_MULTI_CONNECT_DEFAULT);

	/* Only save the value for master connections */
	type = nm_setting_connection_get_connection_type (s_con);
	if (_nm_connection_type_is_master (type)) {
		NMSettingConnectionAutoconnectSlaves autoconnect_slaves;
		autoconnect_slaves = nm_setting_connection_get_autoconnect_slaves (s_con);
		g_hash_table_insert (netplan, "AUTOCONNECT_SLAVES",
		               autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES ? "yes" :
		               autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO ? "no" : NULL);
	}

	switch (nm_setting_connection_get_lldp (s_con)) {
	case NM_SETTING_CONNECTION_LLDP_ENABLE_RX:
		tmp = "rx";
		break;
	case NM_SETTING_CONNECTION_LLDP_DISABLE:
		tmp = "no";
		break;
	default:
		tmp = NULL;
	}
	g_hash_table_insert (netplan, "LLDP", tmp);
#endif

#if 0 // TODO: handle user permissions for connections
	/* Permissions */
	g_hash_table_insert (netplan, "USERS");
	n = nm_setting_connection_get_num_permissions (s_con);
	if (n > 0) {
		str = g_string_sized_new (n * 20);

		for (i = 0; i < n; i++) {
			const char *puser = NULL;

			/* Items separated by space for consistency with eg
			 * IPV6ADDR_SECONDARIES and DOMAIN.
			 */
			if (str->len)
				g_string_append_c (str, ' ');

			if (nm_setting_connection_get_permission (s_con, i, NULL, &puser, NULL))
				g_string_append (str, puser);
		}
		g_hash_table_insert (netplan, "USERS", str->str);
		g_string_free (str, TRUE);
	}

	g_hash_table_insert (netplan, "ZONE", nm_setting_connection_get_zone (s_con));
#endif

#if 0
	master = nm_setting_connection_get_master (s_con);
	if (master) {
		/* The reader prefers the *_UUID variants, however we still try to resolve
		 * it into an interface name, so that legacy tooling is not confused. */
		if (!nm_utils_get_testing ()) {
			/* This is conditional for easier testing. */
			master_iface = nm_manager_iface_for_uuid (nm_manager_get (), master);
		}
		if (!master_iface) {
			master_iface = master;
			master = NULL;

		}

		if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BOND_SETTING_NAME)) {
			g_hash_table_insert (netplan, "MASTER_UUID", master);
			g_hash_table_insert (netplan, "MASTER", master_iface);
			g_hash_table_insert (netplan, "SLAVE", "yes");
		} else if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_BRIDGE_SETTING_NAME)) {
			g_hash_table_insert (netplan, "BRIDGE_UUID", master);
			g_hash_table_insert (netplan, "BRIDGE", master_iface);
		} else if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_TEAM_SETTING_NAME)) {
			g_hash_table_insert (netplan, "TEAM_MASTER_UUID", master);
			g_hash_table_insert (netplan, "TEAM_MASTER", master_iface);
		} else if (nm_setting_connection_is_slave_type (s_con, NM_SETTING_OVS_PORT_SETTING_NAME)) {
			g_hash_table_insert (netplan, "OVS_PORT_UUID", master);
			g_hash_table_insert (netplan, "OVS_PORT", master_iface);
		} else {
			_LOGW ("don't know how to set master for a %s slave",
			       nm_setting_connection_get_slave_type (s_con));
		}
	}
#endif

#if 0 // TODO: use devicetype code for bridgeport detection
	if (nm_streq0 (type, NM_SETTING_TEAM_SETTING_NAME))
		g_hash_table_insert (netplan, "DEVICETYPE", TYPE_TEAM);
	else if (master_iface && nm_setting_connection_is_slave_type (s_con, NM_SETTING_TEAM_SETTING_NAME))
		g_hash_table_insert (netplan, "DEVICETYPE", TYPE_TEAM_PORT);
#endif

#if 0
	/* secondary connection UUIDs */
	n = nm_setting_connection_get_num_secondaries (s_con);
	if (n > 0) {
		str = g_string_sized_new (n * 37);

		for (i = 0; i < n; i++) {
			const char *uuid;

			/* Items separated by space for consistency with eg
			 * IPV6ADDR_SECONDARIES and DOMAIN.
			 */
			if (str->len)
				g_string_append_c (str, ' ');

			if ((uuid = nm_setting_connection_get_secondary (s_con, i)) != NULL)
				g_string_append (str, uuid);
		}
		g_hash_table_insert (netplan, "SECONDARY_UUIDS", str->str);
		g_string_free (str, TRUE);
	}

	vuint32 = nm_setting_connection_get_gateway_ping_timeout (s_con);
	if (vuint32 != 0)
		g_hash_table_insert (netplan, "GATEWAY_PING_TIMEOUT", vuint32);

	switch (nm_setting_connection_get_metered (s_con)) {
	case NM_METERED_YES:
		g_hash_table_insert (netplan, "CONNECTION_METERED", "yes");
		break;
	case NM_METERED_NO:
		g_hash_table_insert (netplan, "CONNECTION_METERED", "no");
		break;
	default:
		break;
	}

	vint = nm_setting_connection_get_auth_retries (s_con);
	if (vint >= 0)
		g_hash_table_insert (netplan, "AUTH_RETRIES", vint);

	vint32 = nm_setting_connection_get_wait_device_timeout (s_con);
	if (vint32 == -1)
		// Do nothing
	else if ((vint32 % 1000) == 0)
		g_hash_table_insert (netplan, "DEVTIMEOUT", vint32 / 1000);
	else {
		char b[100];

		g_hash_table_insert (netplan,
		                     "DEVTIMEOUT",
		                     nm_sprintf_buf (b, "%.3f", ((double) vint) / 1000.0));
	}
#endif

#if 0
	mdns = nm_setting_connection_get_mdns (s_con);
	if (mdns != NM_SETTING_CONNECTION_MDNS_DEFAULT) {
		g_hash_table_insert (netplan, "MDNS", //nm_setting_connection_mdns_get_type (),
		                     mdns);
	}

	llmnr = nm_setting_connection_get_llmnr (s_con);
	if (llmnr != NM_SETTING_CONNECTION_LLMNR_DEFAULT) {
		g_output_stream_printf (netplan, "LLMNR", //nm_setting_connection_llmnr_get_type (),
		                        llmnr);
	}
#endif
}

#if 0 /* goes with routes!!! */
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
#endif

#if 0 /* temp disable : routes: */
static GString *
write_route_settings (NMSettingIPConfig *s_ip)
{
	GString *contents;
	NMIPRoute *route;
	guint32 i, num;
	int addr_family;

	addr_family = nm_setting_ip_config_get_addr_family (s_ip);

	num = nm_setting_ip_config_get_num_routes (s_ip);
	if (num == 0)
		return NULL;

	contents = g_string_new ("");

	for (i = 0; i < num; i++) {
		gs_free char *options = NULL;
		const char *next_hop;
		gint64 metric;

		route = nm_setting_ip_config_get_route (s_ip, i);
		next_hop = nm_ip_route_get_next_hop (route);
		metric = nm_ip_route_get_metric (route);
		options = get_route_attributes_string (route, addr_family);

		g_string_append_printf (contents, "      - to: %s/%u\n",
		                        nm_ip_route_get_dest (route),
		                        nm_ip_route_get_prefix (route));
		if (next_hop)
			g_string_append_printf (contents, "        via: %s\n", next_hop);
		if (metric >= 0)
			g_string_append_printf (contents, "        metric: %u\n", (guint) metric);
#if 0  // TODO: implementing route options
		if (options) {
			g_string_append_c (contents, ' ');
			g_string_append (contents, options);
		}
#endif
	}

	return contents;
}
#endif

#if 0  // TODO: implement proxy support.
static gboolean
write_proxy_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
	NMSettingProxy *s_proxy;
	NMSettingProxyMethod method;
	const char *pac_url, *pac_script;

	s_proxy = nm_connection_get_setting_proxy (connection);
	if (!s_proxy)
		return TRUE;

	svUnsetValue (netplan, "BROWSER_ONLY");
	svUnsetValue (netplan, "PAC_URL");
	svUnsetValue (netplan, "PAC_SCRIPT");

	method = nm_setting_proxy_get_method (s_proxy);
	switch (method) {
	case NM_SETTING_PROXY_METHOD_AUTO:
		svSetValueStr (netplan, "PROXY_METHOD", "auto");

		pac_url = nm_setting_proxy_get_pac_url (s_proxy);
		if (pac_url)
			svSetValueStr (netplan, "PAC_URL", pac_url);

		pac_script = nm_setting_proxy_get_pac_script (s_proxy);
		if (pac_script)
			svSetValueStr (netplan, "PAC_SCRIPT", pac_script);

		break;
	case NM_SETTING_PROXY_METHOD_NONE:
		svSetValueStr (netplan, "PROXY_METHOD", "none");
		break;
	}

	svSetValueBoolean (netplan, "BROWSER_ONLY", nm_setting_proxy_get_browser_only (s_proxy));
	return TRUE;
}
#endif

static gboolean
write_user_setting (NMConnection *connection, GOutputStream *netplan, GError **error)
{
#if 0  // TODO: implement user permission settings
	NMSettingUser *s_user;
	guint i, len;
	const char *const*keys;

	s_user = NM_SETTING_USER (nm_connection_get_setting (connection, NM_TYPE_SETTING_USER));

	svUnsetAll (netplan, SV_KEY_TYPE_USER);

	if (!s_user)
		return TRUE;

	keys = nm_setting_user_get_keys (s_user, &len);
	if (len) {
		nm_auto_free_gstring GString *str = g_string_sized_new (100);

		for (i = 0; i < len; i++) {
			const char *key = keys[i];

			g_string_set_size (str, 0);
			g_string_append (str, "NM_USER_");
			nms_netplan_utils_user_key_encode (key, str);
			svSetValue (netplan,
			            str->str,
			            nm_setting_user_get_data (s_user, key));
		}
	}
#endif
	return TRUE;
}

#if 0  // TODO: implement SR-IOV settings
static void
write_sriov_setting (NMConnection *connection, GHashTable *netplan)
{
	NMSettingSriov *s_sriov;
	guint i, num = 0;
	NMTernary b;
	NMSriovVF *vf;
	char key[32];
	char *str;

	svUnsetAll (netplan, SV_KEY_TYPE_SRIOV_VF);

	s_sriov = NM_SETTING_SRIOV (nm_connection_get_setting (connection,
	                                                       NM_TYPE_SETTING_SRIOV));
	svSetValueInt64 (netplan, "SRIOV_TOTAL_VFS", nm_setting_sriov_get_total_vfs (s_sriov));

	b = nm_setting_sriov_get_autoprobe_drivers (s_sriov);
	if (b != NM_TERNARY_DEFAULT)
		svSetValueInt64 (netplan, "SRIOV_AUTOPROBE_DRIVERS", b);
	else
		svUnsetValue (netplan, "SRIOV_AUTOPROBE_DRIVERS");

	num = nm_setting_sriov_get_num_vfs (s_sriov);
	for (i = 0; i < num; i++) {
		vf = nm_setting_sriov_get_vf (s_sriov, i);
		nm_sprintf_buf (key, "SRIOV_VF%u", nm_sriov_vf_get_index (vf));
		str = nm_utils_sriov_vf_to_str (vf, TRUE, NULL);
		svSetValueStr (netplan, key, str);
		g_free (str);
	}
}
#endif

#if 0 // TODO: implement TC settings for netplan
static gboolean
write_tc_setting (NMConnection *connection, GHashTable *netplan, GError **error)
{
	NMSettingTCConfig *s_tc;
	guint i, num, n;
	char tag[64];

	svUnsetAll (netplan, SV_KEY_TYPE_TC);

	s_tc = nm_connection_get_setting_tc_config (connection);
	if (!s_tc)
		return TRUE;

	num = nm_setting_tc_config_get_num_qdiscs (s_tc);
	for (n = 1, i = 0; i < num; i++) {
		NMTCQdisc *qdisc;
		gs_free char *str = NULL;

		qdisc = nm_setting_tc_config_get_qdisc (s_tc, i);
		str = nm_utils_tc_qdisc_to_str (qdisc, error);
		if (!str)
			return FALSE;

		svSetValueStr (netplan, numbered_tag (tag, "QDISC", n), str);
		n++;
	}

	num = nm_setting_tc_config_get_num_tfilters (s_tc);
	for (n = 1, i = 0; i < num; i++) {
		NMTCTfilter *tfilter;
		gs_free char *str = NULL;

		tfilter = nm_setting_tc_config_get_tfilter (s_tc, i);
		str = nm_utils_tc_tfilter_to_str (tfilter, error);
		if (!str)
			return FALSE;

		svSetValueStr (netplan, numbered_tag (tag, "FILTER", n), str);
		n++;
	}
	return TRUE;
}
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
{
	nm_auto_free_gstring GString *value = NULL;
	guint i, num_options;

	value = g_string_new (NULL);
	num_options = nm_setting_ip_config_get_num_dns_options (s_ip);
	for (i = 0; i < num_options; i++) {
		if (i > 0)
			g_string_append_c (value, ' ');
		g_string_append (value, nm_setting_ip_config_get_dns_option (s_ip, i));
	}

	svSetValue (netplan, var, value->str);
}
#endif

static gboolean
write_ip4_setting (NMConnection *connection,
                   GOutputStream *netplan,
		   GArray *addresses,
		   GArray *nameservers,
		   GArray *searches,
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
	method = nm_setting_ip_config_get_method (s_ip4);

	/* Missing IP4 setting is assumed to be DHCP */
	if (!method)
		method = NM_SETTING_IP4_CONFIG_METHOD_AUTO;

	num = nm_setting_ip_config_get_num_addresses (s_ip4);

	if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO))
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      dhcp4: yes\n");
#if 0  /* TODO: implement setting statically assigned IPs: append to GArray for addresses */
	else if (!strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		// Static addresses addressed below.
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

#if 0  /* TODO: improve routes handling */
		routes = g_array_new(...)
	    // Routes -> split up into routes section
	    // routes = g_array_new (...)
	    // ...
	    // g_hash_table_insert (netplan, "routes", <routes>)
	    // 
		g_hash_table_insert (route,
		                     "to",
		                     nm_ip_address_get_address (addr));
#endif

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
	if (num > 0) {
		for (i = 0; i < num; i++) {
			const char *search;

			search = nm_setting_ip_config_get_dns_search (s_ip4, i);
			g_array_append_val (searches, search);
		}
	}

#if 0  // TODO: default-route toggles and peer, dhcp settings.
	/* DEFROUTE; remember that it has the opposite meaning from never-default */
	svSetValueBoolean (netplan, "DEFROUTE", !nm_setting_ip_config_get_never_default (s_ip4));

	/* Missing PEERDNS means TRUE, so write it only when is FALSE */
	svSetValueStr (netplan, "PEERDNS",
	               nm_setting_ip_config_get_ignore_auto_dns (s_ip4) ? "no" : NULL);
	/* Missing PEERROUTES means TRUE, so write it only when is FALSE */
	svSetValueStr (netplan, "PEERROUTES",
	               nm_setting_ip_config_get_ignore_auto_routes (s_ip4) ? "no" : NULL);

	value = nm_setting_ip_config_get_dhcp_hostname (s_ip4);
	svSetValueStr (netplan, "DHCP_HOSTNAME", value);

	value = nm_setting_ip4_config_get_dhcp_fqdn (NM_SETTING_IP4_CONFIG (s_ip4));
	svSetValueStr (netplan, "DHCP_FQDN", value);

	/* Missing DHCP_SEND_HOSTNAME means TRUE, and we prefer not write it explicitly
	 * in that case, because it is NM-specific variable
	 */
	svSetValueStr (netplan, "DHCP_SEND_HOSTNAME",
	               nm_setting_ip_config_get_dhcp_send_hostname (s_ip4) ? NULL : "no");

	value = nm_setting_ip4_config_get_dhcp_client_id (NM_SETTING_IP4_CONFIG (s_ip4));
	svSetValueStr (netplan, "DHCP_CLIENT_ID", value);

	timeout = nm_setting_ip_config_get_dhcp_timeout (s_ip4);
	svSetValueInt64_cond (netplan,
	                      "IPV4_DHCP_TIMEOUT",
	                      timeout != 0,
	                      timeout);
#endif

#if 0  // TODO: Implement route settings here for ipv4
	svSetValueBoolean (netplan, "IPV4_FAILURE_FATAL", !nm_setting_ip_config_get_may_fail (s_ip4));

	route_metric = nm_setting_ip_config_get_route_metric (s_ip4);
	svSetValueInt64_cond (netplan,
	                      "IPV4_ROUTE_METRIC",
	                      route_metric != -1,
	                      route_metric);

	route_table = nm_setting_ip_config_get_route_table (s_ip4);
	svSetValueInt64_cond (netplan,
	                      "IPV4_ROUTE_TABLE",
	                      route_table != 0,
	                      route_table);

	//NM_SET_OUT (out_route_content_svformat, write_route_file_svformat (svFileGetName (netplan), s_ip4));
	NM_SET_OUT (out_route_content, write_route_settings (s_ip4));

	timeout = nm_setting_ip_config_get_dad_timeout (s_ip4);
	if (timeout < 0) {
		svUnsetValue (netplan, "ACD_TIMEOUT");
		svUnsetValue (netplan, "ARPING_WAIT");
	} else if (timeout == 0) {
		svSetValueStr (netplan, "ACD_TIMEOUT", "0");
		svSetValueStr (netplan, "ARPING_WAIT", "0");
	} else {
		svSetValueInt64 (netplan, "ACD_TIMEOUT", timeout);
		/* Round the value up to next integer for initscripts */
		svSetValueInt64 (netplan, "ARPING_WAIT", (timeout - 1) / 1000 + 1);
	}

	priority = nm_setting_ip_config_get_dns_priority (s_ip4);
	if (priority)
		svSetValueInt64 (netplan, "IPV4_DNS_PRIORITY", priority);
	else
		svUnsetValue (netplan, "IPV4_DNS_PRIORITY");

	write_res_options (netplan, s_ip4, "RES_OPTIONS");
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
	g_hash_table_insert (dhcp_overrides, "use-hostname", g_strdup(hostname));

	if (!nm_setting_ip_config_get_dhcp_send_hostname (s_ip6))
		g_hash_table_insert (dhcp_overrides, "send-hostname", g_strdup("no"));
}

static gboolean
write_ip6_setting (NMConnection *connection,
                   GOutputStream *netplan,
		   GArray *addresses,
		   GArray *nameservers,
		   GArray *searches,
		   GHashTable *dhcp_overrides,
                   GError **error)
{
	NMSettingIPConfig *s_ip6;
	const char *value;
	guint i, num; //, num4;
	//int priority;
	NMIPAddress *addr;
	const char *dns;
	//gint64 route_metric;
	//NMIPRouteTableSyncMode route_table;
	GString *ip_str;
	//NMSettingIP6ConfigAddrGenMode addr_gen_mode;

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (!s_ip6) {
		return TRUE;
	}

	value = nm_setting_ip_config_get_method (s_ip6);
	g_assert (value);
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

	// TODO: implement DUID selection in netplan
	//svSetValueStr (netplan, "DHCPV6_DUID",
	//               nm_setting_ip6_config_get_dhcp_duid (NM_SETTING_IP6_CONFIG (s_ip6)));

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
	if (num > 0) {
		for (i = 0; i < num; i++) {
			value = nm_setting_ip_config_get_dns_search (s_ip6, i);
			g_array_append_val (searches, value);
		}
	}

	/* handle IPV6_DEFROUTE */
	/* IPV6_DEFROUTE has the opposite meaning from 'never-default' */
	if (nm_setting_ip_config_get_never_default (s_ip6)) {
		g_output_stream_printf(netplan, 0, NULL, NULL, "      dhcp6-overrides:\n");
		g_output_stream_printf(netplan, 0, NULL, NULL, "        use-routes: no\n");
	}

	// TODO: more about "optional" (see above)
	//svSetValueStr (netplan, "IPV6_FAILURE_FATAL",
	//               nm_setting_ip_config_get_may_fail (s_ip6) ? "no" : "yes");

#if 0  /* TODO: Implement proper writing of the metric value to netplan YAML */
	route_metric = nm_setting_ip_config_get_route_metric (s_ip6);
	if (route_metric != -1)
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "      metric: %ld\n", route_metric);
#endif

#if 0
    // TODO: Implement this route as a formal route (rather than gatewayN) to set route table
    // TODO: Implement RouteTable= (networkd)  for DHCP.

	route_table = nm_setting_ip_config_get_route_table (s_ip6);
	svSetValueInt64_cond (netplan,
	                      "IPV6_ROUTE_TABLE",
	                      route_table != 0,
	                      route_table);
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

#if 0
    // TODO: Support address generation and interface identified. (not in netplan yet)
	/* IPv6 Address generation mode */
	addr_gen_mode = nm_setting_ip6_config_get_addr_gen_mode (NM_SETTING_IP6_CONFIG (s_ip6));
	if (addr_gen_mode != NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64) {
		svSetValueEnum (netplan, "IPV6_ADDR_GEN_MODE", nm_setting_ip6_config_addr_gen_mode_get_type (),
		                addr_gen_mode);
	} else {
		svUnsetValue (netplan, "IPV6_ADDR_GEN_MODE");
	}

	/* IPv6 tokenized interface identifier */
	value = nm_setting_ip6_config_get_token (NM_SETTING_IP6_CONFIG (s_ip6));
	svSetValueStr (netplan, "IPV6_TOKEN", value);
#endif

    // TODO: Implement priority for connections (probably NM-specific)
#if 0
	priority = nm_setting_ip_config_get_dns_priority (s_ip6);
	if (priority)
		svSetValueInt64 (netplan, "IPV6_DNS_PRIORITY", priority);
	else
		svUnsetValue (netplan, "IPV6_DNS_PRIORITY");

	write_res_options (netplan, s_ip6, "IPV6_RES_OPTIONS");
#endif

	return TRUE;
}

static void
write_ip_routing_rules (NMConnection *connection,
                        GOutputStream *netplan)
{
	//gsize idx = 0;
	int is_ipv4;
	GString *routing_policy;

	routing_policy = g_string_sized_new (200);

	for (is_ipv4 = 1; is_ipv4 >= 0; is_ipv4--) {
		const int addr_family = is_ipv4 ? AF_INET : AF_INET6;
		NMSettingIPConfig *s_ip;
		guint i, num;

		s_ip = nm_connection_get_setting_ip_config (connection, addr_family);
		if (!s_ip)
			continue;

		num = nm_setting_ip_config_get_num_routing_rules (s_ip);
		for (i = 0; i < num; i++) {
			NMIPRoutingRule *rule = nm_setting_ip_config_get_routing_rule (s_ip, i);
			gs_free const char *s = NULL;
			//char key[64];

			g_string_append_printf(routing_policy, "        - to: %s\n",
			                       nm_ip_routing_rule_get_to(rule));
			g_string_append_printf(routing_policy, "          from: %s\n",
			                       nm_ip_routing_rule_get_from(rule));
			g_string_append_printf(routing_policy, "          table: %d\n",
			                       nm_ip_routing_rule_get_table(rule));
			g_string_append_printf(routing_policy, "          mark: %d\n",
			                       nm_ip_routing_rule_get_fwmark(rule));
			g_string_append_printf(routing_policy, "          type-of-service: %d\n",
			                       nm_ip_routing_rule_get_tos(rule));
			g_string_append_printf(routing_policy, "          priority: %ld\n",
			                       nm_ip_routing_rule_get_priority(rule));
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
	const gchar *type = NULL;
	GArray *addresses, *nameservers, *searches;
	GHashTable *dhcp_overrides;

	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS);

	addresses = g_array_new (TRUE, FALSE, sizeof(char *));
	nameservers = g_array_new (TRUE, FALSE, sizeof(char *));
	searches = g_array_new (TRUE, FALSE, sizeof(char *));
	dhcp_overrides = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

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

	if (!strcmp (type, NM_SETTING_WIRED_SETTING_NAME)) {
		// TODO: Implement PPPoE support.
		if (nm_connection_get_setting_pppoe (connection)) {
			g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			             "Can't write connection type '%s'",
			             NM_SETTING_PPPOE_SETTING_NAME);
			return FALSE;
		}

		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  ethernets:\n    %s:\n",
		                        nm_connection_get_interface_name (connection));
		if (!write_wired_setting (connection, netplan, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_VLAN_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  vlans:\n    %s:\n",
		                        nm_connection_get_interface_name (connection));
		if (!write_vlan_setting (connection, netplan, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_GSM_SETTING_NAME)) {
		// TODO: add NM_SETTING_GSM_SETTING_NAME
		//       see: https://github.com/CanonicalLtd/netplan/commit/76aa65e67c6a406548cdc4b866e0e0f54ab2b363
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
			         "Can't write connection type '%s'",
			         NM_SETTING_GSM_SETTING_NAME);
		return FALSE;
	} else if (!strcmp (type, NM_SETTING_WIRELESS_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  wifis:\n    %s:\n",
		                        nm_connection_get_interface_name (connection));
		if (!write_wireless_setting (connection, netplan, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_INFINIBAND_SETTING_NAME)) {
#if 0
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  ethernets:\n    %s:\n",
		                        nm_connection_get_interface_name (connection));
		if (!write_infiniband_setting (connection, netplan, error))
#endif
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_BOND_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  bonds:\n    %s:\n",
		                        nm_connection_get_interface_name (connection));
		if (!write_bond_setting (connection, netplan, error))
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_TEAM_SETTING_NAME)) {
#if 0
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  ethernets:\n    %s:\n",
		                        nm_connection_get_interface_name (connection));
		if (!write_team_setting (connection, netplan, error))
#endif
			return FALSE;
	} else if (!strcmp (type, NM_SETTING_BRIDGE_SETTING_NAME)) {
		g_output_stream_printf (netplan, 0, NULL, NULL,
		                        "  bridges:\n    %s:\n",
		                        nm_connection_get_interface_name (connection));
		if (!write_bridge_setting (connection, netplan, error))
			return FALSE;
	} else {
		g_set_error (error, NM_SETTINGS_ERROR, NM_SETTINGS_ERROR_FAILED,
		             "Can't write connection type '%s'", type);
		return FALSE;
	}

	if (!write_bridge_port_setting (connection, netplan, error))
		return FALSE;

	//if (!write_team_port_setting (connection, netplan, error))
	//	return FALSE;

	//if (!write_dcb_setting (connection, netplan, error))
	//	return FALSE;

	//if (!write_proxy_setting (connection, netplan, error))
	//	return FALSE;

	//if (!write_ethtool_setting (connection, netplan, error))
	//	return FALSE;

	if (!write_user_setting (connection, netplan, error))
		return FALSE;

	if (!write_match_setting (connection, netplan, error))
		return FALSE;

	//write_sriov_setting (connection, netplan);

	//if (!write_tc_setting (connection, netplan, error))
	//	return FALSE;

	//s_ip4 = nm_connection_get_setting_ip4_config (connection);
	//s_ip6 = nm_connection_get_setting_ip6_config (connection);

	if (!write_ip4_setting (connection,
	                        netplan,
				addresses,
				nameservers,
				searches,
	                        error))
		return FALSE;

	if (!write_ip6_setting (connection,
	                        netplan,
				addresses,
				nameservers,
				searches,
				dhcp_overrides,
	                        error))
		return FALSE;

	write_ip_routing_rules (connection,
	                        netplan);

	write_connection_setting (s_con, netplan);

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
		filename_str = g_string_sized_new (120);
		g_string_printf (filename_str, "NM-%s.yaml", nm_connection_get_uuid (connection));

		netplan_yaml_path = g_build_filename (netplan_dir,
		                                      filename_str->str,
		                                      NULL);
	} else {
		netplan_yaml_path = g_strdup(filename);
	}

	netplan_yaml = g_file_new_for_path (netplan_yaml_path);
	_LOGT ("write: path %s / %s / %p", netplan_dir, g_file_get_path(netplan_yaml),
				out_filename);

	if (out_filename && !filename)
		*out_filename = g_file_get_path(netplan_yaml);

	netplan = (GOutputStream *) g_file_replace (netplan_yaml,
	                                            NULL, FALSE,
	                                            G_FILE_CREATE_REPLACE_DESTINATION,
				                    NULL,
				                    error);
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
	       filename);

	if (!do_write_to_disk (connection,
	                       netplan,
	                       blobs,
	                       secrets,
	                       route_ignore,
			       NULL, NULL, NULL,
	                       error))
		return FALSE;

#if 0
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

		reread = connection_from_file (filename,
		                               &unhandled,
		                               &local,
		                               NULL);
		nm_assert ((NM_IS_CONNECTION (reread) && !local) || (!reread && local));

		if (!reread) {
			_LOGW ("write: failure to re-read connection \"%s\": %s",
			       filename, local->message);
		} else if (unhandled) {
			g_clear_object (&reread);
			_LOGW ("write: failure to re-read connection \"%s\": %s",
			       filename, "connection is unhandled");
		} else {
			if (out_reread_same) {
				reread_same = nm_connection_compare (reread, connection, NM_SETTING_COMPARE_FLAG_EXACT);
				if (!reread_same) {
					_LOGD ("write: connection %s (%s) was modified by persisting it to \"%s\" ",
					       nm_connection_get_id (connection),
					       nm_connection_get_uuid (connection),
					       filename);
				}
			}
		}

		NM_SET_OUT (out_reread, g_steal_pointer (&reread));
		NM_SET_OUT (out_reread_same, reread_same);
	}

	/* Only return the filename if this was a newly written netplan */
	if (out_filename && !filename)
		*out_filename = g_strdup (filename);
#endif

	return TRUE;
}

gboolean
nms_netplan_writer_can_write_connection (NMConnection *connection, GError **error)
{
	const char *type, *id;

	type = nm_connection_get_connection_type (connection);
	_LOGW ("MATT: writing \"%s\"", type);
	// TODO: add NM_SETTING_GSM_SETTING_NAME
	if (NM_IN_STRSET (type,
	                  NM_SETTING_VLAN_SETTING_NAME,
	                  NM_SETTING_WIRELESS_SETTING_NAME,
	                  NM_SETTING_BOND_SETTING_NAME,
	                  NM_SETTING_TEAM_SETTING_NAME,
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
