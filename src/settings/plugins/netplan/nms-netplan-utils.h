// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd..
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include "nm-connection.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

typedef enum {
	NMS_NETPLAN_STORAGE_TYPE_RUN       = 1, /* read-write, runtime only, e.g. /run */
	NMS_NETPLAN_STORAGE_TYPE_ETC       = 2, /* read-write, persistent,   e.g. /etc     */
	NMS_NETPLAN_STORAGE_TYPE_LIB_BASE  = 3, /* read-only,                e.g. /usr/lib */

	_NMS_NETPLAN_STORAGE_TYPE_LIB_LAST = 1000,
} NMSNetplanStorageType;

static inline NMSNetplanStorageType
NMS_NETPLAN_STORAGE_TYPE_LIB (guint run_idx)
{
	nm_assert (run_idx <= (_NMS_NETPLAN_STORAGE_TYPE_LIB_LAST - NMS_NETPLAN_STORAGE_TYPE_LIB_BASE));
	return NMS_NETPLAN_STORAGE_TYPE_LIB_BASE + run_idx;
}

gboolean nms_netplan_util_parse_unhandled_spec (const char *unhandled_spec,
                                                const char **out_unmanaged_spec,
                                                const char **out_unrecognized_spec);

#define NM_NETPLAN_CONNECTION_LOG_PATH(path)  ((path) ?: "in-memory")
#define NM_NETPLAN_CONNECTION_LOG_FMT         "%s (%s,\"%s\")"
#define NM_NETPLAN_CONNECTION_LOG_ARG(con)    NM_NETPLAN_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_settings_connection_get_uuid ((NMSettingsConnection *) (con)), nm_settings_connection_get_id ((NMSettingsConnection *) (con))
#define NM_NETPLAN_CONNECTION_LOG_FMTD        "%s (%s,\"%s\",%p)"
#define NM_NETPLAN_CONNECTION_LOG_ARGD(con)   NM_NETPLAN_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_settings_connection_get_uuid ((NMSettingsConnection *) (con)), nm_settings_connection_get_id ((NMSettingsConnection *) (con)), (con)

char *utils_cert_path (const char *parent, const char *suffix, const char *extension);

const char *utils_get_netplan_name (const char *file, gboolean only_netplan);

gboolean utils_should_ignore_file (const char *filename, gboolean only_netplan);

#if 0 // See C file...
shvarFile *utils_get_extra_netplan (const char *parent, const char *tag, gboolean should_create);
shvarFile *utils_get_keys_netplan (const char *parent, gboolean should_create);
shvarFile *utils_get_route_netplan (const char *parent, gboolean should_create);
#endif

gboolean utils_has_route_file_new_syntax (const char *filename);
gboolean utils_has_complex_routes (const char *filename, int addr_family);

gboolean utils_is_netplan_alias_file (const char *alias, const char *netplan);

char *utils_detect_netplan_path (const char *path, gboolean only_netplan);

void nms_netplan_utils_user_key_encode (const char *key, GString *str_buffer);
gboolean nms_netplan_utils_user_key_decode (const char *name, GString *str_buffer);

/*****************************************************************************/

extern const char *const _nm_ethtool_netplan_names[_NM_ETHTOOL_ID_FEATURE_NUM];

static inline const char *
nms_netplan_utils_get_ethtool_name (NMEthtoolID ethtool_id)
{
	nm_assert (ethtool_id >= _NM_ETHTOOL_ID_FEATURE_FIRST && ethtool_id <= _NM_ETHTOOL_ID_FEATURE_LAST);
	nm_assert ((ethtool_id - _NM_ETHTOOL_ID_FEATURE_FIRST) < G_N_ELEMENTS (_nm_ethtool_netplan_names));
	nm_assert (_nm_ethtool_netplan_names[ethtool_id - _NM_ETHTOOL_ID_FEATURE_FIRST]);

	return _nm_ethtool_netplan_names[ethtool_id - _NM_ETHTOOL_ID_FEATURE_FIRST];
}

const NMEthtoolData *nms_netplan_utils_get_ethtool_by_name (const char *name);

#endif  /* _UTILS_H_ */
