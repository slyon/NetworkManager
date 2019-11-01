// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd..
 */

#ifndef __NMS_NETPLAN_STORAGE_H__
#define __NMS_NETPLAN_STORAGE_H__

#include "c-list/src/c-list.h"
#include "settings/nm-settings-storage.h"
#include "nms-netplan-utils.h"

/*****************************************************************************/

#define NMS_TYPE_NETPLAN_STORAGE            (nms_netplan_storage_get_type ())
#define NMS_NETPLAN_STORAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_NETPLAN_STORAGE, NMSNetplanStorage))
#define NMS_NETPLAN_STORAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_NETPLAN_STORAGE, NMSNetplanStorageClass))
#define NMS_IS_NETPLAN_STORAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_NETPLAN_STORAGE))
#define NMS_IS_NETPLAN_STORAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_NETPLAN_STORAGE))
#define NMS_NETPLAN_STORAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_NETPLAN_STORAGE, NMSNetplanStorageClass))

typedef struct {
	/* whether this is a tombstone to hide a UUID (via symlink to /dev/null). */
	bool is_tombstone:1;
} NMSettingsMetaData;

typedef struct {
	NMSettingsStorage parent;

	NMConnection *connection;

	/* The connection. Note that there are tombstones (loaded-uuid files to /dev/null)
	 * that don't have a connection.
	 *
	 * Also, we don't actually remember the loaded connection after returning it
	 * to NMSettings. So, also for regular storages (non-tombstones) this field
	 * is often cleared. */
	union {
		struct {
			NMConnection *connection;

			/* the timestamp (stat's mtime) of the keyfile. For meta-data this
			 * is irrelevant. The purpose is that if the same storage type (directory) has
			 * multiple files with the same UUID, then the newer file gets preferred. */
			struct timespec stat_mtime;

			/* these flags are only relevant for storages with %NMS_NETPLAN_STORAGE_TYPE_RUN
			 * (and non-metadata). This is to persist and reload these settings flags to
			 * /run.
			 *
			 * Note that these flags are not stored in as meta-data. The reason is that meta-data
			 * is per UUID. But these flags are only relevant for a particular keyfile on disk.
			 * That is, it must be tied to the actual keyfile, and not to the UUID. */
			bool is_nm_generated:1;
			bool is_volatile:1;

		} conn_data;

		/* the content from the .nmmeta file. Note that the nmmeta file has the UUID
		 * in the filename, that means there can be only two variants of this file:
		 * in /etc and in /run. As such, this is really meta-data about the entire profile
		 * (the UUID), and not about the individual keyfile. */
		NMSettingsMetaData meta_data;

	} u;

	char *unmanaged_spec;
	char *unrecognized_spec;

	/* The storage type. This is directly related to the filename. Since
	 * the filename cannot change, this value is unchanging. */
	const NMSNetplanStorageType storage_type;

	/* whether union "u" has meta_data or conn_data. Since the type of the storage
	 * depends on the (immutable) filename, this is also const. */
	const bool is_meta_data;

	/* this flag is only used during reload to mark and prune old entries. */
	bool is_dirty:1;

} NMSNetplanStorage;

typedef struct _NMSNetplanStorageClass NMSNetplanStorageClass;

GType nms_netplan_storage_get_type (void);

struct _NMSNetplanPlugin;

NMSNetplanStorage *nms_netplan_storage_new_tombstone (struct _NMSNetplanPlugin *self,
                                                      const char *uuid,
                                                      const char *filename,
                                                      NMSNetplanStorageType storage_type);

NMSNetplanStorage *nms_netplan_storage_new_connection (struct _NMSNetplanPlugin *self,
                                                       NMConnection *connection_take /* pass reference */,
                                                       const char *filename,
                                                       NMSNetplanStorageType storage_type);

NMSNetplanStorage *nms_netplan_storage_new_unhandled (struct _NMSNetplanPlugin *plugin,
                                                      const char *filename,
                                                      const char *unmanaged_spec,
                                                      const char *unrecognized_spec);

void nms_netplan_storage_destroy (NMSNetplanStorage *storage);

/*****************************************************************************/

gboolean nms_netplan_storage_equal_type (const NMSNetplanStorage *self_a,
                                         const NMSNetplanStorage *self_b);

void nms_netplan_storage_copy_content (NMSNetplanStorage *dst,
                                       const NMSNetplanStorage *src);

NMConnection *nms_netplan_storage_steal_connection (NMSNetplanStorage *storage);

/*****************************************************************************/

static inline const char *
nms_netplan_storage_get_uuid (const NMSNetplanStorage *self)
{
	return nm_settings_storage_get_uuid ((const NMSettingsStorage *) self);
}

static inline const char *
nms_netplan_storage_get_filename (const NMSNetplanStorage *self)
{
	return nm_settings_storage_get_filename ((const NMSettingsStorage *) self);
}

/*****************************************************************************/

static inline gboolean
nm_settings_storage_is_netplan_run (const NMSettingsStorage *self)
{
	return    NMS_IS_NETPLAN_STORAGE (self)
	       && (((NMSNetplanStorage *) self)->storage_type == NMS_NETPLAN_STORAGE_TYPE_RUN);
}

static inline gboolean
nm_settings_storage_is_netplan_lib (const NMSettingsStorage *self)
{
	return    NMS_IS_NETPLAN_STORAGE (self)
	       && (((NMSNetplanStorage *) self)->storage_type >= NMS_NETPLAN_STORAGE_TYPE_LIB_BASE);
}

static inline const NMSettingsMetaData *
nm_settings_storage_is_meta_data (const NMSettingsStorage *storage)
{
	const NMSNetplanStorage *self;

	if (!NMS_IS_NETPLAN_STORAGE (storage))
		return NULL;

	self = (NMSNetplanStorage *) storage;

	if (!self->is_meta_data)
		return NULL;

	return &self->u.meta_data;
}

static inline const NMSettingsMetaData *
nm_settings_storage_is_meta_data_alive (const NMSettingsStorage *storage)
{
	const NMSettingsMetaData *meta_data;

	meta_data = nm_settings_storage_is_meta_data (storage);

	if (!meta_data)
		return NULL;

	/* Regular (all other) storages are alive as long as they report a NMConnection, and
	 * they will be dropped, once they have no more connection.
	 *
	 * Meta-data storages are special: they never report a NMConnection.
	 * So, a meta-data storage is alive as long as it is tracked by the
	 * settings plugin.
	 *
	 * This function is used to ckeck for that. */

	if (c_list_is_empty (&storage->_storage_lst))
		return NULL;

	return meta_data;
}

/*****************************************************************************/

enum _NMSettingsConnectionIntFlags;

void nm_settings_storage_load_sett_flags (NMSettingsStorage *self,
                                          enum _NMSettingsConnectionIntFlags *sett_flags,
                                          enum _NMSettingsConnectionIntFlags *sett_mask);

#endif /* __NMS_NETPLAN_STORAGE_H__ */
