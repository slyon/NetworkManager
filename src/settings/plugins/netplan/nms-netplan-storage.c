// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd..
 */

#include "nm-default.h"

#include "nms-netplan-storage.h"

#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nms-netplan-plugin.h"

/*****************************************************************************/

struct _NMSNetplanStorageClass {
	NMSettingsStorageClass parent;
};

G_DEFINE_TYPE (NMSNetplanStorage, nms_netplan_storage, NM_TYPE_SETTINGS_STORAGE)

/*****************************************************************************/

gboolean
nms_netplan_storage_equal_type (const NMSNetplanStorage *self_a,
                                const NMSNetplanStorage *self_b)
{
	return    (self_a == self_b)
	       || (   self_a
	           && self_b
	           && nm_streq0 (nms_netplan_storage_get_uuid (self_a),
	                         nms_netplan_storage_get_uuid (self_b))
	           && nm_streq0 (self_a->unmanaged_spec,
	                         self_b->unmanaged_spec)
	           && nm_streq0 (self_a->unrecognized_spec,
	                         self_b->unrecognized_spec));
}

void
nms_netplan_storage_copy_content (NMSNetplanStorage *dst,
                                  const NMSNetplanStorage *src)
{
	nm_assert (src != dst);
	nm_assert (nm_streq (nms_netplan_storage_get_uuid (dst), nms_netplan_storage_get_uuid (src)));
	nm_assert (   nms_netplan_storage_get_filename (dst)
	           && nm_streq (nms_netplan_storage_get_filename (dst), nms_netplan_storage_get_filename (src)));
	nm_assert (dst->storage_type == src->storage_type);
	nm_assert (dst->is_meta_data == src->is_meta_data);

	//NMConnection *connection_to_free;

	//connection_to_free = g_steal_pointer (&dst->u.conn_data.connection);
	dst->u.conn_data = src->u.conn_data;
	nm_g_object_ref (dst->u.conn_data.connection);
}

NMConnection *
nms_netplan_storage_steal_connection (NMSNetplanStorage *self)
{
	nm_assert (NMS_IS_NETPLAN_STORAGE (self));
	nm_assert (   self->is_meta_data
	           || NM_IS_CONNECTION (self->u.conn_data.connection));

	return   self->is_meta_data
	       ? NULL
	       : g_steal_pointer (&self->u.conn_data.connection);
}

/*****************************************************************************/

static int
cmp_fcn (const NMSNetplanStorage *a,
         const NMSNetplanStorage *b)
{
	nm_assert (NMS_IS_NETPLAN_STORAGE (a));
	nm_assert (NMS_IS_NETPLAN_STORAGE (b));
	nm_assert (a != b);

	/* sort by storage-type, which also has a numeric value according to their
	 * (inverse) priority. */
	NM_CMP_FIELD_UNSAFE (b, a, storage_type);

	/* meta-data is more important. */
	NM_CMP_FIELD_UNSAFE (a, b, is_meta_data);

	if (a->is_meta_data) {
		nm_assert (nm_streq (nms_netplan_storage_get_filename (a), nms_netplan_storage_get_filename (b)));
		NM_CMP_FIELD_UNSAFE (a, b, u.meta_data.is_tombstone);
	} else {
		/* newer files are more important. */
		NM_CMP_FIELD (a, b, u.conn_data.stat_mtime.tv_sec);
		NM_CMP_FIELD (a, b, u.conn_data.stat_mtime.tv_nsec);

		NM_CMP_DIRECT_STRCMP (nms_netplan_storage_get_filename (a), nms_netplan_storage_get_filename (b));
	}

	return 0;
}

/*****************************************************************************/

static void
nms_netplan_storage_init (NMSNetplanStorage *self)
{
}

static NMSNetplanStorage *
_storage_new (NMSNetplanPlugin *plugin,
              const char *uuid,
              const char *filename,
              gboolean is_meta_data,
              NMSNetplanStorageType storage_type)

{
	NMSNetplanStorage *self;

	nm_assert (NMS_IS_NETPLAN_PLUGIN (plugin));
	nm_assert (nm_utils_is_uuid (uuid));
	nm_assert (filename && filename[0] == '/');

	self = g_object_new (NMS_TYPE_NETPLAN_STORAGE,
	                     NM_SETTINGS_STORAGE_PLUGIN, plugin,
	                     NM_SETTINGS_STORAGE_UUID, uuid,
	                     NM_SETTINGS_STORAGE_FILENAME, filename,
	                     NULL);

	*((bool *) &self->is_meta_data) = is_meta_data;
	*((NMSNetplanStorageType *) &self->storage_type) = storage_type;

	return self;
}

NMSNetplanStorage *
nms_netplan_storage_new_tombstone (NMSNetplanPlugin *plugin,
                                   const char *uuid,
                                   const char *filename,
                                   NMSNetplanStorageType storage_type)
{
	NMSNetplanStorage *self;

	nm_assert (nm_utils_is_uuid (uuid));
	nm_assert (filename && filename[0] == '/');
	nm_assert (NM_IN_SET (storage_type, NMS_NETPLAN_STORAGE_TYPE_ETC,
	                                    NMS_NETPLAN_STORAGE_TYPE_RUN));

	self = _storage_new (plugin, uuid, filename, TRUE, storage_type);
	self->u.meta_data.is_tombstone = TRUE;
	return self;
}

NMSNetplanStorage *
nms_netplan_storage_new_unhandled (NMSNetplanPlugin *plugin,
                                   const char *filename,
                                   const char *unmanaged_spec,
                                   const char *unrecognized_spec)
{
	NMSNetplanStorage *self;

	nm_assert (unmanaged_spec || unrecognized_spec);

	self = _storage_new (plugin,
	                     NULL,
	                     filename,
			     FALSE,
			     NMS_NETPLAN_STORAGE_TYPE_ETC);
	self->unmanaged_spec = g_strdup (unmanaged_spec);
	self->unrecognized_spec = g_strdup (unrecognized_spec);
	return self;
}

NMSNetplanStorage *
nms_netplan_storage_new_connection (NMSNetplanPlugin *plugin,
                                    NMConnection *connection_take /* pass reference */,
                                    const char *filename,
                                    NMSNetplanStorageType storage_type)
{
	NMSNetplanStorage *self;

	nm_assert (NMS_IS_NETPLAN_PLUGIN (plugin));
	nm_assert (NM_IS_CONNECTION (connection_take));
	nm_assert (_nm_connection_verify (connection_take, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nm_assert (filename && filename[0] == '/');
	nm_assert (   storage_type >= NMS_NETPLAN_STORAGE_TYPE_RUN
	           && storage_type <= _NMS_NETPLAN_STORAGE_TYPE_LIB_LAST);
	nmtst_connection_assert_unchanging (connection_take);

	self = _storage_new (plugin, nm_connection_get_uuid (connection_take), filename, FALSE, storage_type);

	self->u.conn_data.connection = connection_take; /* take reference. */

	return self;
}

static void
_storage_clear (NMSNetplanStorage *self)
{
	const char *netplan_yaml_path;
	GFile *netplan_yaml;
	GError *error = NULL;

	/* Make sure that the related netplan .yaml config file gets removed. */
	netplan_yaml_path = nms_netplan_storage_get_filename (self);
	if (g_file_test (full_filename, G_FILE_TEST_EXISTS)) {
		netplan_yaml = g_file_new_for_path (netplan_yaml_path);
		g_file_delete (netplan_yaml, NULL, &error);
		if (error && *error)
			_LOGT ("netplan: %s", (*error)->message);
	}
	
	c_list_unlink (&self->parent._storage_lst);
	c_list_unlink (&self->parent._storage_by_uuid_lst);
	g_clear_object (&self->u.conn_data.connection);
}

static void
dispose (GObject *object)
{
	NMSNetplanStorage *self = NMS_NETPLAN_STORAGE (object);

	_storage_clear (self);

	G_OBJECT_CLASS (nms_netplan_storage_parent_class)->dispose (object);
}

void
nms_netplan_storage_destroy (NMSNetplanStorage *self)
{
	_storage_clear (self);
	g_object_unref (self);
}

static void
nms_netplan_storage_class_init (NMSNetplanStorageClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsStorageClass *storage_class = NM_SETTINGS_STORAGE_CLASS (klass);

	object_class->dispose = dispose;

	storage_class->cmp_fcn = (int (*) (NMSettingsStorage *, NMSettingsStorage *)) cmp_fcn;
}

/*****************************************************************************/

#include "settings/nm-settings-connection.h"

void
nm_settings_storage_load_sett_flags (NMSettingsStorage *self,
                                     NMSettingsConnectionIntFlags *sett_flags,
                                     NMSettingsConnectionIntFlags *sett_mask)
{
	NMSNetplanStorage *s;

	*sett_flags = NM_SETTINGS_CONNECTION_INT_FLAGS_NONE;
	*sett_mask =   NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED
	             | NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;

	if (!NMS_IS_NETPLAN_STORAGE (self))
		return;

	s = NMS_NETPLAN_STORAGE (self);

	if (s->is_meta_data)
		return;
	if (s->storage_type != NMS_NETPLAN_STORAGE_TYPE_RUN)
		return;

	if (s->u.conn_data.is_nm_generated)
		*sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED;

	if (s->u.conn_data.is_volatile)
		*sett_flags |= NM_SETTINGS_CONNECTION_INT_FLAGS_VOLATILE;
}
