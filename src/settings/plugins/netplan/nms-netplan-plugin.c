// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager netplan settings plugin
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd.
 */

#include "nm-default.h"

#include "nms-netplan-plugin.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <netplan/parse.h>

#include "nm-std-aux/c-list-util.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-glib-aux/nm-io-utils.h"
#include "nm-std-aux/nm-dbus-compat.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-config.h"
#include "settings/nm-settings-plugin.h"
#include "settings/nm-settings-utils.h"
#include "NetworkManagerUtils.h"

#include "nms-netplan-storage.h"
#include "nms-netplan-utils.h"
#include "nms-netplan-reader.h"
#include "nms-netplan-writer.h"

/*****************************************************************************/

typedef struct {
	NMConfig *config;

	NMSettUtilStorages storages;

	GHashTable *unmanaged_specs;
	GHashTable *unrecognized_specs;

} NMSNetplanPluginPrivate;

struct _NMSNetplanPlugin {
	NMSettingsPlugin parent;
	NMSNetplanPluginPrivate _priv;
};

struct _NMSNetplanPluginClass {
	NMSettingsPluginClass parent;
};

G_DEFINE_TYPE (NMSNetplanPlugin, nms_netplan_plugin, NM_TYPE_SETTINGS_PLUGIN)

#define NMS_NETPLAN_PLUGIN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSNetplanPlugin, NMS_IS_NETPLAN_PLUGIN, NMSettingsPlugin)

/*****************************************************************************/

#define _NMLOG_DOMAIN  LOGD_SETTINGS
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), NULL, NULL, \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                "netplan: " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void _unhandled_specs_merge_storages (NMSNetplanPlugin *self,
                                             NMSettUtilStorages *storages);
static void _unhandled_specs_reset (NMSNetplanPlugin *self);

/*****************************************************************************/

static void
nm_assert_self (NMSNetplanPlugin *self, gboolean unhandled_specs_consistent)
{
	nm_assert (NMS_IS_NETPLAN_PLUGIN (self));

#if NM_MORE_ASSERTS > 5
	{
		NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
		NMSNetplanStorage *storage;
		gsize n_uuid;
		gs_unref_hashtable GHashTable *h_unmanaged = NULL;
		gs_unref_hashtable GHashTable *h_unrecognized = NULL;

		nm_assert (g_hash_table_size (priv->storages.idx_by_filename) == c_list_length (&priv->storages._storage_lst_head));

		h_unmanaged = g_hash_table_new (nm_str_hash, g_str_equal);
		h_unrecognized = g_hash_table_new (nm_str_hash, g_str_equal);

		n_uuid = 0;

		c_list_for_each_entry (storage, &priv->storages._storage_lst_head, parent._storage_lst) {
			const char *uuid;
			const char *filename;

			filename = nms_netplan_storage_get_filename (storage);

			nm_assert (filename && NM_STR_HAS_PREFIX (filename, NETPLAN_DIR"/"));

			uuid = nms_netplan_storage_get_uuid (storage);

			nm_assert ((!!uuid) + (!!storage->unmanaged_spec) + (!!storage->unrecognized_spec) == 1);

			nm_assert (storage == nm_sett_util_storages_lookup_by_filename (&priv->storages, filename));

			if (uuid) {
				NMSettUtilStorageByUuidHead *sbuh;
				NMSettUtilStorageByUuidHead *sbuh2;

				if (storage->connection)
					nm_assert (nm_streq0 (nm_connection_get_uuid (storage->connection), uuid));

				if (!g_hash_table_lookup_extended (priv->storages.idx_by_uuid, &uuid, (gpointer *) &sbuh, (gpointer *) &sbuh2))
					nm_assert_not_reached ();

				nm_assert (sbuh);
				nm_assert (nm_streq (uuid, sbuh->uuid));
				nm_assert (sbuh == sbuh2);
				nm_assert (c_list_contains (&sbuh->_storage_by_uuid_lst_head, &storage->parent._storage_by_uuid_lst));

				if (c_list_first (&sbuh->_storage_by_uuid_lst_head) == &storage->parent._storage_by_uuid_lst)
					n_uuid++;
			} else if (storage->unmanaged_spec) {
				nm_assert (strlen (storage->unmanaged_spec) > 0);
				g_hash_table_add (h_unmanaged, storage->unmanaged_spec);
			} else if (storage->unrecognized_spec) {
				nm_assert (strlen (storage->unrecognized_spec) > 0);
				g_hash_table_add (h_unrecognized, storage->unrecognized_spec);
			} else
				nm_assert_not_reached ();

			nm_assert (!storage->connection);
		}

		nm_assert (g_hash_table_size (priv->storages.idx_by_uuid) == n_uuid);

		if (unhandled_specs_consistent) {
			nm_assert (nm_utils_hashtable_same_keys (h_unmanaged, priv->unmanaged_specs));
			nm_assert (nm_utils_hashtable_same_keys (h_unrecognized, priv->unrecognized_specs));
		}
	}
#endif
}

/*****************************************************************************/

static NMSNetplanStorage *
_load_file (NMSNetplanPlugin *self,
            const char *filename,
            GError **error)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_free_error GError *load_error = NULL;
	gs_free char *unhandled_spec = NULL;
	gboolean load_error_ignore;
	NMSettingsStorage *storage = NULL;
	struct stat st;
	const char *uuid;

	if (stat (filename, &st) != 0) {
		int errsv = errno;

		if (error) {
			nm_utils_error_set_errno (error, errsv,
			                          "failure to stat file \%s\": %s",
			                          filename);
		} else
			_LOGT ("load[%s]: failure to stat file: %s", filename, nm_strerror_native (errsv));
		return NULL;
	}

	connection = connection_from_file (filename,
	                                   &unhandled_spec,
	                                   &load_error,
	                                   &load_error_ignore);

	if (load_error) {
		if (error) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    "failure to read file \"%s\": %s",
			                    filename, load_error->message);
		} else {
			_NMLOG (load_error_ignore ? LOGL_TRACE : LOGL_WARN,
			        "load[%s]: failure to read file: %s", filename, load_error->message);
		}
		return NULL;
	}

	if (unhandled_spec) {
		const char *unmanaged_spec;
		const char *unrecognized_spec;

		if (!nms_netplan_util_parse_unhandled_spec (unhandled_spec,
		                                            &unmanaged_spec,
		                                            &unrecognized_spec)) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    "invalid unhandled spec \"%s\"",
			                    unhandled_spec);
			nm_assert_not_reached ();
			return NULL;
		}
		return nms_netplan_storage_new_unhandled (self,
		                                          filename,
		                                          unmanaged_spec,
		                                          unrecognized_spec);
	}
				uuid = nm_connection_get_uuid (connection);

				if (!storage)
					storage = nm_settings_storage_new (NM_SETTINGS_PLUGIN (self), uuid, NULL);

				_LOGD ("parse: adding connection \"%s\" (%s)", filename, uuid);

	return nms_netplan_storage_new_connection (self,
	                                           g_steal_pointer (&connection),
	                                           filename,
	                                           NMS_NETPLAN_STORAGE_TYPE_ETC);
}

static void
_load_dir (NMSNetplanPlugin *self,
           NMSettUtilStorages *storages)
{
	gs_unref_hashtable GHashTable *dupl_filenames = NULL;
	gs_free_error GError *local = NULL;
	const char *f_filename;
	GDir *dir;

	dir = g_dir_open (NETPLAN_DIR, 0, &local);
	if (!dir) {
		_LOGT ("Could not read directory '%s': %s", NETPLAN_DIR, local->message);
		return;
	}

	dupl_filenames = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, NULL);

	/* XXX: Do we need to load virtual connections (bridge, bond, ...) after
	 *   physical connections, in order to make libnetplan's YAML parser happy?
	 *   So all the references to physical interfaces are there, before virtual
	 *   interfaces try to use them... */
	while ((f_filename = g_dir_read_name (dir))) {
		gs_free char *full_path = NULL;
		NMSNetplanStorage *storage;

		full_path = g_build_filename (NETPLAN_DIR, f_filename, NULL);
		if (!full_path)
			continue;

		if (!g_hash_table_add (dupl_filenames, full_path))
			continue;

		nm_assert (!nm_sett_util_storages_lookup_by_filename (storages, full_path));

		storage = _load_file (self, full_path, NULL);
		if (storage)
			nm_sett_util_storages_add_take (storages, storage);
	}
	g_dir_close (dir);
}

static void
_storages_consolidate (NMSNetplanPlugin *self,
                       NMSettUtilStorages *storages_new,
                       gboolean replace_all,
                       GHashTable *storages_replaced,
                       NMSettingsPluginConnectionLoadCallback callback,
                       gpointer user_data)
{
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
	CList lst_conn_info_deleted = C_LIST_INIT (lst_conn_info_deleted);
	gs_unref_ptrarray GPtrArray *storages_modified = NULL;
	CList storages_deleted;
	NMSNetplanStorage *storage_safe;
	NMSNetplanStorage *storage_new;
	NMSNetplanStorage *storage_old;
	NMSNetplanStorage *storage;
	guint i;

	/* when we reload all files, we must signal add/update/modify of profiles one-by-one.
	 * NMSettings then goes ahead and emits further signals and a lot of things happen.
	 *
	 * So, first, emit an update of the unmanaged/unrecognized specs that contains *all*
	 * the unmanaged/unrecognized devices from before and after. Since both unmanaged/unrecognized
	 * specs have the meaning of "not doing something", it makes sense that we temporarily
	 * disable that action for the sum of before and after. */
	_unhandled_specs_merge_storages (self, storages_new);

	storages_modified = g_ptr_array_new_with_free_func (g_object_unref);
	c_list_init (&storages_deleted);

	c_list_for_each_entry_safe (storage_new, storage_safe, &storages_new->_storage_lst_head, parent._storage_lst) {
		storage_old = nm_sett_util_storages_lookup_by_filename (&priv->storages, nms_netplan_storage_get_filename (storage_new));

		nm_sett_util_storages_steal (storages_new, storage_new);

		if (   !storage_old
		    || !nms_netplan_storage_equal_type (storage_new, storage_old)) {
			if (storage_old) {
				nm_sett_util_storages_steal (&priv->storages, storage_old);
				if (nms_netplan_storage_get_uuid (storage_old))
					c_list_link_tail (&storages_deleted, &storage_old->parent._storage_lst);
				else
					nms_netplan_storage_destroy (storage_old);
			}
			storage_new->is_dirty = FALSE;
			nm_sett_util_storages_add_take (&priv->storages, storage_new);
			g_ptr_array_add (storages_modified, g_object_ref (storage_new));
			continue;
		}

		storage_old->is_dirty = FALSE;
		nms_netplan_storage_copy_content (storage_old, storage_new);
		nms_netplan_storage_destroy (storage_new);
		g_ptr_array_add (storages_modified, g_object_ref (storage_old));
	}

	c_list_for_each_entry_safe (storage_old, storage_safe, &priv->storages._storage_lst_head, parent._storage_lst) {
		if (!storage_old->is_dirty)
			continue;
		if (   replace_all
		    || (   storages_replaced
		        && g_hash_table_contains (storages_replaced, storage_old))) {
			nm_sett_util_storages_steal (&priv->storages, storage_old);
			if (nms_netplan_storage_get_uuid (storage_old))
				c_list_link_tail (&storages_deleted, &storage_old->parent._storage_lst);
			else
				nms_netplan_storage_destroy (storage_old);
		}
	}

	/* raise events. */

	for (i = 0; i < storages_modified->len; i++) {
		storage = storages_modified->pdata[i];
		storage->is_dirty = TRUE;
	}

	for (i = 0; i < storages_modified->len; i++) {
		gs_unref_object NMConnection *connection = NULL;
		storage = storages_modified->pdata[i];

		if (!storage->is_dirty) {
			/* the entry is no longer dirty. In the meantime we already emited
			 * another signal for it. */
			continue;
		}
		storage->is_dirty = FALSE;
		if (storage != nm_sett_util_storages_lookup_by_filename (&priv->storages, nms_netplan_storage_get_filename (storage))) {
			/* hm? The profile was deleted in the meantime? That is only possible
			 * if the signal handler called again into the plugin. In any case, the event
			 * was already emitted. Skip. */
			continue;
		}

		connection = nms_netplan_storage_steal_connection (storage);
		if (!connection) {
			nm_assert (!nms_netplan_storage_get_uuid (storage));
			continue;
		}

		nm_assert (NM_IS_CONNECTION (connection));
		nm_assert (nms_netplan_storage_get_uuid (storage));
		callback (NM_SETTINGS_PLUGIN (self),
		          NM_SETTINGS_STORAGE (storage),
		          connection,
		          user_data);
	}

	while ((storage = c_list_first_entry (&storages_deleted, NMSNetplanStorage, parent._storage_lst))) {
		c_list_unlink (&storage->parent._storage_lst);
		callback (NM_SETTINGS_PLUGIN (self),
		          NM_SETTINGS_STORAGE (storage),
		          NULL,
		          user_data);
		nms_netplan_storage_destroy (storage);
	}
}

/*****************************************************************************/

static void
load_connections (NMSettingsPlugin *plugin,
                  NMSettingsPluginConnectionLoadEntry *entries,
                  gsize n_entries,
                  NMSettingsPluginConnectionLoadCallback callback,
                  gpointer user_data)
{
	NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (plugin);
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
	nm_auto_clear_sett_util_storages NMSettUtilStorages storages_new = NM_SETT_UTIL_STORAGES_INIT (storages_new, nms_netplan_storage_destroy);
	gs_unref_hashtable GHashTable *dupl_filenames = NULL;
	gs_unref_hashtable GHashTable *storages_replaced = NULL;
	gs_unref_hashtable GHashTable *loaded_uuids = NULL;
	const char *loaded_uuid;
	GHashTableIter h_iter;
	gsize i;

	if (n_entries == 0)
		return;

	dupl_filenames = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	loaded_uuids = g_hash_table_new (nm_str_hash, g_str_equal);

	storages_replaced = g_hash_table_new_full (nm_direct_hash, NULL, g_object_unref, NULL);

	for (i = 0; i < n_entries; i++) {
		NMSettingsPluginConnectionLoadEntry *const entry = &entries[i];
		gs_free_error GError *local = NULL;
		const char *full_filename;
		const char *uuid;
		gs_free char *full_filename_keep = NULL;
		NMSettingsPluginConnectionLoadEntry *dupl_content_entry;
		gs_unref_object NMSNetplanStorage *storage = NULL;

		if (entry->handled)
			continue;

		if ((dupl_content_entry = g_hash_table_lookup (dupl_filenames, entry->filename))) {
			/* we already visited this file. */
			entry->handled = dupl_content_entry->handled;
			if (dupl_content_entry->error) {
				g_set_error_literal (&entry->error,
				                     dupl_content_entry->error->domain,
				                     dupl_content_entry->error->code,
				                     dupl_content_entry->error->message);
			}
			continue;
		}

		entry->handled = TRUE;

		full_filename = entry->filename;
		if (!g_hash_table_insert (dupl_filenames, g_strdup (full_filename), entry))
			nm_assert_not_reached ();

		storage = _load_file (self,
		                      full_filename,
		                      &local);
		if (!storage) {
			if (nm_utils_file_stat (full_filename, NULL) == -ENOENT) {
				NMSNetplanStorage *storage2;

				/* the file does not exist. We take that as indication to unload the file
				 * that was previously loaded... */
				storage2 = nm_sett_util_storages_lookup_by_filename (&priv->storages, full_filename);
				if (storage2)
					g_hash_table_add (storages_replaced, g_object_ref (storage2));
				continue;
			}
			g_propagate_error (&entry->error, g_steal_pointer (&local));
			continue;
		}

		uuid = nms_netplan_storage_get_uuid (storage);
		if (uuid)
			g_hash_table_add (loaded_uuids, (char *) uuid);

		nm_sett_util_storages_add_take (&storages_new, g_steal_pointer (&storage));
	}

	/* now we visit all UUIDs that are about to change... */
	g_hash_table_iter_init (&h_iter, loaded_uuids);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &loaded_uuid, NULL)) {
		NMSNetplanStorage *storage;
		NMSettUtilStorageByUuidHead *sbuh;

		sbuh = nm_sett_util_storages_lookup_by_uuid (&priv->storages, loaded_uuid);
		if (!sbuh)
			continue;

		c_list_for_each_entry (storage, &sbuh->_storage_by_uuid_lst_head, parent._storage_by_uuid_lst) {
			const char *full_filename = nms_netplan_storage_get_filename (storage);
			gs_unref_object NMSNetplanStorage *storage_new = NULL;
			gs_free_error GError *local = NULL;

			if (g_hash_table_contains (dupl_filenames, full_filename)) {
				/* already re-loaded. */
				continue;
			}

			/* @storage has a UUID that was just loaded from disk, but we have an entry in cache.
			 * Reload that file too despite not being told to do so. The reason is to get
			 * the latest file timestamp so that we get the priorities right. */

			storage_new = _load_file (self,
			                          full_filename,
			                          &local);
			if (   storage_new
			    && !nm_streq0 (loaded_uuid, nms_netplan_storage_get_uuid (storage_new))) {
				/* the file now references a different UUID. We are not told to reload
				 * that file, so this means the existing storage (with the previous
				 * filename and UUID tuple) is no longer valid. */
				g_clear_object (&storage_new);
			}

			g_hash_table_add (storages_replaced, g_object_ref (storage));
			if (storage_new)
				nm_sett_util_storages_add_take (&storages_new, g_steal_pointer (&storage_new));
		}
	}

	nm_clear_pointer (&loaded_uuids, g_hash_table_destroy);
	nm_clear_pointer (&dupl_filenames, g_hash_table_destroy);

	_storages_consolidate (self,
	                       &storages_new,
	                       FALSE,
	                       storages_replaced,
	                       callback,
	                       user_data);
}

static void
reload_connections (NMSettingsPlugin *plugin,
                    NMSettingsPluginConnectionLoadCallback callback,
                    gpointer user_data)
{
	NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (plugin);
	nm_auto_clear_sett_util_storages NMSettUtilStorages storages_new = NM_SETT_UTIL_STORAGES_INIT (storages_new, nms_netplan_storage_destroy);

	nm_assert_self (self, TRUE);

	_load_dir (self, &storages_new);

	_storages_consolidate (self,
	                       &storages_new,
	                       TRUE,
	                       NULL,
	                       callback,
	                       user_data);

	nm_assert_self (self, FALSE);
}

static void
load_connections_done (NMSettingsPlugin *plugin)
{
	NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (plugin);

	/* at the beginning of a load, we emit a change signal for unmanaged/unrecognized
	 * specs that contain the sum of before and after (_unhandled_specs_merge_storages()).
	 *
	 * The idea is that while we emit signals about changes to connection, we have
	 * the sum of all unmanaged/unrecognized devices from before and after.
	 *
	 * This if triggered at the end, to reset the specs. */
	_unhandled_specs_reset (self);

	nm_assert_self (self, TRUE);
}

/*****************************************************************************/

static gboolean
add_connection (NMSettingsPlugin *plugin,
                NMConnection *connection,
                NMSettingsStorage **out_storage,
                NMConnection **out_connection,
                GError **error)
{
	NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (plugin);
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
	gs_unref_object NMSNetplanStorage *storage = NULL;
	gs_unref_object NMConnection *reread = NULL;
	gs_free char *full_filename = NULL;
	GError *local = NULL;
	gboolean reread_same;

	nm_assert_self (self, TRUE);
	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (out_storage && !*out_storage);
	nm_assert (out_connection && !*out_connection);

	_LOGT ("MATT: called to save netplan config");

	if (!nms_netplan_writer_write_connection (connection,
	                                          NETPLAN_DIR,
	                                          NULL,
	                                          nm_sett_util_allow_filename_cb,
	                                          NM_SETT_UTIL_ALLOW_FILENAME_DATA (&priv->storages, NULL),
	                                          &full_filename,
	                                          &reread,
	                                          &reread_same,
	                                          &local)) {
		_LOGT ("commit: %s (%s): failed to add: %s",
		       nm_connection_get_uuid (connection),
		       nm_connection_get_id (connection),
		       local->message);
		g_propagate_error (error, local);
		return FALSE;
	}

	if (   !reread
	    || reread_same)
		nm_g_object_ref_set (&reread, connection);

	nm_assert (full_filename && full_filename[0] == '/');

	_LOGT ("commit: %s (%s) added as \"%s\"",
	       nm_connection_get_uuid (reread),
	       nm_connection_get_id (reread),
	       full_filename);

	storage = nms_netplan_storage_new_connection (self,
	                                              g_steal_pointer (&reread),
	                                              full_filename,
	                                              NMS_NETPLAN_STORAGE_TYPE_ETC);

	nm_sett_util_storages_add_take (&priv->storages, g_object_ref (storage));

	*out_connection = nms_netplan_storage_steal_connection (storage);
	*out_storage = NM_SETTINGS_STORAGE (g_steal_pointer (&storage));

	nm_assert_self (self, TRUE);

	return TRUE;
}

static gboolean
update_connection (NMSettingsPlugin *plugin,
                   NMSettingsStorage *storage_x,
                   NMConnection *connection,
                   NMSettingsStorage **out_storage,
                   NMConnection **out_connection,
                   GError **error)
{
	NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (plugin);
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
	NMSNetplanStorage *storage = NMS_NETPLAN_STORAGE (storage_x);
	const char *full_filename;
	const char *uuid;
	GError *local = NULL;
	gs_unref_object NMConnection *reread = NULL;
	gboolean reread_same;

	_LOGT ("MATT: called to update netplan config");

	nm_assert_self (self, TRUE);
	nm_assert (NM_IS_CONNECTION (connection));
	nm_assert (NMS_IS_NETPLAN_STORAGE (storage));
	nm_assert (_nm_connection_verify (connection, NULL) == NM_SETTING_VERIFY_SUCCESS);
	nm_assert (!error || !*error);

	uuid = nms_netplan_storage_get_uuid (storage);

	nm_assert (uuid && nm_streq0 (uuid, nm_connection_get_uuid (connection)));

	full_filename = nms_netplan_storage_get_filename (storage);

	nm_assert (full_filename);
	nm_assert (storage == nm_sett_util_storages_lookup_by_filename (&priv->storages, full_filename));

	if (!nms_netplan_writer_write_connection (connection,
	                                          NETPLAN_DIR,
	                                          full_filename,
	                                          nm_sett_util_allow_filename_cb,
	                                          NM_SETT_UTIL_ALLOW_FILENAME_DATA (&priv->storages, full_filename),
	                                          NULL,
	                                          &reread,
	                                          &reread_same,
	                                          &local)) {
		_LOGT ("commit: failure to write %s (%s) to \"%s\": %s",
		       nm_connection_get_uuid (connection),
		       nm_connection_get_id (connection),
		       full_filename,
		       local->message);
		g_propagate_error (error, local);
		return FALSE;
	}

	if (   !reread
	    || reread_same)
		nm_g_object_ref_set (&reread, connection);

	_LOGT ("commit: \"%s\": profile %s (%s) written",
	       full_filename,
	       uuid,
	       nm_connection_get_id (connection));

	*out_storage = NM_SETTINGS_STORAGE (g_object_ref (storage));
	*out_connection = g_steal_pointer (&reread);

	nm_assert_self (self, TRUE);

	return TRUE;
}

static gboolean
delete_connection (NMSettingsPlugin *plugin,
                   NMSettingsStorage *storage_x,
                   GError **error)
{
	NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (plugin);
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
	NMSNetplanStorage *storage = NMS_NETPLAN_STORAGE (storage_x);
	const char *operation_message = NULL;
	const char *full_filename;

	nm_assert_self (self, TRUE);
	nm_assert (!error || !*error);
	nm_assert (NMS_IS_NETPLAN_STORAGE (storage));

	full_filename = nms_netplan_storage_get_filename (storage);
	nm_assert (full_filename);

	nm_assert (nms_netplan_storage_get_uuid (storage));

	nm_assert (storage == nm_sett_util_storages_lookup_by_filename (&priv->storages, full_filename));

	_LOGT ("commit: deleted \"%s\", profile %s (%s)",
	       full_filename,
	       nms_netplan_storage_get_uuid (storage),
	       operation_message ? operation_message : "");

	nm_sett_util_storages_steal (&priv->storages, storage);
	nms_netplan_storage_destroy (storage);

	nm_assert_self (self, TRUE);

	return TRUE;
}

/*****************************************************************************/

static void
_unhandled_specs_reset (NMSNetplanPlugin *self)
{
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
	gs_unref_hashtable GHashTable *unmanaged_specs = NULL;
	gs_unref_hashtable GHashTable *unrecognized_specs = NULL;
	NMSNetplanStorage *storage;

	unmanaged_specs = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);
	unrecognized_specs = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	c_list_for_each_entry (storage, &priv->storages._storage_lst_head, parent._storage_lst) {
		if (storage->unmanaged_spec)
			g_hash_table_add (unmanaged_specs, g_strdup (storage->unmanaged_spec));
		if (storage->unrecognized_spec)
			g_hash_table_add (unrecognized_specs, g_strdup (storage->unrecognized_spec));
	}

	if (!nm_utils_hashtable_same_keys (unmanaged_specs, priv->unmanaged_specs)) {
		g_hash_table_unref (priv->unmanaged_specs);
		priv->unmanaged_specs = g_steal_pointer (&unmanaged_specs);
	}
	if (!nm_utils_hashtable_same_keys (unrecognized_specs, priv->unrecognized_specs)) {
		g_hash_table_unref (priv->unrecognized_specs);
		priv->unrecognized_specs = g_steal_pointer (&unrecognized_specs);
	}

	if (!unmanaged_specs)
		_nm_settings_plugin_emit_signal_unmanaged_specs_changed (NM_SETTINGS_PLUGIN (self));
	if (!unrecognized_specs)
		_nm_settings_plugin_emit_signal_unrecognized_specs_changed (NM_SETTINGS_PLUGIN (self));
}

static void
_unhandled_specs_merge_storages (NMSNetplanPlugin *self,
                                 NMSettUtilStorages *storages)
{
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);
	gboolean unmanaged_changed = FALSE;
	gboolean unrecognized_changed = FALSE;
	NMSNetplanStorage *storage;

	c_list_for_each_entry (storage, &storages->_storage_lst_head, parent._storage_lst) {
		if (   storage->unmanaged_spec
		    && !g_hash_table_contains (priv->unmanaged_specs, storage->unmanaged_spec)) {
			unmanaged_changed = TRUE;
			g_hash_table_add (priv->unmanaged_specs, g_strdup (storage->unmanaged_spec));
		}
		if (   storage->unrecognized_spec
		    && !g_hash_table_contains (priv->unrecognized_specs, storage->unrecognized_spec)) {
			unrecognized_changed = TRUE;
			g_hash_table_add (priv->unrecognized_specs, g_strdup (storage->unrecognized_spec));
		}
	}

	if (unmanaged_changed)
		_nm_settings_plugin_emit_signal_unmanaged_specs_changed (NM_SETTINGS_PLUGIN (self));
	if (unrecognized_changed)
		_nm_settings_plugin_emit_signal_unrecognized_specs_changed (NM_SETTINGS_PLUGIN (self));
}

static GSList *
_unhandled_specs_from_hashtable (GHashTable *hash)
{
	gs_free const char **keys = NULL;
	GSList *list = NULL;
	guint i, l;

	keys = nm_utils_strdict_get_keys (hash, TRUE, &l);
	for (i = l; i > 0; ) {
		i--;
		list = g_slist_prepend (list, g_strdup (keys[i]));
	}
	return list;
}

static GSList *
get_unmanaged_specs (NMSettingsPlugin *plugin)
{
	return _unhandled_specs_from_hashtable (NMS_NETPLAN_PLUGIN_GET_PRIVATE (plugin)->unmanaged_specs);
}

static GSList *
get_unrecognized_specs (NMSettingsPlugin *plugin)
{
	return _unhandled_specs_from_hashtable (NMS_NETPLAN_PLUGIN_GET_PRIVATE (plugin)->unrecognized_specs);
}

/*****************************************************************************/

static void
nms_netplan_plugin_init (NMSNetplanPlugin *self)
{
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);

	priv->config = g_object_ref (nm_config_get ());

	priv->unmanaged_specs = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);
	priv->unrecognized_specs = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, NULL);

	priv->storages = (NMSettUtilStorages) NM_SETT_UTIL_STORAGES_INIT (priv->storages, nms_netplan_storage_destroy);
}

static void
constructed (GObject *object)
{
	//NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (object);
	//NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);

	G_OBJECT_CLASS (nms_netplan_plugin_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
	NMSNetplanPlugin *self = NMS_NETPLAN_PLUGIN (object);
	NMSNetplanPluginPrivate *priv = NMS_NETPLAN_PLUGIN_GET_PRIVATE (self);

	nm_sett_util_storages_clear (&priv->storages);

	g_clear_object (&priv->config);

	G_OBJECT_CLASS (nms_netplan_plugin_parent_class)->dispose (object);

	nm_clear_pointer (&priv->unmanaged_specs, g_hash_table_destroy);
	nm_clear_pointer (&priv->unrecognized_specs, g_hash_table_destroy);
}

static void
nms_netplan_plugin_class_init (NMSNetplanPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsPluginClass *plugin_class = NM_SETTINGS_PLUGIN_CLASS (klass);

	object_class->constructed = constructed;
	object_class->dispose     = dispose;

	plugin_class->plugin_name            = "netplan";
	plugin_class->get_unmanaged_specs    = get_unmanaged_specs;
	plugin_class->get_unrecognized_specs = get_unrecognized_specs;
	plugin_class->reload_connections     = reload_connections;
	plugin_class->load_connections       = load_connections;
	plugin_class->load_connections_done  = load_connections_done;
	plugin_class->add_connection         = add_connection;
	plugin_class->update_connection      = update_connection;
	plugin_class->delete_connection      = delete_connection;
}

/*****************************************************************************/

G_MODULE_EXPORT NMSettingsPlugin *
nm_settings_plugin_factory (void)
{
	return g_object_new (NMS_TYPE_NETPLAN_PLUGIN, NULL);
}
