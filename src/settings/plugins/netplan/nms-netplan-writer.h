// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd..
 */

#ifndef __NMS_NETPLAN_WRITER_H__
#define __NMS_NETPLAN_WRITER_H__

#include "nm-connection.h"


typedef gboolean (*NMSNetplanWriterAllowFilenameCb) (const char *check_filename,
                                                     gpointer allow_filename_user_data);

gboolean nms_netplan_writer_can_write_connection (NMConnection *connection,
                                                  GError **error);

gboolean nms_netplan_writer_write_connection (NMConnection *connection,
                                              const char *netplan_dir,
                                              const char *filename,
                                              NMSNetplanWriterAllowFilenameCb allow_filename_cb,
                                              gpointer allow_filename_user_data,
                                              char **out_filename,
                                              NMConnection **out_reread,
                                              gboolean *out_reread_same,
                                              GError **error);

#endif /* __NMS_NETPLAN_WRITER_H__ */
