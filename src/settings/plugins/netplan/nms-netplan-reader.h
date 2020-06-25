// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager system settings service
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd..
 */

#ifndef __NMS_NETPLAN_READER_H__
#define __NMS_NETPLAN_READER_H__

#include "nm-connection.h"

NMConnection *connection_from_file (const char *filename,
                                    char **out_unhandled,
                                    GError **error,
                                    gboolean *out_ignore_error);

NMConnection *nmtst_connection_from_file (const char *filename,
                                          const char *network_file,
                                          const char *test_type,
                                          char **out_unhandled,
                                          GError **error);

#endif  /* __NMS_NETPLAN_READER_H__ */
