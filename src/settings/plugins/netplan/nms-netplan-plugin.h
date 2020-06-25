// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager netplan settings plugin
 *
 * Mathieu Trudel-Lapierre <mathieu.trudel-lapierre@canonical.com>
 *
 * Copyright (C) 2019 Canonical Ltd.
 */

#ifndef __NMS_NETPLAN_PLUGIN_H__
#define __NMS_NETPLAN_PLUGIN_H__

#define NETPLAN_DIR				SYSCONFDIR "/netplan"
#define NMS_TYPE_NETPLAN_PLUGIN            (nms_netplan_plugin_get_type ())
#define NMS_NETPLAN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMS_TYPE_NETPLAN_PLUGIN, NMSNetplanPlugin))
#define NMS_NETPLAN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMS_TYPE_NETPLAN_PLUGIN, NMSPluginClass))
#define NMS_IS_NETPLAN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMS_TYPE_NETPLAN_PLUGIN))
#define NMS_IS_NETPLAN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMS_TYPE_NETPLAN_PLUGIN))
#define NMS_NETPLAN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMS_TYPE_NETPLAN_PLUGIN, NMSNetplanPluginClass))

typedef struct _NMSNetplanPlugin NMSNetplanPlugin;
typedef struct _NMSNetplanPluginClass NMSNetplanPluginClass;

GType nms_netplan_plugin_get_type (void);

#endif /* __NMS_NETPLAN_PLUGIN_H__ */
