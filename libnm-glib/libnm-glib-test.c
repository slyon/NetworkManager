#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iwlib.h>
#include <wireless.h>

#include "nm-client.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"


/* Shamelessly ripped from the Linux kernel ieee80211 stack */
static gboolean
nm_utils_is_empty_ssid (const char * ssid, int len)
{
        /* Single white space is for Linksys APs */
        if (len == 1 && ssid[0] == ' ')
                return TRUE;

        /* Otherwise, if the entire ssid is 0, we assume it is hidden */
        while (len--) {
                if (ssid[len] != '\0')
                        return FALSE;
        }
        return TRUE;
}

static const char *
nm_utils_escape_ssid (const char * ssid, guint32 len)
{
	static char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
	const char *s = ssid;
	char *d = escaped;

	if (nm_utils_is_empty_ssid (ssid, len)) {
		memcpy (escaped, "<hidden>", sizeof ("<hidden>"));
		return escaped;
	}

	len = MIN (len, (guint32) IW_ESSID_MAX_SIZE);
	while (len--) {
		if (*s == '\0') {
			*d++ = '\\';
			*d++ = '0';
			s++;
		} else {
			*d++ = *s++;
		}
	}
	*d = '\0';
	return escaped;
}

static gboolean
test_wireless_enabled (NMClient *client)
{
	gboolean wireless;

	wireless = nm_client_wireless_get_enabled (client);
	g_print ("Wireless enabled? %s\n", wireless ? "yes" : "no");

	nm_client_wireless_set_enabled (client, !wireless);

	wireless = nm_client_wireless_get_enabled (client);
	g_print ("Wireless enabled? %s\n", wireless ? "yes" : "no");

	nm_client_wireless_set_enabled (client, !wireless);

	return TRUE;
}

static gboolean
test_get_state (NMClient *client)
{
	guint state;

	state = nm_client_get_state (client);
	g_print ("Current state: %d\n", state);

	return TRUE;
}

static gchar *
ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	gchar *ip_string;

	tmp_addr.s_addr = ip;
	ip_string = inet_ntoa (tmp_addr);

	return g_strdup (ip_string);
}

static void
dump_ip4_config (NMIP4Config *cfg)
{
	char *tmp;
	GArray *array;
	char **ptr_array;
	int i;

	tmp = ip4_address_as_string (nm_ip4_config_get_address (cfg));
	g_print ("IP4 address: %s\n", tmp);
	g_free (tmp);

	tmp = ip4_address_as_string (nm_ip4_config_get_gateway (cfg));
	g_print ("IP4 gateway: %s\n", tmp);
	g_free (tmp);

	tmp = ip4_address_as_string (nm_ip4_config_get_netmask (cfg));
	g_print ("IP4 netmask: %s\n", tmp);
	g_free (tmp);

	tmp = ip4_address_as_string (nm_ip4_config_get_broadcast (cfg));
	g_print ("IP4 broadcast: %s\n", tmp);
	g_free (tmp);

	tmp = nm_ip4_config_get_hostname (cfg);
	g_print ("IP4 hostname: %s\n", tmp);
	g_free (tmp);

	array = nm_ip4_config_get_nameservers (cfg);
	if (array) {
		g_print ("IP4 DNS:\n");
		for (i = 0; i < array->len; i++) {
			tmp = ip4_address_as_string (g_array_index (array, guint32, i));
			g_print ("\t%s\n", tmp);
			g_free (tmp);
		}

		g_array_free (array, TRUE);
	}

	ptr_array = nm_ip4_config_get_domains (cfg);
	if (ptr_array) {
		g_print ("IP4 domains:\n");
		for (i = 0; ptr_array[i]; i++) {
			g_print ("\t%s\n", ptr_array[i]);
		}

		g_strfreev (ptr_array);
	}

	tmp = nm_ip4_config_get_nis_domain (cfg);
	g_print ("IP4 NIS domain: %s\n", tmp);
	g_free (tmp);

	array = nm_ip4_config_get_nis_servers (cfg);
	if (array) {
		g_print ("IP4 NIS servers:\n");
		for (i = 0; i < array->len; i++) {
			tmp = ip4_address_as_string (g_array_index (array, guint32, i));
			g_print ("\t%s\n", tmp);
			g_free (tmp);
		}

		g_array_free (array, TRUE);
	}
}

static void
dump_access_point (NMAccessPoint *ap)
{
	const GByteArray * ssid;
	char * str;

	ssid = nm_access_point_get_ssid (ap);
	g_print ("\tSsid: %s\n",
	         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");

	str = nm_access_point_get_hw_address (ap);
	g_print ("\tMAC Address: %s\n", str);
	g_free (str);

	g_print ("\tFlags: 0x%X\n", nm_access_point_get_flags (ap));
	g_print ("\tWPA Flags: 0x%X\n", nm_access_point_get_wpa_flags (ap));
	g_print ("\tRSN Flags: 0x%X\n", nm_access_point_get_rsn_flags (ap));
	g_print ("\tFrequency: %f\n", nm_access_point_get_frequency (ap));

	g_print ("\tMode: %d\n", nm_access_point_get_mode (ap));
	g_print ("\tRate: %d\n", nm_access_point_get_rate (ap));
	g_print ("\tStrength: %d\n", nm_access_point_get_strength (ap));
}

static void
dump_wireless (NMDevice80211Wireless *device)
{
	char *str;
	GSList *iter;
	GSList *aps;

	g_print ("Mode: %d\n", nm_device_802_11_wireless_get_mode (device));
	g_print ("Bitrate: %d\n", nm_device_802_11_wireless_get_bitrate (device));

	str = nm_device_802_11_wireless_get_hw_address (device);
	g_print ("MAC: %s\n", str);
	g_free (str);

	g_print ("AccessPoints:\n");
	aps = nm_device_802_11_wireless_get_access_points (device);
	for (iter = aps; iter; iter = iter->next) {
		dump_access_point (NM_ACCESS_POINT (iter->data));
		g_print ("\n");
	}

	g_slist_foreach (aps, (GFunc) g_object_unref, NULL);
	g_slist_free (aps);
}

static void
dump_wired (NMDevice8023Ethernet *device)
{
	char *str;

	g_print ("Speed: %d\n", nm_device_802_3_ethernet_get_speed (device));

	str = nm_device_802_3_ethernet_get_hw_address (device);
	g_print ("MAC: %s\n", str);
	g_free (str);
}

static void
dump_device (NMDevice *device)
{
	char *str;
	guint32 u;
	NMDeviceState state;

	str = nm_device_get_iface (device);
	g_print ("Interface: %s\n", str);
	g_free (str);

	str = nm_device_get_udi (device);
	g_print ("Udi: %s\n", str);
	g_free (str);

	str = nm_device_get_driver (device);
	g_print ("Driver: %s\n", str);
	g_free (str);

	u = nm_device_get_ip4_address (device);
	g_print ("IP address: %d\n", u);

	state = nm_device_get_state (device);
	g_print ("State: %d\n", state);

	if (state == NM_DEVICE_STATE_ACTIVATED) {
		NMIP4Config *cfg = nm_device_get_ip4_config (device);
		dump_ip4_config (cfg);
		g_object_unref (cfg);
	}

	if (NM_IS_DEVICE_802_3_ETHERNET (device))
		dump_wired (NM_DEVICE_802_3_ETHERNET (device));
	else if (NM_IS_DEVICE_802_11_WIRELESS (device))
		dump_wireless (NM_DEVICE_802_11_WIRELESS (device));
}

static gboolean
test_devices (NMClient *client)
{
	GSList *list, *iter;

	list = nm_client_get_devices (client);
	g_print ("Got devices:\n");
	for (iter = list; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);
		dump_device (device);
		g_print ("\n");
	}

	g_slist_free (list);

	return TRUE;
}

static void
device_added_cb (NMClient *client, NMDevice *device, gpointer user_data)
{
	g_print ("New device added\n");
	dump_device (device);
}

static void
device_removed_cb (NMClient *client, NMDevice *device, gpointer user_data)
{
	g_print ("Device removed\n");
	dump_device (device);
}


static gboolean
device_deactivate (gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	nm_device_deactivate (device);

	return FALSE;
}

static void
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	char *str;

	str = nm_device_get_iface (device);
	g_print ("Device state changed: %s %d\n", str, state);
	g_free (str);

	if (state == NM_DEVICE_STATE_ACTIVATED) {
		g_print ("Scheduling device deactivation\n");
		g_timeout_add (5 * 1000,
					   device_deactivate,
					   device);
	}
}

static void
manager_running (NMClient *client, gboolean running, gpointer user_data)
{
	if (running) {
		g_print ("NM appeared\n");
		/* 	test_wireless_enabled (client); */
		test_get_state (client);
		test_devices (client);
	} else
		g_print ("NM disappeared\n");
}

int
main (int argc, char *argv[])
{
	NMClient *client;

	g_type_init ();

	client = nm_client_new ();
	if (!client) {
		exit (1);
	}

	g_signal_connect (client, "manager-running", G_CALLBACK (manager_running), NULL);
	manager_running (client, nm_client_manager_is_running (client), NULL);

	g_signal_connect (client, "device-added",
					  G_CALLBACK (device_added_cb), NULL);
	g_signal_connect (client, "device-removed",
					  G_CALLBACK (device_removed_cb), NULL);

	g_main_loop_run (g_main_loop_new (NULL, FALSE));

	g_object_unref (client);

	return 0;
}
