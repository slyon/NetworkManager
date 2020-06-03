#!/bin/sh
killall NetworkManager
rm /etc/netplan/*
rm /etc/NetworkManager/system-connections/*
sleep 1
#NetworkManager -d -n &
NetworkManager -n &

sleep 2
nmcli gen log level trace
echo
echo "##### Adding WiFi connection #####"
nmcli con add type wifi con-name netplan-wifi ssid TEST_SSID ifname wlan0
nmcli con show
cat /etc/netplan/*.yaml | grep -A4 wifis:

#add & del again
echo
echo "##### Modify PSK #####"
nmcli con mod netplan-wifi "802-11-wireless-security.key-mgmt" "wpa-psk" "802-11-wireless-security.psk" "s0s3kr3t"
nmcli con show
cat /etc/netplan/*.yaml | grep -A7 wifis:

#verify NM is still running and results
echo
echo "##### END results #####"
nmcli con show
ls -la /etc/netplan/
ls -la /etc/NetworkManager/system-connections/
