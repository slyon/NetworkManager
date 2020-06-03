#!/bin/sh
killall NetworkManager
rm /etc/netplan/*
rm /etc/netplan/.goutput*
rm /etc/NetworkManager/system-connections/*
sleep 1
#NetworkManager -d -n &
NetworkManager -n &

sleep 2
nmcli gen log level trace
echo
echo "##### 1st add-del round #####"
nmcli con add type ethernet con-name np1 ifname ens3
nmcli con show
nmcli con mod np1 con-name np1x

#verify NM is still running and results
echo
echo "##### END results #####"
nmcli con show
ls -la /etc/netplan/
ls -la /etc/NetworkManager/system-connections/
