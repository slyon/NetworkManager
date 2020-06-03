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
echo "##### 1st add-del round #####"
nmcli con add type ethernet
nmcli con show
nmcli con del ethernet

#add & del again
echo
echo "##### 2nd add-del round #####"
nmcli con add type ethernet
nmcli con show
nmcli con del ethernet

#verify NM is still running and results
echo
echo "##### END results #####"
nmcli con show
ls -la /etc/netplan/
ls -la /etc/NetworkManager/system-connections/
