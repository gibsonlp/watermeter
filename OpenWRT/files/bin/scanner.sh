#!/bin/sh

/usr/bin/stdbuf -e0 -i0 -o0 /usr/sbin/tcpdump -w - -n -s0 -i wlan0 type mgt
