#!/bin/bash
serial_number = 123

# Sample file - edit as needed

while true
do
    /usr/bin/stdbuf -i0 -o0 -e0 /bin/nc -w 600 192.168.1.21 7777 | $HOME/water_analyzer.py -sn ${serial_number}
    sleep 10
done
