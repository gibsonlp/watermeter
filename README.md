# Water meter project

This repository contains MV-MA (NT) wireless water meter analyzer tool as well as:
- html graph tool (under http dir)
- Simple python script that I used to reverse-engineer the protocol (under reverse-tool dir)

This meter uses dekaliters (DAL) to report volume (101.11 CBM = 10111 DAL) and -
Centilitre / min to report flow (101.11 l/min = 10111 cl/min)
  
## The following files need configuration
All info would be in the header

### Mandatory:
| File | 
| ------ |
| server_side/water_analyzer.py | 
| OpenWRT/files/bin/scanner.sh |
| http/get.php |
| http/db.php | 

### Optional:
| File |  Comments |
| ------ | ------ |
| OpenWRT/files/etc/dropbear/authorized_keys | If you wish to add your own ssh key to the OpenWRT installation |
| OpenWRT/files/etc/rc.local | Any startup modification |
| OpenWRT/files/etc/config/network | Custom network config (IP address, etc...) |
| OpenWRT/config | If you wish to customize OpenWRT further (using menuconfig for that) |
| reverse-tool/packetmaker.py | If you wish to fiddle with the reverse engineering tool |

## Installation

I do not provide step by step instructions, most of the information / steps will be described in the blog, feel free to add any useful instructions if you wish
As a minimum, after configuration you should be able to run the analyzer tool with

```sh
$ stdbuf -i0 -e0 -o0 nc [IP ADDRESS OF LISTENING DEVICE RUNNING SOCAT] | wateranalyzer.py
```
License
----

MIT
