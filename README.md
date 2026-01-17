# Water meter project

This repository contains MV-MA (NT) wireless water meter analyzer tool as well as:
- A simple graph tool (under http dir) to visualize the data.
- The python script I wrote and used to reverse-engineer the protocol (under reverse-tool dir).
- OpenWRT configuration (not needed if you can run the analyzer tool directly on a RPi or any other capable hardware.)

This meter uses dekaliters (DAL) to report volume (101.11 CBM = 10111 DAL) and -
Centilitre / min to report flow (101.11 L/min = 10111 cL/min)
  
## The following files need configuration

### Mandatory:
| File |  Comments |
| ------ | ------ |
| server_side/water_analyzer.conf | move to /etc/water_analyzer/water_analyzer.conf |
| server_side/runwater.sh | put your meter's serial number |
| http/public_html/api.php | set config.php path|
| http/config.php | set mariadb/mysql parameters|

### Optional:
| File |  Comments |
| ------ | ------ |
| OpenWRT/files/etc/dropbear/authorized_keys | If you wish to add your own ssh key to the OpenWRT installation |
| OpenWRT/files/etc/rc.local | Any startup modification |
| OpenWRT/files/etc/config/network | Custom network config (IP address, etc...) |
| OpenWRT/config | If you wish to customize OpenWRT further (using menuconfig for that) |
| reverse-tool/packetmaker.py | If you wish to fiddle with the reverse engineering tool |

## Installation

I will add installation instructions as time permits, feel free to reach out if you need assistance setting this up.
If you can run the analyzer on a unit capable of sniffing wifi you can simply run it directly on the wifi interface.
You can check server_side/schema.sql to get the DB layout...
