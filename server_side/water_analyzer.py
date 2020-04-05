#!/usr/bin/env python

"""
MV-MA (NT) wireless water meter analyzer tool
Can run on stdin, pcap file and with a small modification - directly on an interface

This model uses dekaliters (DAL) to report volume (101.11 CBM = 10111 DAL) and -
Centilitre / min to report flow (101.11 l/min = 10111 cl/min)
"""

import sys
import os
import struct
import argparse
from datetime import datetime
from mysql.connector import MySQLConnection
from scapy.layers.dot11 import Dot11, Dot11FCS, Dot11EltRates, Dot11EltVendorSpecific
from scapy.sendrecv import sniff
from pytz import timezone


MYSQL_HOST = "localhost"
MYSQL_USER = "DBUSERNAME"
MYSQL_PASS = "DBPASSWORD"
MYSQL_DB = "DBNAME"
FORCE_UPDATE = 3600 # Force update every hour regardless to changes

MYMAC = "WATER_CLOCK_MACADDRESS"

# Do not edut below this point
PROBE_SUBTYPE = 4
BEACON_SUBTYPE = 8
PAYLOAD = struct.Struct('<' + '9B 2I 2B I 15B')


def parse_args():
    """ Args parser """

    parser = argparse.ArgumentParser(description='Water meter analyzer')
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-f", "--file", action="store", default=None, help="(Optional) Local File")
    return parser.parse_args()


def get_payload(packet):
    """ Returns payload at correct offset depending on management frame type """
    subtype = packet.getlayer(Dot11FCS).subtype

    if subtype == BEACON_SUBTYPE:
        return packet.getlayer(Dot11EltVendorSpecific).info[3:]
    elif subtype == PROBE_SUBTYPE:
        return packet.getlayer(Dot11EltRates)[1].info
    else:
        return ""


def get_meter_values(payload):
    """ Gets meter values from the right offsets """
    values = PAYLOAD.unpack(payload)
    dal = values[10]
    clpm = values[13]
    return (dal, clpm)


def check_mac(packet):
    """ We should never have anything without our mac here,
    this is here just for safety as everything would break otherwise """
    src_mac = packet.getlayer(Dot11).addr2

    return src_mac == MYMAC


class ANALYZER(object):
    """ Analyzer object """

    def __init__(self):
        print "Running Analyzer"
        self.previous_dal = 0
        self.last_update = datetime.now()
        self.database = MySQLConnection(host=MYSQL_HOST, user=MYSQL_USER, passwd=MYSQL_PASS, db=MYSQL_DB)
        self.cursor = self.database.cursor()


    def check_timediff(self, now):
        """ Returns true/false if FORCE_UPDATE passed or not. Will set last_update if needed """
        timediff = now - self.last_update
        if timediff.total_seconds() > FORCE_UPDATE:
            self.last_update = now
            return True
        else:
            return False

    def update_database(self, clpm, dal, packet):
        """Update DB only if:
        1. Current flow  (cl/min) is > 0, or:
        2. Previous dal measurement is smaller than current one, or:
        3. Last report was made more than FORACE_UPDATE seconds ago"""

        now = datetime.now()
        if clpm > 0 or self.previous_dal < dal or self.check_timediff(now):
            sql = "INSERT IGNORE INTO water_raw_data VALUES (NULL, FROM_UNIXTIME({}), {}, {})".format(packet.time, dal, clpm)
            self.cursor.execute(sql)
            self.previous_dal = dal
            self.last_update = now
            self.database.commit()
            return True
        else:
            return False


    def analyze_line(self, packet):
        """ Analyzes packets to extract water usage """
        payload = get_payload(packet)

        # SANITY
        if not check_mac(packet) or payload == "":
            return

        dal, clpm = get_meter_values(payload)
        packet_timestamp = datetime.fromtimestamp(packet.time, tz=timezone('Israel'))

        print packet_timestamp.strftime("%d-%m-%Y %H:%M:%S "),
        print "{}, {}".format(dal, clpm),

        if self.update_database(clpm, dal, packet):
            print ", Updated"
        else:
            print ", Skipping"


if __name__ == '__main__':
    ARGS = parse_args()

    if ARGS.file:
        FILENAME = ARGS.file
        if not os.path.isfile(FILENAME):
            print "Cannot find file {}".format(FILENAME)
            sys.exit(1)
        else:
            print "Using {}".format(FILENAME)
    else:
        FILENAME = sys.stdin

    ANALYZER_INSTANCE = ANALYZER()
    sniff(offline=FILENAME, prn=ANALYZER_INSTANCE.analyze_line, store=0)
    ANALYZER_INSTANCE.database.close()
