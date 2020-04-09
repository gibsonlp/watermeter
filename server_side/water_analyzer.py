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
import logging
import ConfigParser
from datetime import datetime
from mysql.connector import MySQLConnection
from scapy.layers.dot11 import Dot11, Dot11FCS, Dot11EltRates, Dot11EltVendorSpecific
from scapy.sendrecv import sniff

LOGGING_FORMAT = '[%(asctime)s] %(message)s'
PROBE_SUBTYPE = 4
BEACON_SUBTYPE = 8
PAYLOAD = struct.Struct('<' + '9B 2I 2B I 15B')


def parse_args():
    """ Args parser """

    parser = argparse.ArgumentParser(description='Water meter analyzer')
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-f", "--file", action="store", default=None, help="(Optional) Local playback File")
    parser.add_argument("-pt", "--pcaptime", action="store_true", default=False, help="(Optional) Use timestamp from capture file")
    parser.add_argument("-sn", "--serialnum", action="store", type=int, default=None, required=True, help="Meter serial number")
    parser.add_argument("-m", "--mac", action="store", default=None, help="(Optional) Meter mac address to filter")
    parser.add_argument("-mu", "--minupdate", action="store", type=int, default=3600, help="(Optional) Minimum time between DB updates")
    parser.add_argument("-c", "--config", action="store", default=None, help="(Optional) Alternative Configuration file")
    return parser.parse_args()

def get_payload(packet):
    """ Returns payload at correct offset depending on management frame type """
    subtype = packet.getlayer(Dot11FCS).subtype

    if subtype == BEACON_SUBTYPE:
        if packet.haslayer(Dot11EltVendorSpecific):
            return packet.getlayer(Dot11EltVendorSpecific).info[3:]
    elif subtype == PROBE_SUBTYPE:
        if packet.haslayer(Dot11EltRates):
            return packet.getlayer(Dot11EltRates)[1].info
    return ""


def get_meter_values(payload):
    """ Gets meter values from the right offsets """
    values = PAYLOAD.unpack(payload)
    serial = values[9]
    dal = values[10]
    clpm = values[13]
    return (serial, dal, clpm)


class ANALYZER(object):
    # pylint: disable=too-many-instance-attributes
    """ Analyzer object """

    def __init__(self):

        LOGGER.debug("Running Analyzer")
        self.previous_dal = 0
        self.last_update = datetime.now()
        self.database = None
        self.cursor = None


        if ARGS.mac:
            self.macfilter = ARGS.mac
        else:
            self.macfilter = False

        self.pcap_time = ARGS.pcaptime
        self.min_update = ARGS.minupdate

        self.serial_num = ARGS.serialnum

        # Initialize filename, need to be after checking for captime as it will override it
        self.get_file()

        # Set up our database link
        self.config_database()

    def config_database(self):
        """ Configure our database connection using configuration file """

        mysql_user = CONFIG.get('Database', 'username')
        mysql_pass = CONFIG.get('Database', 'password')
        mysql_host = CONFIG.get('Database', 'host')
        mysql_db = CONFIG.get('Database', 'db')
        self.database = MySQLConnection(host=mysql_host, user=mysql_user, passwd=mysql_pass, db=mysql_db)
        self.cursor = self.database.cursor()

    def get_file(self):
        """ returns and verifies paht for pcap file name (or stdin if one is not supplied) """
        if ARGS.file:
            self.filename = ARGS.file
            if not os.path.isfile(self.filename):
                LOGGER.critical("Cannot find file %s", self.filename)
                sys.exit(1)
            else:
                LOGGER.debug("Using file %s", self.filename)

                # Use pcap capture time when replaying from file
                self.pcap_time = True
        else:
            self.filename = sys.stdin
            LOGGER.debug("Using stdin")


    def check_mac(self, packet):
        """ We should never have anything without our mac here,
        this is here just for safety as everything would break otherwise """
        if self.macfilter:
            src_mac = packet.getlayer(Dot11).addr2
            print src_mac
            return src_mac == self.macfilter
        else:
            return True


    def check_timediff(self, now):
        """ Returns true/false if self.min_update passed or not. Will set last_update if needed """
        timediff = now - self.last_update
        if timediff.total_seconds() > self.min_update:
            self.last_update = now
            return True
        else:
            return False

    def update_database(self, clpm, dal, packet):
        """Update DB only if:
        1. Current flow  (cl/min) is > 0, or:
        2. Previous dal measurement is smaller than current one, or:
        3. Last report was made more than self.min_update seconds ago"""

        now = datetime.now()
        if clpm > 0 or self.previous_dal < dal or self.check_timediff(now):
            if self.pcap_time:
                pkt_time = "FROM_UNIXTIME({})".format(packet.time)
            else:
                pkt_time = "NULL"

            sql = "INSERT IGNORE INTO water_raw_data VALUES (NULL, {}, {}, {})".format(pkt_time, dal, clpm)
            LOGGER.debug(sql)
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
        msg = ""

        # SANITY
        if not self.check_mac(packet) or payload == "":
            LOGGER.debug("Mac address mismatch")
            return

        serial, dal, clpm = get_meter_values(payload)

        if serial != self.serial_num:
            LOGGER.debug("Found meter data but wrong Meter ID: %s", serial)
            return

        msg += "{}, {}".format(dal, clpm)

        if self.update_database(clpm, dal, packet):
            msg += ", Updated"
        else:
            msg += ", Skipping"

        LOGGER.info(msg)

def get_config():
    """ Make sure we have a configuration in place """

    if ARGS.config:
        config_file = ARGS.config
    else:
        config_file = "/etc/water_analyzer"

    if not os.path.isfile(config_file):
        LOGGER.critical("Cannot find configuration file at %s", config_file)
        sys.exit(1)
    else:
        LOGGER.debug("Using conf file %s", config_file)
    CONFIG.read(config_file)


if __name__ == '__main__':

    ARGS = parse_args()
    if ARGS.verbose:
        LOGLEVEL = logging.DEBUG
    else:
        LOGLEVEL = logging.INFO

    logging.basicConfig(level=LOGLEVEL, format=LOGGING_FORMAT)
    LOGGER = logging.getLogger()
    CONFIG = ConfigParser.ConfigParser()

    get_config()

    ANALYZER_INSTANCE = ANALYZER()
    sniff(offline=ANALYZER_INSTANCE.filename, prn=ANALYZER_INSTANCE.analyze_line, store=0)
    ANALYZER_INSTANCE.database.close()
