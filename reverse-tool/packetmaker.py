#!/usr/bin/env python
"""
Simple quick and dirty tool used to highlight differences between payload.
Useful for easy reverse engineering, modify to match your needs
"""

import sys
import struct
from datetime import datetime
import pytz
from scapy.layers.dot11 import Dot11, Dot11FCS, Dot11EltRates, Dot11EltVendorSpecific
from scapy.sendrecv import sniff

# Put your own mac address here
MYMAC = "WATER_CLOCK_MACADDRESS"

# Do not edut below this point
PROBE_SUBTYPE = 4
BEACON_SUBTYPE = 8
HEADER_OCCURENCE = 40
HIGHLIGHTER = '\033[1m\033[4m\033[92m'
ENDC = '\033[0m'
PAYLOAD = struct.Struct('<' + '9B 2I 2B I 15B')

def print_header():
    """ Prints header"""
    print "\n",
    print """TIMESTAMP            SEQ  TYP  INCSER   03 CD 05 06 07 08 DEVICE_ID  \
TOTAL 17 18 LITER/min   23 24 25 26 27 28 29 30 31 32 33 34 35 UNKN"""

class ANALYZER(object):
    """ Analyzer object """
    def __init__(self):
        print "Running Analyzer"

    previous_value = None
    line_number = 0


    def analyze_line(self, packet):
        """ Analyzes packet, prints data if relevant"""

        src_mac = packet.getlayer(Dot11).addr2
        if src_mac != MYMAC:
            return

        timestamp = datetime.fromtimestamp(packet.time, tz=pytz.timezone('Israel'))
        subtype = packet.getlayer(Dot11FCS).subtype

        if subtype == BEACON_SUBTYPE:
            payload = packet.getlayer(Dot11EltVendorSpecific).info[3:]
            frame_type = 'BC'
        elif subtype == PROBE_SUBTYPE:
            payload = packet.getlayer(Dot11EltRates)[1].info
            frame_type = 'PR'
        else:
            return

        if self.line_number % HEADER_OCCURENCE == 0:
            print_header()

        print timestamp.strftime("%d-%m-%Y %H:%M:%S "),
        print "{:04x} {}  ".format(self.line_number, frame_type),

        values = PAYLOAD.unpack(payload)
        if self.previous_value is None:
            self.previous_value = values

        for i, val in enumerate(values):
            if val != self.previous_value[i]:
                if isinstance(values[i], int) and values[i] < 256:
                    print "{}{:02x}{}".format(HIGHLIGHTER, values[i], ENDC),
                else:
                    print "{}{}{}".format(HIGHLIGHTER, values[i], ENDC),
            else:
                if isinstance(values[i], int) and values[i] < 255:
                    print "{:02x}".format(values[i]),
                else:
                    print "{}".format(values[i]),

        self.previous_value = values
        self.line_number += 1
        print ""

ANALYZER_INSTANCE = ANALYZER()
sniff(offline=sys.stdin, prn=ANALYZER_INSTANCE.analyze_line, store=0)
