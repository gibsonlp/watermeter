"""
services/ingester.py
--------------------
Modernized Packet Sniffer Service.
Captures 802.11 frames, scans for meter data, and saves to DB.

Verbosity Levels:
  None : Silent (Service Mode) - Only Critical Errors
  -v   : Info Mode - Prints "Updated" and "Skipping" logs
  -vv  : Debug Mode - Prints Hex Dumps, Payload details, and Scan info
"""

import sys
import struct
import argparse
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from mysql.connector import MySQLConnection
from scapy.all import sniff, Dot11, Dot11Elt, PcapReader
from config import get_db_config

# Constants
PAYLOAD_STRUCT = struct.Struct('<' + '9B 2I 2B 2h 15B')

# Colors
HIGHLIGHTER = '\033[1m\033[4m\033[92m'
ENDC = '\033[0m'
FAIL = '\033[91m'

# Setup Logging
LOGGER = logging.getLogger("Ingester")

@dataclass
class State:
    """Simple container for runtime state to avoid globals."""
    serial_num: int
    min_update: int
    db_config: dict
    conn: Optional[MySQLConnection] = None
    cursor: Optional[object] = None
    previous_dal: Optional[int] = None
    previous_values: Optional[tuple] = None
    last_update: datetime = datetime.now()

    # Track if we were flowing previously
    was_flowing: bool = False

def get_meter_values(payload):
    """Unpacks payload. Returns tuple of values or None."""
    try:
        values = PAYLOAD_STRUCT.unpack(payload)
        # serial(9), dal(10), clpm(13), full_tuple, error(14)
        return (values[9], values[10], values[13], values, values[14])
    except Exception:
        return (None, None, None, None, None)

def scan_packet_layers(packet, verbose_debug=False):
    """
    Scans ALL Information Elements (IEs) in the packet.
    Returns the first payload matching 38 or 41 bytes.
    """
    layer = packet
    while layer:
        if isinstance(layer, Dot11Elt):
            info = layer.info
            length = len(info)
            
            # Match 38 bytes (Perfect) or 41 bytes (Header included)
            if length == 38:
                if verbose_debug: LOGGER.debug(f"Candidate IE Found (38b). ID: {layer.ID}")
                return info
            elif length == 41:
                if verbose_debug: LOGGER.debug(f"Candidate IE Found (41b). ID: {layer.ID}")
                return info[3:] # Strip OUI

        layer = layer.payload
    return None

def connect_db(state: State):
    try:
        state.conn = MySQLConnection(**state.db_config)
        state.cursor = state.conn.cursor()
        LOGGER.info("DB Connected")
    except Exception as e:
        LOGGER.critical(f"DB Connection Failed: {e}")
        sys.exit(1)

def update_database(state: State, clpm, dal, error_codes, packet, pcap_time=False):
    now = datetime.now()
    time_diff = (now - state.last_update).total_seconds()

    # Detect if flow JUST stopped (Trailing Edge)
    just_stopped = (clpm == 0 and state.was_flowing)
    
    # Logic: Write if First Packet, Flowing, Volume Change, or Heartbeat
    should_write = (
        state.previous_dal is None or 
        clpm > 0 or 
        dal > state.previous_dal or 
        time_diff > state.min_update or
        just_stopped
    )

    if should_write:
        try:
            # Reconnect if needed
            if not state.conn.is_connected():
                state.conn.reconnect()
                state.cursor = state.conn.cursor()

            if pcap_time:
                pkt_time = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
                sql = "INSERT IGNORE INTO water_raw_data VALUES (NULL, %s, %s, %s, %s)"
                vals = (pkt_time, dal, clpm, error_codes)
            else:
                sql = "INSERT IGNORE INTO water_raw_data VALUES (NULL, NOW(), %s, %s, %s)"
                vals = (dal, clpm, error_codes)

            state.cursor.execute(sql, vals)
            state.conn.commit()
            
            state.previous_dal = dal
            state.last_update = now
            state.was_flowing = (clpm > 0)
            return True
        except Exception as e:
            LOGGER.error(f"DB Write Error: {e}")
            
    return False

def process_packet(packet, state: State, verbose_level: int, use_pcap_time: bool, mac_filter: str):
    """Main processing logic per packet."""
    
    # 1. MAC Filter (Optimization: Check before deep scan)
    if mac_filter:
        try:
            if packet.getlayer(Dot11).addr2 != mac_filter: return
        except: return

    # 2. Scan Layers for Payload
    payload = scan_packet_layers(packet, verbose_debug=(verbose_level > 1))
    if not payload: return

    # 3. Decode
    serial, dal, clpm, values, error_codes = get_meter_values(payload)
    if serial is None: return

    # 4. Serial Filter
    if serial != state.serial_num:
        if verbose_level > 1:
            LOGGER.debug(f"{FAIL}Serial Mismatch: {serial} (Target {state.serial_num}){ENDC}")
        return

    # 5. Database Logic
    updated = update_database(state, clpm, dal, error_codes, packet, use_pcap_time)
    
    # 6. Logging (Controlled by Verbosity)
    # Level 1 (-v): Show "Updated" and "Skipping"
    if verbose_level >= 1:
        status = "Updated" if updated else "Skipping"
        LOGGER.info(f"{dal}, {clpm}, {error_codes}, {status}")

    # Level 2 (-vv): Hex Dump
    if verbose_level >= 2:
        dbgstr = "RAW: "
        if state.previous_values is None: state.previous_values = values
        
        for i, val in enumerate(values):
            formatted = f"{val:02x}" if (isinstance(val, int) and val < 256) else f"{val}"
            # Highlight changes
            if val != state.previous_values[i]:
                dbgstr += f"{HIGHLIGHTER}{formatted}{ENDC} "
            else:
                dbgstr += f"{formatted} "
        
        state.previous_values = values
        LOGGER.debug(dbgstr)

def main():
    parser = argparse.ArgumentParser(description="Water Meter Ingester")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity (-v: Info, -vv: Debug)")
    parser.add_argument("-f", "--file", default=None, help="Read from PCAP file")
    parser.add_argument("-pt", "--pcaptime", action="store_true", help="Use PCAP timestamp")
    parser.add_argument("-sn", "--serialnum", type=int, required=True, help="Meter Serial Number")
    parser.add_argument("-m", "--mac", default=None, help="Filter by Source MAC")
    parser.add_argument("-mu", "--minupdate", type=int, default=3600, help="Min update interval")
    
    args = parser.parse_args()

    # Configure Logging based on flags
    if args.verbose == 0:
        log_level = logging.WARNING
    elif args.verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG
        
    logging.basicConfig(
        level=log_level,
        format='[%(asctime)s] %(levelname)s [%(name)s]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Initialize State
    db_config = get_db_config()
    state = State(
        serial_num=args.serialnum,
        min_update=args.minupdate,
        db_config=db_config
    )
    
    connect_db(state)

    # Scapy Callback Wrapper
    def callback(pkt):
        process_packet(pkt, state, args.verbose, args.pcaptime, args.mac)

    try:
        if args.file:
            LOGGER.warning(f"Reading from file: {args.file}")
            with PcapReader(args.file) as reader:
                for pkt in reader:
                    callback(pkt)
        elif not sys.stdin.isatty():
            LOGGER.warning("Reading from STDIN (Pipe)...")
            with PcapReader(sys.stdin.buffer) as reader:
                for pkt in reader:
                    callback(pkt)
        else:
            LOGGER.warning("Reading from Live Interface...")
            sniff(prn=callback, store=0)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        LOGGER.critical(f"Critical Crash: {e}")
    finally:
        if state.conn and state.conn.is_connected():
            state.conn.close()

if __name__ == '__main__':
    main()
