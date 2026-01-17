#!/usr/bin/env python3

"""
MV-MA (NT) Wireless Water Meter Analyzer
Usage:
  Daily Report:  python3 water_monitor.py
  Hourly Check:  python3 water_monitor.py --errors-only
"""

import sys
import os
import argparse
import logging
import configparser
import smtplib
from email.message import EmailMessage
from mysql.connector import MySQLConnection

# --- GLOBAL CONFIG STORAGE ---
LOGGING_FORMAT = '[%(asctime)s] %(message)s'
LINE_CONFIG = {} 
ALERTS = []

def parse_args():
    parser = argparse.ArgumentParser(description='Water meter analyzer')
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-c", "--config", action="store", default=None, help="Config file path")
    parser.add_argument("--errors-only", action="store_true", help="Only email if anomalies are found")
    return parser.parse_args()

def get_config():
    """ Load config and populate LINE_CONFIG dynamically """
    if ARGS.config:
        config_file = ARGS.config
    else:
        config_file = "/etc/water_analyzer"

    if not os.path.isfile(config_file):
        # Fallback for local testing
        if os.path.isfile("config.ini"):
            config_file = "config.ini"
        else:
            LOGGER.warning(f"Configuration file not found at {config_file}")
            
    CONFIG.read(config_file)
    
    # Load Line Configurations dynamically
    global LINE_CONFIG
    LINE_CONFIG = {}
    
    for section in CONFIG.sections():
        if section.lower().startswith("line_"):
            try:
                # Extract ID from [Line_0] -> 0
                line_id = int(section.split("_")[1])
                LINE_CONFIG[line_id] = {
                    "name": CONFIG.get(section, 'name', fallback=f"Line {line_id}"),
                    "limit_dal": CONFIG.getfloat(section, 'limit_dal', fallback=100),
                    "limit_flow": CONFIG.getfloat(section, 'limit_flow', fallback=5000),
                    "isolation_check": CONFIG.getboolean(section, 'isolation_check', fallback=False)
                }
                LOGGER.debug(f"Loaded config for {LINE_CONFIG[line_id]['name']} (ID: {line_id})")
            except (IndexError, ValueError):
                LOGGER.warning(f"Skipping invalid config section: {section}")

def check_hardware_errors_realtime(cursor):
    """ Checks for Error 256 (Leak Alarm) in the last 2 hours """
    sql = """
        SELECT capture_time, error_codes 
        FROM water_raw_data 
        WHERE capture_time >= NOW() - INTERVAL 2 HOUR
          AND error_codes != 0 
        ORDER BY capture_time DESC LIMIT 1
    """
    LOGGER.debug(f"Executing Realtime Error Check: {sql}")
    cursor.execute(sql)
    row = cursor.fetchone()
    if row:
        LOGGER.debug(f"Realtime Error Found: {row}")
        ALERTS.append(f"CRITICAL: Meter Hardware Error {row[1]} detected at {row[0]}")

def get_rolling_24h_total(cursor):
    """ Checks rolling 24h usage for the Hourly safety check """
    limit = CONFIG.getfloat('Analysis', 'daily_leak_limit_liters', fallback=1500)
    sql = "SELECT MAX(dal) - MIN(dal) FROM water_raw_data WHERE capture_time >= NOW() - INTERVAL 24 HOUR"
    cursor.execute(sql)
    res = cursor.fetchone()
    if res and res[0] is not None:
        liters = float(res[0]) * 10
        if liters > limit:
            ALERTS.append(f"CRITICAL: Rolling 24h usage {liters:.0f}L exceeds limit ({limit}L)")

def get_yesterday_total_and_check(cursor):
    """ Strict 'Yesterday' total for the Daily Report & Leak Check """
    limit = CONFIG.getfloat('Analysis', 'daily_leak_limit_liters', fallback=1500)
    sql = """
        SELECT MAX(dal) - MIN(dal) 
        FROM water_raw_data 
        WHERE capture_time >= CURDATE() - INTERVAL 1 DAY 
          AND capture_time < CURDATE()
    """
    cursor.execute(sql)
    res = cursor.fetchone()
    liters = (float(res[0]) * 10) if res and res[0] is not None else 0.0

    if liters > limit:
        ALERTS.append(f"LEAK: Yesterday's usage {liters:.0f}L exceeds limit ({limit}L)")
    
    return liters

def is_isolated_event(cursor, start_time, end_time):
    """
    Generic Isolation Check.
    Returns True if the house was silent (no other water usage).
    """
    LOGGER.debug(f"Running Isolation Check for {start_time}")
    
    # Check 5 minutes BEFORE start
    cursor.execute("""
        SELECT SUM(clpm) FROM water_raw_data 
        WHERE capture_time BETWEEN %s - INTERVAL 5 MINUTE AND %s
    """, (start_time, start_time))
    res = cursor.fetchone()
    pre_noise = float(res[0]) if res and res[0] else 0

    # Check 5 minutes AFTER end
    cursor.execute("""
        SELECT SUM(clpm) FROM water_raw_data 
        WHERE capture_time BETWEEN %s AND %s + INTERVAL 5 MINUTE
    """, (end_time, end_time))
    res = cursor.fetchone()
    post_noise = float(res[0]) if res and res[0] else 0

    LOGGER.debug(f"Isolation Result: Pre-Noise={pre_noise}, Post-Noise={post_noise}")

    # Threshold: 100 cl (1 Liter) to account for minor sensor noise
    return (pre_noise < 100) and (post_noise < 100)

def analyze_line_run(cursor, irrigation):
    """ Analyzes irrigation for anomalies using dynamic config """
    run_id, start_time, end_time, line_id = irrigation
    
    sql = """
        SELECT MAX(dal) - MIN(dal), MIN(NULLIF(clpm, 0)), MAX(clpm), AVG(clpm), COUNT(*)
        FROM water_raw_data 
        WHERE capture_time BETWEEN %s AND %s
    """
    cursor.execute(sql, (start_time, end_time))
    stats = cursor.fetchone()
    
    cons_dal = stats[0] if stats[0] is not None else 0
    max_flow = stats[2] if stats[2] is not None else 0
    count = stats[4]
    
    # Load config for this line, or use defaults
    line_conf = LINE_CONFIG.get(line_id, {
        "name": f"Unknown Line {line_id}", 
        "limit_dal": 100, 
        "limit_flow": 5000,
        "isolation_check": False
    })
    
    line_name = line_conf['name']
    start_str = start_time.strftime("%H:%M")
    liters = cons_dal * 10
    flow_lpm = max_flow / 100.0
    
    duration = end_time - start_time
    minutes = duration.total_seconds() / 60

    msg = f"[{line_name}] {start_str} ({minutes:.1f} min): {liters:.0f}L / Max Flow {flow_lpm:.1f} lpm"

    # -- ANOMALY CHECKS --
    if count == 0:
        # If it's a line that requires isolation checks (like Pots), we tolerate gaps more
        if not line_conf['isolation_check']:
            ALERTS.append(f"DATA LOSS: {line_name} ran at {start_str} but no meter data found.")
        return msg + " [NO DATA]"

    # Check Usage Limit
    if cons_dal > line_conf['limit_dal']:
        ALERTS.append(f"LEAK: {line_name} used {liters}L (Limit: {line_conf['limit_dal']*10}L)")
        msg += " [HIGH USAGE]"

    # Check Flow Limit
    if max_flow > line_conf['limit_flow']:
        # If this line requires isolation (e.g., Pots), check for background noise
        if line_conf['isolation_check']:
            LOGGER.debug(f"Line {line_id} High Flow. Checking Isolation...")
            if is_isolated_event(cursor, start_time, end_time):
                ALERTS.append(f"BURST: {line_name} flow {flow_lpm} lpm (Isolated Event)")
                msg += " [HIGH FLOW - CONFIRMED]"
            else:
                msg += " [HIGH FLOW - IGNORED (Background Noise)]"
        else:
            # Standard Line
            ALERTS.append(f"BURST: {line_name} flow {flow_lpm} lpm (Limit: {line_conf['limit_flow']/100})")
            msg += " [HIGH FLOW]"

    # Zero Flow Check
    # If isolation check is ON, we assume it's a low flow line (like Pots)
    # So we don't alert on Zero Flow unless it's critical, or we just note it.
    if max_flow == 0:
        if line_conf['isolation_check']:
             msg += " [No flow registered]"
        else:
             ALERTS.append(f"FAILURE: {line_name} ran but no water flow detected!")
             msg += " [NO FLOW]"

    return msg

def send_email(subject, body):
    """ Robust email sender that mimics default behavior (Port 25/587 + STARTTLS) """
    if not CONFIG.has_section('Email') or not CONFIG.getboolean('Email', 'enabled', fallback=False):
        LOGGER.info("Email disabled or configuration missing.")
        return

    smtp_host = CONFIG.get('Email', 'smtp_host', fallback='')
    smtp_port = CONFIG.getint('Email', 'smtp_port', fallback=25) 
    smtp_starttls = CONFIG.getboolean('Email', 'smtp_ssl', fallback=True)
    smtp_user = CONFIG.get('Email', 'smtp_user', fallback='')
    smtp_pass = CONFIG.get('Email', 'smtp_pass', fallback='')
    from_addr = CONFIG.get('Email', 'from_addr', fallback='')
    to_addr = CONFIG.get('Email', 'to_addr', fallback='')

    if not smtp_host or not to_addr:
        LOGGER.error("Missing required email configuration (host or to_addr).")
        return

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = to_addr

    try:
        LOGGER.debug(f"Connecting to SMTP: {smtp_host}:{smtp_port} (Timeout=10s)...")
        s = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        
        if smtp_starttls:
            s.starttls()
        
        if smtp_user and smtp_pass:
            s.login(smtp_user, smtp_pass)
        
        s.send_message(msg)
        s.quit()
        LOGGER.info(f"Email sent successfully: {subject}")
    except Exception as e:
        LOGGER.error(f"Failed to send email: {e}")

# --- MAIN ---
if __name__ == '__main__':
    ARGS = parse_args()
    LOGLEVEL = logging.DEBUG if ARGS.verbose else logging.INFO
    logging.basicConfig(level=LOGLEVEL, format=LOGGING_FORMAT)
    LOGGER = logging.getLogger()
    CONFIG = configparser.ConfigParser()
    get_config()

    try:
        database = MySQLConnection(
            host=CONFIG.get('Database', 'host', fallback='localhost'),
            user=CONFIG.get('Database', 'username', fallback='root'),
            passwd=CONFIG.get('Database', 'password', fallback=''),
            db=CONFIG.get('Database', 'db', fallback='sniffler')
        )
        cursor = database.cursor()
    except Exception as e:
        LOGGER.critical(f"DB Connection failed: {e}")
        sys.exit(1)

    # 1. Run Global Checks
    check_hardware_errors_realtime(cursor)
    get_rolling_24h_total(cursor)
    yesterday_liters = get_yesterday_total_and_check(cursor)
    
    if not ARGS.errors_only:
        sql = """
            SELECT capture_time, error_codes FROM water_raw_data 
            WHERE capture_time >= CURDATE() - INTERVAL 1 DAY 
              AND capture_time < CURDATE() 
              AND error_codes != 0 LIMIT 1
        """
        cursor.execute(sql)
        row = cursor.fetchone()
        if row:
            ALERTS.append(f"CRITICAL: Yesterday Meter Hardware Error {row[1]} detected at {row[0]}")

    # 2. Analyze Logs (Optional)
    irrigation_log = ""
    if CONFIG.getboolean('Analysis', 'enable_line_monitoring', fallback=True):
        search_window_start = "NOW() - INTERVAL 24 HOUR" if ARGS.errors_only else "CURDATE() - INTERVAL 1 DAY"
        search_window_end = "NOW()" if ARGS.errors_only else "CURDATE()"
        
        sql = f"""
            SELECT id, start_time, end_time, line 
            FROM irrigation_tracker 
            WHERE start_time >= {search_window_start} AND start_time < {search_window_end}
            ORDER BY start_time
        """
        LOGGER.debug(f"Fetching irrigation logs: {sql}")
        cursor.execute(sql)
        irrigations = cursor.fetchall()
        
        for irrigation in irrigations:
            irrigation_log += analyze_line_run(cursor, irrigation) + "\n"
    else:
        LOGGER.info("Line Monitoring disabled in config. Skipping irrigation analysis.")
        irrigation_log = "Line Monitoring Disabled.\n"

    database.close()

    # 3. Decision Logic
    should_send_email = False
    subject = ""
    body = ""

    if ARGS.errors_only:
        if ALERTS:
            should_send_email = True
            subject = f"⚠️ CRITICAL: Water Anomalies ({len(ALERTS)})"
            body = "The following issues require attention:\n\n" + "\n".join(ALERTS)
            body += "\n\nRecent Activity Log:\n" + irrigation_log
    else:
        should_send_email = True
        if ALERTS:
            subject = f"⚠️ Daily Water: {yesterday_liters:.0f}L - Issues Detected"
            body = "ISSUES DETECTED:\n" + "\n".join(ALERTS) + "\n\n"
        else:
            subject = f"Daily Water: {yesterday_liters:.0f}L - Normal"
            body = "System Status: Green\n\n"
        
        body += f"Total Daily Consumption: {yesterday_liters:.0f} Liters\n"
        body += "-"*30 + "\n"
        body += "Irrigation Log (Yesterday):\n" + "-"*30 + "\n" + irrigation_log
        LOGGER.debug(f"\n{body}")

    # 4. Send Email
    if should_send_email:
        print(f"Sending email: {subject}")
        send_email(subject, body)
    else:
        print("No anomalies found. Silent mode.")
