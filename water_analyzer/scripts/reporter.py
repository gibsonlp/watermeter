"""
scripts/reporter.py
-------------------
Daily & Hourly Report Generator.
Performs safety checks (Hardware Errors, Leaks) and sends email alerts.
Replaces 'consumption_and_irrigation_analyzer.py'.

Usage:
  Hourly Check: python3 -m scripts.reporter --errors-only
  Daily Report: python3 -m scripts.reporter
"""

import argparse
import logging
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage
from core.database import get_connection
from core.logic import analyze_period
from config import get_email_config, get_analysis_config

ALERTS = []
LOGGER = logging.getLogger("Reporter")

def check_realtime_hw_error(cursor):
    """
    Safety Check 1: Real-time Hardware Error.
    Checks the last 2 hours for Error Code 256 (Leak/Burst Flag).
    """
    cursor.execute("""
        SELECT capture_time, error_codes FROM water_raw_data 
        WHERE capture_time >= NOW() - INTERVAL 2 HOUR 
        AND (error_codes & 256) > 0 
        ORDER BY capture_time DESC LIMIT 1
    """)
    row = cursor.fetchone()
    if row:
        ALERTS.append(f"CRITICAL: Hardware Leak Alarm (256) detected at {row[0]}")
    
    """
    Heuristic Leak Check (The Rolling Minimum)
    [UPDATED] Now fetches Volume and Duration for better context.
    """
    cursor.execute("""
        SELECT 
            COUNT(*), 
            MIN(clpm), 
            MAX(dal) - MIN(dal), 
            MIN(capture_time), 
            MAX(capture_time)
        FROM water_raw_data 
        WHERE capture_time >= NOW() - INTERVAL 1 HOUR
    """)
    row = cursor.fetchone()
    count, min_flow, volume_dal, start_ts, end_ts = row
    
    # If we have data (> 30 samples) and flow never dropped to 0
    if count and count > 30 and min_flow is not None and min_flow > 0:
        flow_lpm = min_flow / 100.0
        vol_liters = float(volume_dal) * 10 if volume_dal else 0
        
        # Calculate time range string
        time_str = "Unknown"
        if start_ts and end_ts:
            s = start_ts.strftime("%H:%M")
            e = end_ts.strftime("%H:%M")
            time_str = f"{s}-{e}"

        ALERTS.append(f"WARNING: Continuous Flow (>1h). Range: {time_str} | Vol: {vol_liters:.0f}L | Min Rate: {flow_lpm:.1f} LPM")

def check_rolling_24h(cursor, limit):
    """
    Safety Check 2: Rolling 24h Total.
    Checks strictly the last 24 hours from NOW (crossing midnight).
    Useful for catching leaks that started yesterday evening.
    """
    cursor.execute("SELECT MAX(dal) - MIN(dal) FROM water_raw_data WHERE capture_time >= NOW() - INTERVAL 24 HOUR")
    res = cursor.fetchone()
    if res and res[0]:
        liters = float(res[0]) * 10
        if liters > limit:
            ALERTS.append(f"CRITICAL: Rolling 24h usage {liters:.0f}L exceeds limit ({limit}L)")

def get_yesterday_total(cursor, limit):
    """
    Status Check: Yesterday's Total (00:00 - 23:59).
    Used for the Daily Report summary.
    """
    cursor.execute("""
        SELECT MAX(dal) - MIN(dal) FROM water_raw_data 
        WHERE capture_time >= CURDATE() - INTERVAL 1 DAY AND capture_time < CURDATE()
    """)
    res = cursor.fetchone()
    liters = (float(res[0]) * 10) if res and res[0] else 0.0
    
    if liters > limit:
        ALERTS.append(f"LEAK: Yesterday's usage {liters:.0f}L exceeds limit ({limit}L)")
    
    return liters

def send_email(subject, body):
    """Sends email using credentials from config."""
    cfg = get_email_config()
    if not cfg['enabled']:
        LOGGER.info("Email disabled in config.")
        return

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = cfg['from']
    msg['To'] = cfg['to']

    try:
        s = smtplib.SMTP(cfg['host'], cfg['port'])
        if cfg['ssl']: s.starttls()
        if cfg['user']: s.login(cfg['user'], cfg['pass'])
        s.send_message(msg)
        s.quit()
        LOGGER.info(f"Email sent: {subject}")
    except Exception as e:
        LOGGER.error(f"Email failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--errors-only", action="store_true", help="Only send email if critical errors found")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    
    conn = get_connection()
    cursor = conn.cursor()
    conf_analysis = get_analysis_config()

    # 1. Run Global Safety Checks
    check_realtime_hw_error(cursor)
    check_rolling_24h(cursor, conf_analysis['daily_limit'])
    yest_liters = get_yesterday_total(cursor, conf_analysis['daily_limit'])

    # 2. Detailed Irrigation Analysis
    # If running Hourly (--errors-only), scan last 24h window for context.
    # If running Daily, scan exactly Yesterday (00:00-23:59).
    end_dt = datetime.now()
    if args.errors_only:
        start_dt = end_dt - timedelta(hours=24)
    else:
        # Snap to yesterday 00:00 - 23:59
        end_dt = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        start_dt = end_dt - timedelta(days=1)

    # Use Shared Logic Engine
    res = analyze_period(start_dt, end_dt)
    bands = res['plotBands']
    points = res['points']
    log_output = ""

    # Check for Hardware Errors (256) in the analyzed period
    if not args.errors_only and points:
        # Sort by time to find the first occurrence
        points.sort(key=lambda x: x['x'])
        # Convert timestamp (ms) to string
        first_ts = points[0]['x'] / 1000
        time_str = datetime.fromtimestamp(first_ts).strftime('%Y-%m-%d %H:%M:%S')
        ALERTS.append(f"CRITICAL: Hardware Hardware Error (256) detected at {time_str}")

    # Process Analysis Results

    # Calculate cutoff for Hourly Alerts (Current Time - 70 minutes)
    current_ms = datetime.now().timestamp() * 1000
    recency_cutoff_ms = current_ms - (70 * 60 * 1000)

    for b in bands:
        d = b['details']
        status = d['status']

        # Calculate duration in minutes (timestamps are in milliseconds)
        duration_mins = (b['to'] - b['from']) / 60000.0

        # Define vol/flow safely once for all branches (matches original logic)
        vol = d.get('vol', 0)
        flow = d.get('flow', 0)

        # Handle Leak Formatting
        if status == 'LEAK':
            log_output += f"!!! LEAK DETECTED !!! {d['start_str']} | {duration_mins:.0f} min | Flow Floor: {d.get('flow',0)/100:.1f} LPM\n"
            # Add to alerts list if it was a significant leak yesterday
            if not args.errors_only and duration_mins > 120: # Only alert on big ones in the summary
                ALERTS.append(f"Daily Report: Significant Leak ({duration_mins:.0f} min) detected yesterday at {d['start_str']}")
        else:
            # Standard Irrigation Log
            log_output += f"[{d['name']}] {d['start_str']} | {duration_mins:.1f} min | {status} | {vol:.0f}L | {flow} LPM\n"                        
        # Updated format with duration
        #log_output += f"[{d['name']}] {d['start_str']} | {duration_mins:.1f} min | {status} | {d['vol']:.0f}L | {d['flow']} LPM\n"
        
        # Add High Priority statuses to Alert list
        if status in ['LEAK', 'BURST', 'CRITICAL', 'DATA LOSS']:
            # Recency Filter: In Hourly mode, skip alerts older than 70 mins
            if args.errors_only and b['to'] < recency_cutoff_ms:
                continue

            ALERTS.append(f"{status}: {d['name']} ({d['msg']})")

    conn.close()

    # 3. Decision: To Send or Not to Send
    should_send = False
    subject = ""
    body = ""

    if args.errors_only:
        # Hourly Check: Only send if we found NEW alerts
        if ALERTS:
            should_send = True
            subject = f"⚠️ CRITICAL: Water Issues ({len(ALERTS)})⚠️"
            body = "ALERTS:\n" + "\n".join(ALERTS)
            body += "\n\nRecent Activity Log:\n" + log_output
    else:
        # Daily Check: Always send summary
        should_send = True
        status_str = "Issues Detected ⚠️" if ALERTS else "Normal"
        subject = f"Daily Water: {yest_liters:.0f}L - {status_str}"
        body = f"Total Daily Consumption: {yest_liters:.0f} Liters\n\n"
        if ALERTS:
            body += "ISSUES DETECTED:\n" + "\n".join(ALERTS) + "\n\n"
        else:
            body += "System Status: Green\n\n"
        body += "IRRIGATION LOG (Yesterday):\n" + "-"*30 + "\n" + log_output

    if should_send:
        send_email(subject, body)
    else:
        LOGGER.info("No anomalies found. Silent mode.")
