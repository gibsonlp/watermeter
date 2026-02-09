"""
app.py
------
Flask Web Server.
- Serves the Dashboard (index.html)
- Provides Data API (Graphs/Anomalies)
- Provides Shelly API (Irrigation Logging)
"""

import sys
import os
# --- PATH FIX: Ensure we can import from 'core' regardless of how this is run ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
# -------------------------------------------------------------------------------

from flask import Flask, jsonify, request, send_from_directory
from datetime import datetime, timedelta
from core.database import get_connection
from core.logic import analyze_period

app = Flask(__name__, static_folder='static')

@app.route('/')
def index():
    """Serves the main dashboard."""
    return send_from_directory('static', 'index.html')

@app.route('/api/irrigation', methods=['GET'])
def log_irrigation():
    """
    Shelly Integration Endpoint.
    Replaces 'waterrun.php'.
    Usage: /api/irrigation?action=0&line=2 (Start Line 2)
           /api/irrigation?action=1&line=2 (Stop Line 2)
    """
    try:
        action = int(request.args.get('action'))
        line = int(request.args.get('line'))
        
        conn = get_connection()
        cursor = conn.cursor()
        
        if action == 0: # Start
            cursor.execute("INSERT INTO irrigation_tracker (start_time, end_time, line) VALUES (NOW(), NOW(), %s)", (line,))
        elif action == 1: # Stop
            # Update the most recent 'open' run for this line
            cursor.execute("""
                UPDATE irrigation_tracker 
                SET end_time = NOW() 
                WHERE line = %s 
                ORDER BY start_time DESC LIMIT 1
            """, (line,))
            
        conn.commit()
        conn.close()
        return "OK", 200
    except Exception as e:
        return str(e), 500

@app.route('/api/data')
def get_data():
    """
    Data API.
    Returns Flow, Volume, or Anomaly data for the frontend.
    Supported ranges: 24h, 7d, 30d, 1y.
    """
    metric = request.args.get('metric', 'flow')
    range_str = request.args.get('range', '24h')
    
    # Calculate Time Window
    end_dt = datetime.now()
    if range_str == '7d': start_dt = end_dt - timedelta(days=7)
    elif range_str == '30d': start_dt = end_dt - timedelta(days=30)
    elif range_str == '1y': start_dt = end_dt - timedelta(days=365)
    else: start_dt = end_dt - timedelta(hours=24)
    
    # 1. Anomaly / Forensics Data
    if metric == 'anomalies':
        # Performance: Limit complex forensic analysis to 30 days max
        if range_str == '1y': start_dt = end_dt - timedelta(days=30)
        return jsonify(analyze_period(start_dt, end_dt))
        
    # 2. Standard Metrics (Flow/Volume)
    conn = get_connection()
    cursor = conn.cursor()
    
    col = 'dal' if metric == 'volume' else 'clpm'
    
    if range_str == '1y':
        # Downsample for 1 Year view (Group by Hour)
        sql = f"""
            SELECT (UNIX_TIMESTAMP(capture_time) DIV 3600) * 3600 * 1000 as ts, 
                   AVG({col}) / 100 as val
            FROM water_raw_data 
            WHERE capture_time >= %s 
            GROUP BY ts ORDER BY ts
        """
    else:
        # Full Resolution
        sql = f"""
            SELECT UNIX_TIMESTAMP(capture_time) * 1000 as ts, 
                   {col} / 100 as val
            FROM water_raw_data 
            WHERE capture_time >= %s 
            ORDER BY ts
        """
        
    cursor.execute(sql, (start_dt,))
    data = [[row[0], float(row[1])] for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(data)

# -------------------------------------------------------------------------
# NEW: Real-Time & Bath API Endpoints
# -------------------------------------------------------------------------

@app.route('/api/realtime')
def get_realtime():
    """
    Real-Time Status API.
    Returns the absolute latest flow rate and signal time.
    Logic: If the last signal is older than 60 seconds, assume Flow is 0.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Fetch only the very last packet
    cursor.execute("""
        SELECT capture_time, clpm 
        FROM water_raw_data 
        ORDER BY capture_time DESC LIMIT 1
    """)
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'flow': 0.0, 'time_str': 'No Data', 'seconds_ago': -1})

    last_dt = row[0]
    raw_clpm = row[1]
    
    # Calculate staleness
    seconds_ago = (datetime.now() - last_dt).total_seconds()
    
    # Logic: If data is stale (>60s), force flow to 0 (pump stopped / no signal)
    # Otherwise, convert Centiliters/min to Liters/min
    current_flow = (raw_clpm / 100.0) if seconds_ago < 60 else 0.0

    return jsonify({
        'flow': current_flow,
        'ts': last_dt.timestamp(),
        'time_str': last_dt.strftime('%H:%M:%S'),
        'seconds_ago': int(seconds_ago)
    })


@app.route('/bath')
def serve_bath():
    """Serves the standalone Bath Monitor App."""
    return send_from_directory('static', 'bath.html')


@app.route('/api/bath_data')
def get_bath_data():
    """
    Bath Session Logic:
    1. Fetches recent data (last 2 hours).
    2. Detects the current 'Session' by looking for a silence gap > 3 minutes.
    3. Calculates total volume for just this active session.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Fetch raw data for the last 2 hours to analyze session history
    cursor.execute("""
        SELECT UNIX_TIMESTAMP(capture_time), dal, clpm 
        FROM water_raw_data 
        WHERE capture_time >= NOW() - INTERVAL 2 HOUR 
        ORDER BY capture_time ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return jsonify({'vol': 0, 'flow': 0, 'last_seen': 'No Signal'})

    # --- Session Detection Algorithm ---
    # We look for the last time there was a "Silence Gap" (> 180 seconds).
    # The session is defined as everything AFTER that gap.
    GAP_THRESHOLD = 180  # 3 Minutes
    session_start_idx = 0

    for i in range(1, len(rows)):
        prev_ts = rows[i-1][0]
        curr_ts = rows[i][0]
        
        # If the gap between packets > 3 mins, a new session started here
        if (curr_ts - prev_ts) > GAP_THRESHOLD:
            session_start_idx = i

    # Slice the data to only include the current session
    session_data = rows[session_start_idx:]
    
    if not session_data:
        return jsonify({'vol': 0, 'flow': 0, 'last_seen': 'Idle'})

    # Calculate Session Stats
    start_dal = session_data[0][1]
    last_row = session_data[-1]
    current_dal = last_row[1]
    last_ts = last_row[0]

    # Volume: Difference between Start DAL and Current DAL (x10 for Liters)
    session_vol = (current_dal - start_dal) * 10.0
    
    # Current Flow: Stale check (>60s = 0 flow)
    seconds_ago = datetime.now().timestamp() - last_ts
    current_flow = (last_row[2] / 100.0) if seconds_ago < 60 else 0.0

    # [FIX] Force Session End if silence > 5 minutes (300s)
    if seconds_ago > 300:
        session_vol = 0.0

    return jsonify({
        'vol': session_vol,
        'flow': current_flow,
        'last_seen': datetime.fromtimestamp(last_ts).strftime('%H:%M:%S')
    })

if __name__ == '__main__':
    # Run listening on all interfaces, Port 8081
    app.run(host='0.0.0.0', port=8081, debug=False)
