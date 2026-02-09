"""
core/logic.py
-------------
Shared logic engine for Water Monitor.
Contains the 'analyze_period' function which correlates Irrigation Runs
with Raw Water Data to detect leaks, bursts, and clogs.
"""

from config import get_line_rules
from core.database import get_connection
from datetime import datetime

def detect_leaks(raw_data, irrigation_bands):
    """
    Scans for continuous flow > 0 during non-irrigation periods.
    Threshold: > 60 minutes of continuous flow.
    Gap Rule: If data gap > 2 mins, assume flow stopped (Zero).
    """
    leaks = []
    
    irrigation_intervals = []
    for b in irrigation_bands:
        irrigation_intervals.append((b['from'], b['to']))
    
    potential_start = None
    min_flow_in_run = None
    last_ts = 0
    
    for i, row in enumerate(raw_data):
        ts_ms = row['ts'] * 1000
        clpm = row['clpm']
        
        # Gap Detection (> 2 mins)
        if i > 0:
            prev_ts = raw_data[i-1]['ts'] * 1000
            if (ts_ms - prev_ts) > 120000:
                if potential_start is not None:
                    duration_mins = (last_ts - potential_start) / 60000.0
                    if duration_mins > 60:
                        flow_lpm = min_flow_in_run / 100.0
                        total_leak = flow_lpm * duration_mins
                        leaks.append({
                            'from': potential_start,
                            'to': last_ts,
                            'color': 'rgba(255, 0, 0, 0.3)',
                            'label': {'text': 'LEAK', 'style': {'color': '#ff0000', 'fontWeight': 'bold'}},
                            'details': {
                                'name': 'Suspected Leak',
                                'start_str': datetime.fromtimestamp(potential_start/1000).strftime('%H:%M'),
                                'vol': total_leak,   # [UPDATED] Estimated Volume
                                'flow': flow_lpm,
                                'status': 'LEAK',
                                'msg': f"Stable base flow detected for {int(duration_mins)} min" # [UPDATED] Fixes 'undefined'
                            }
                        })
                potential_start = None
                min_flow_in_run = None

        # Check Irrigation
        is_irrigating = False
        for start, end in irrigation_intervals:
            if start <= ts_ms <= end:
                is_irrigating = True
                break
        
        # Leak Logic
        if clpm > 0 and not is_irrigating:
            if potential_start is None:
                potential_start = ts_ms
                min_flow_in_run = clpm
            else:
                if clpm < min_flow_in_run: min_flow_in_run = clpm
            last_ts = ts_ms
        else:
            if potential_start is not None:
                duration_mins = (last_ts - potential_start) / 60000.0
                if duration_mins > 60:
                    flow_lpm = min_flow_in_run / 100.0
                    total_leak = flow_lpm * duration_mins
                    leaks.append({
                        'from': potential_start,
                        'to': last_ts,
                        'color': 'rgba(255, 0, 0, 0.3)',
                        'label': {'text': 'LEAK', 'style': {'color': '#ff0000', 'fontWeight': 'bold'}},
                        'details': {
                            'name': 'Suspected Leak',
                            'start_str': datetime.fromtimestamp(potential_start/1000).strftime('%H:%M'),
                            'vol': total_leak,
                            'flow': flow_lpm,
                            'status': 'LEAK',
                            'msg': f"Stable base flow detected for {int(duration_mins)} min"
                        }
                    })
                potential_start = None
                min_flow_in_run = None

    # Handle ongoing leak
    if potential_start is not None:
        duration_mins = (last_ts - potential_start) / 60000.0
        if duration_mins > 60:
            flow_lpm = min_flow_in_run / 100.0
            total_leak = flow_lpm * duration_mins
            leaks.append({
                'from': potential_start,
                'to': last_ts,
                'color': 'rgba(255, 0, 0, 0.3)',
                'label': {'text': 'ONGOING LEAK', 'style': {'color': '#ff0000'}},
                'details': {
                    'name': 'Suspected Leak', 
                    'start_str': datetime.fromtimestamp(potential_start/1000).strftime('%H:%M'),
                    'vol': total_leak,
                    'flow': flow_lpm,
                    'status': 'LEAK',
                    'msg': f"Ongoing continuous flow ({int(duration_mins)} min)"
                }
            })
            
    return leaks

def analyze_period(start_dt, end_dt):
    """
    Analyzes a specific time range for anomalies.
    
    Algorithm:
    1. Fetches all Irrigation Runs in the window.
    2. Fetches all Raw Water Data (buffered by +/- 5 mins).
    3. Uses an in-memory sequential scan (O(N)) to correlate data without
       expensive SQL joins.
    4. Applies 'Isolation Checks' (Noise Detection) for sensitive lines.
    
    Returns:
        dict: {
            'plotBands': [List of runs with status/color],
            'points': [List of specific error points (Red Dots)]
        }
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    rules = get_line_rules()
    
    # 1. Fetch Irrigation Runs
    cursor.execute("""
        SELECT id, line, start_time, end_time 
        FROM irrigation_tracker 
        WHERE start_time >= %s AND start_time <= %s
        ORDER BY start_time ASC
    """, (start_dt, end_dt))
    runs = cursor.fetchall()

    # 2. Fetch Water Data (Buffer -5 mins for isolation check)
    cursor.execute("""
        SELECT UNIX_TIMESTAMP(capture_time) as ts, dal, clpm, error_codes 
        FROM water_raw_data 
        WHERE capture_time >= %s - INTERVAL 5 MINUTE 
          AND capture_time <= %s + INTERVAL 5 MINUTE
        ORDER BY capture_time ASC
    """, (start_dt, end_dt))
    water_data = cursor.fetchall()
    conn.close()

    plot_bands = []
    points = []
    
    # Pointers for optimization
    w_idx = 0
    w_count = len(water_data)

    for run in runs:
        line_id = run['line']
        r_start = int(run['start_time'].timestamp())
        if run['end_time'] is None:
            r_end = int(time.time()) # If active, assume it ends "NOW"
        else:
            r_end = int(run['end_time'].timestamp())

        # Fallback rule if line is not in config
        rule = rules.get(line_id, {
            'name': f'Line {line_id}', 
            'limit_vol': 1000, 
            'limit_flow': 50, 
            'isolation': False
        })

        # --- In-Memory Scanner ---
        min_dal = None
        max_dal = None
        max_flow_cl = 0
        err_mask = 0
        pre_noise = 0
        post_noise = 0
        has_data = False

        #  Counters for 90% Threshold Logic
        samples_total = 0
        samples_over_limit = 0
        limit_clpm = rule['limit_flow'] * 100  # Pre-calculate limit in Centiliters
        
        # 1. Fast-forward pointer to 5 mins BEFORE run
        buffer_start = r_start - 300
        while w_idx < w_count and water_data[w_idx]['ts'] < buffer_start:
            w_idx += 1
            
        # 2. Scan forward (using a temp pointer to avoid rescanning)
        scan_idx = w_idx
        while scan_idx < w_count:
            row = water_data[scan_idx]
            ts = row['ts']
            
            # Stop if we are past the post-run buffer
            if ts > r_end + 300: break 
            
            # A. Pre-Run Noise (Isolation Check)
            if buffer_start <= ts < r_start:
                pre_noise += row['clpm']
            
            # B. Post-Run Noise (Isolation Check)
            elif r_end < ts <= r_end + 300:
                post_noise += row['clpm']
            
            # C. Inside Run Analysis
            elif r_start <= ts <= r_end:
                has_data = True
                if min_dal is None or row['dal'] < min_dal: min_dal = row['dal']
                if max_dal is None or row['dal'] > max_dal: max_dal = row['dal']
                if row['clpm'] > max_flow_cl: max_flow_cl = row['clpm']
                err_mask |= row['error_codes']
                
            scan_idx += 1

        # Calculate Derived Stats
        vol_liters = (max_dal - min_dal) * 10 if (min_dal is not None) else 0
        flow_lpm = max_flow_cl / 100.0
        # Isolation: Less than 1 Liter of noise in buffers
        is_isolated = (pre_noise < 100 and post_noise < 100)

        # Calculate Violation Ratio
        violation_ratio = (samples_over_limit / samples_total) if samples_total > 0 else 0
        
        # --- Decision Logic ---
        status = 'OK'
        msg = f"{rule['name']}: {vol_liters:.0f}L"
        color = 'rgba(74, 222, 128, 0.1)' # Green

        # Priority 1: Data Loss
        if not has_data:
            # We skip data loss warning for Lines with Isolation checks (e.g. Pots) 
            # as they often have 0 flow which might not register if filtered upstream.
            if not rule['isolation']:
                status = 'DATA LOSS'
                msg = "No meter readings found during run"
                color = 'rgba(128, 128, 128, 0.5)' # Grey
                
        # Priority 2: Hardware Error
        elif err_mask & 256:
            status = 'CRITICAL'
            msg = 'Hardware Alarm (Bit 8)'
            color = 'rgba(255, 99, 71, 0.6)' # Red
            
        # Priority 3: Volume Limit
        elif vol_liters > rule['limit_vol']:
            status = 'LEAK'
            msg = f"Excessive Volume ({vol_liters:.0f}L > {rule['limit_vol']}L)"
            color = 'rgba(255, 165, 0, 0.5)' # Orange
            
        # Priority 4: Flow Limit
        # We only flag BURST if >90% of samples are over the limit
        elif flow_lpm > rule['limit_flow'] and violation_ratio > 0.90:
             if rule['isolation']:
                if is_isolated:
                    status = 'BURST'
                    msg = f"Confirmed Burst (Isolated) | {violation_ratio*100:.0f}% samples > limit"
                    color = 'rgba(255, 165, 0, 0.5)'
                else:
                    msg += " [High flow ignored: Noise]"
             else:
                status = 'BURST'
                msg = f"Excessive Flow ({flow_lpm} > {rule['limit_flow']})"
                color = 'rgba(255, 165, 0, 0.5)'
                
        # Priority 5: Clog (Zero Flow)
        elif flow_lpm == 0 and rule['limit_flow'] > 1:
            status = 'CLOG'
            msg = "Valve Failed / No Flow"
            color = 'rgba(128, 128, 128, 0.5)'

        plot_bands.append({
            'id': f'band_{run["id"]}',
            'from': r_start * 1000, 
            'to': r_end * 1000,
            'color': color,
            'details': {
                'line': line_id, 
                'name': rule['name'], 
                'status': status,
                'msg': msg, 
                'vol': vol_liters, 
                'flow': flow_lpm, 
                'start_str': run['start_time'].strftime("%H:%M")
            }
        })

    # --- Global Hardware Scan ---
    # Scans ALL loaded data for Error 256, even outside irrigation runs.
    for row in water_data:
        if row['error_codes'] & 256:
             points.append({
                'x': row['ts'] * 1000, 
                'y': row['clpm'] / 100.0, 
                'title': 'System/Meter: HW Alarm (256)',
                'marker': {'fillColor': '#ff0000', 'radius': 6}
             })
    # Detect Leaks in the remaining space
    leak_bands = detect_leaks(water_data, plot_bands)
    plot_bands.extend(leak_bands)

    # Sort bands by time so they render correctly
    plot_bands.sort(key=lambda x: x['from'])

    return {'plotBands': plot_bands, 'points': points}
