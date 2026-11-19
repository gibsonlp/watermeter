"""
services/shelly_monitor.py
--------------------------
Outbound WebSocket RPC daemon for Shelly Pro 3 irrigation tracking.
Connects to ws://<shelly_ip>/rpc so no inbound firewall pinhole is needed.
"""

import json
import logging
import signal
import threading

import websocket
from config import get_shelly_config
from core.database import get_connection

LOGGER = logging.getLogger("ShellyMonitor")
RECONNECT_DELAY = 5
PING_INTERVAL = 30
PING_TIMEOUT = 10


def extract_switch_states(msg):
    """Extract {line_id: is_on} from a Shelly GetStatus or NotifyStatus frame."""
    if not isinstance(msg, dict):
        return {}

    if isinstance(msg.get("result"), dict):
        payload = msg["result"]
    elif msg.get("method") in ("NotifyStatus", "NotifyFullStatus") and isinstance(msg.get("params"), dict):
        payload = msg["params"]
    else:
        return {}

    states = {}
    for key, val in payload.items():
        if key.startswith("switch:") and isinstance(val, dict) and isinstance(val.get("output"), bool):
            try:
                line = int(key.split(":", 1)[1])
            except ValueError:
                continue
            states[line] = val["output"]
    return states


def sync_switch(line, is_on, get_conn=get_connection):
    """Reconcile a switch state with open rows in irrigation_tracker. Returns True if DB changed."""
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM irrigation_tracker WHERE line = %s AND end_time IS NULL LIMIT 1",
            (line,),
        )
        has_open = cursor.fetchone() is not None

        if is_on and not has_open:
            cursor.execute(
                "INSERT INTO irrigation_tracker (start_time, end_time, line) VALUES (NOW(), NULL, %s)",
                (line,),
            )
            conn.commit()
            LOGGER.info("Line %d STARTED", line)
            return True

        if not is_on and has_open:
            cursor.execute(
                "UPDATE irrigation_tracker SET end_time = NOW() WHERE line = %s AND end_time IS NULL",
                (line,),
            )
            conn.commit()
            LOGGER.info("Line %d STOPPED", line)
            return True

        return False
    finally:
        conn.close()


def run_monitor():
    cfg = get_shelly_config()
    if not cfg["enabled"] or not cfg["ip"]:
        LOGGER.warning("Shelly monitor disabled or IP not configured. Exiting.")
        return

    url = f"ws://{cfg['ip']}/rpc"
    websocket.setdefaulttimeout(PING_TIMEOUT)

    stop_event = threading.Event()
    active_ws = [None]

    def handle_signal(signum, _frame):
        LOGGER.info("Received signal %s, shutting down.", signum)
        stop_event.set()
        if active_ws[0] is not None:
            active_ws[0].close()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    LOGGER.info("Starting Shelly WebSocket monitor -> %s", url)

    while not stop_event.is_set():
        last_state = {}

        def on_open(ws):
            LOGGER.info("Connected to %s", url)
            # Sending one RPC with `src` subscribes this socket to NotifyStatus pushes.
            ws.send(json.dumps({"id": 1, "src": "water_analyzer", "method": "Shelly.GetStatus"}))

        def on_message(ws, raw):
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                LOGGER.warning("Ignoring non-JSON frame")
                return

            states = extract_switch_states(msg)
            for line, is_on in sorted(states.items()):
                if line in last_state and last_state[line] == is_on:
                    continue
                try:
                    sync_switch(line, is_on)
                    last_state[line] = is_on
                except Exception as exc:
                    LOGGER.error("DB sync failed for line %d (%s): %s — reconnecting", line, is_on, exc)
                    ws.close()
                    return

        def on_error(_ws, err):
            if not stop_event.is_set():
                LOGGER.error("WebSocket error: %s", err)

        def on_close(_ws, code, reason):
            if not stop_event.is_set():
                LOGGER.warning("Disconnected (code=%s, reason=%s)", code, reason)

        ws = websocket.WebSocketApp(
            url,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )
        active_ws[0] = ws
        ws.run_forever(ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT)
        active_ws[0] = None

        if not stop_event.is_set():
            stop_event.wait(RECONNECT_DELAY)


if __name__ == "__main__":
    run_monitor()
