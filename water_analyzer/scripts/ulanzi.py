"""
scripts/ulanzi.py
-----------------
Background worker to sync Water Monitor with Ulanzi/Awtrix Clock.
Display: Toggles between "120 L" (Volume) and "12 LPM" (Flow) every 5 seconds.
"""

import time
import requests
import logging
from config import get_ulanzi_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [Ulanzi] %(message)s')
LOGGER = logging.getLogger("Ulanzi")

def update_ulanzi():
    cfg = get_ulanzi_config()
    if not cfg['enabled']:
        LOGGER.warning("Ulanzi disabled in config. Exiting.")
        return

    APP_NAME = "bath"
    BASE_URL = f"http://{cfg['ip']}/api"
    DATA_SOURCE = cfg['api_url']  # [UPDATED] Read from config
    
    was_active = False
    LOGGER.info(f"Starting Ulanzi Sync -> {cfg['ip']} (Source: {DATA_SOURCE})")

    while True:
        try:
            # 1. Fetch Data
            try:
                r = requests.get(DATA_SOURCE, timeout=2)
                data = r.json()
            except Exception as e:
                LOGGER.error(f"Failed to fetch local data: {e}")
                time.sleep(5)
                continue

            vol = data.get('vol', 0.0)
            flow = data.get('flow', 0.0)
            is_active = (vol > 0 or flow > 0)

            if is_active:
                # Turn Screen ON if this is the start of the session
                if not was_active:
                    requests.post(f"{BASE_URL}/power", json={"power": True}, timeout=1)
                was_active = True
                
                # [NEW] Toggle Logic (Every 5 seconds)
                # epoch // 5 increments every 5 seconds.
                # % 2 gives us 0 or 1.
                toggle_mode = int(time.time() / 5) % 2
                
                if toggle_mode == 0:
                    # Mode 0: Show Volume
                    display_text = f"{vol:.0f} L"
                else:
                    # Mode 1: Show Flow
                    display_text = f"{flow:.1f}/m" # 'm' for /min to save space

                # Icon Logic
                icon = cfg['icon_anim'] if flow > 0 else cfg['icon_static']
                
                payload = {
                    "text": display_text,
                    "icon": icon,
                    "color": cfg['color'],
                    "pushIcon": 2,
                    "lifetime": 10
                }

                # Update Custom App
                requests.post(f"{BASE_URL}/custom?name={APP_NAME}", json=payload, timeout=1)
                
                # Force Switch (Keep visible)
                requests.post(f"{BASE_URL}/switch", json={"name": APP_NAME}, timeout=1)

            else:
                if was_active:
                    LOGGER.info("Session ended. Removing Ulanzi app.")
                    requests.post(f"{BASE_URL}/custom?name={APP_NAME}", json={}, timeout=1)
                    was_active = False

        except Exception as e:
            LOGGER.error(f"Loop error: {e}")

        time.sleep(cfg['update_interval'])

if __name__ == "__main__":
    update_ulanzi()
