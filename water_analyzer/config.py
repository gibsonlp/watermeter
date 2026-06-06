"""
config.py
---------
Central configuration loader for the Water Monitor system.
Reads the legacy 'water_analyzer.conf' file and provides structured access
to database, email, and analysis settings for all modules.
"""

import os
import configparser
import logging

# Paths: Default to /etc, fallback to local directory for development
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_FILE = "/etc/water_analyzer/water_analyzer.conf"       # EDIT ME

if not os.path.exists(CONF_FILE):
    CONF_FILE = os.path.join(BASE_DIR, "water_analyzer.conf")

# Initialize Config Parser
config = configparser.ConfigParser()
if os.path.exists(CONF_FILE):
    config.read(CONF_FILE)
else:
    print(f"WARNING: Configuration file not found at {CONF_FILE}")

# Central Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("WaterMonitor")

def get_db_config():
    """Returns database connection parameters."""
    return {
        'host': config.get('Database', 'host', fallback='localhost'),
        'user': config.get('Database', 'username', fallback='root'),
        'password': config.get('Database', 'password', fallback=''),
        'database': config.get('Database', 'db', fallback='sniffler')
    }

def get_email_config():
    """Returns email server settings."""
    return {
        'enabled': config.getboolean('Email', 'enabled', fallback=False),
        'host': config.get('Email', 'smtp_host', fallback=''),
        'port': config.getint('Email', 'smtp_port', fallback=25),
        'ssl': config.getboolean('Email', 'smtp_ssl', fallback=True),
        'user': config.get('Email', 'smtp_user', fallback=''),
        'pass': config.get('Email', 'smtp_pass', fallback=''),
        'from': config.get('Email', 'from_addr', fallback=''),
        'to': config.get('Email', 'to_addr', fallback='')
    }

def get_line_rules():
    """
    Dynamically parses [Line_X] sections from the config file.
    Returns a dictionary of rules keyed by Line ID.
    
    Converts:
        - limit_dal (Dekaliters) -> Liters (x10)
        - limit_flow (cL/min)    -> LPM (x100)
    """
    rules = {}
    for section in config.sections():
        if section.lower().startswith("line_"):
            try:
                # Extract Line ID (e.g., "Line_0" -> 0)
                line_id = int(section.split("_")[1])
                rules[line_id] = {
                    "name": config.get(section, 'name', fallback=f"Line {line_id}"),
                    "limit_vol": config.getfloat(section, 'limit_dal', fallback=100) * 10,
                    "limit_flow": config.getfloat(section, 'limit_flow', fallback=5000) / 10,
                    "isolation": config.getboolean(section, 'isolation_check', fallback=False)
                }
            except ValueError:
                continue
    return rules

def get_analysis_config():
    """Returns global analysis settings."""
    daily_limit = config.getfloat('Analysis', 'daily_leak_limit_liters', fallback=1500)
    return {
        'enable_monitoring': config.getboolean('Analysis', 'enable_line_monitoring', fallback=True),
        'daily_limit': daily_limit,
        'household_limit': config.getfloat('Analysis', 'daily_household_limit_liters', fallback=daily_limit)
    }

def get_ulanzi_config():
    """Parses the [Ulanzi] section from the config file."""
    config = configparser.ConfigParser()
    config.read(CONF_FILE)
    
    # Default to port 81, but allow override
    defaults = {
        'enabled': False,
        'ip': '192.168.5.147',
        'api_url': 'http://127.0.0.1:81/api/bath_data',
        'update_interval': 1,
        'color': [0, 150, 255],
        'icon_static': "8990",
        'icon_anim': "55027"
    }

    if 'Ulanzi' not in config:
        return defaults

    section = config['Ulanzi']
    
    color_str = section.get('color', '0,150,255')
    try:
        color_list = [int(x.strip()) for x in color_str.split(',')]
    except:
        color_list = [0, 150, 255]

    return {
        'enabled': section.getboolean('enabled', fallback=True),
        'ip': section.get('ip', fallback='192.168.5.147'),
        'api_url': section.get('api_url', fallback=defaults['api_url']),
        'update_interval': section.getint('update_interval', fallback=1),
        'color': color_list,
        'icon_static': section.get('icon_static', fallback="8990"),
        'icon_anim': section.get('icon_anim', fallback="55027")
    }
