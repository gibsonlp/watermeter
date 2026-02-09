"""
core/database.py
----------------
Handles database connection creation.
"""

import mysql.connector
from config import get_db_config, logger

def get_connection():
    """Creates and returns a new MySQL database connection."""
    try:
        cfg = get_db_config()
        return mysql.connector.connect(**cfg)
    except mysql.connector.Error as err:
        logger.error(f"Database Connection Failed: {err}")
        raise
