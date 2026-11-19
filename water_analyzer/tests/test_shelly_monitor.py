"""Unit tests for services.shelly_monitor."""

import os
import sys
import types
import unittest
from unittest.mock import MagicMock

# Allow running tests without third-party runtime deps installed locally.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.modules.setdefault("websocket", types.ModuleType("websocket"))
mysql_mod = types.ModuleType("mysql")
mysql_conn_mod = types.ModuleType("mysql.connector")
mysql_conn_mod.Error = Exception
mysql_mod.connector = mysql_conn_mod
sys.modules.setdefault("mysql", mysql_mod)
sys.modules.setdefault("mysql.connector", mysql_conn_mod)

from services.shelly_monitor import extract_switch_states, sync_switch  # noqa: E402


class TestExtractSwitchStates(unittest.TestCase):
    def test_get_status_result(self):
        msg = {
            "id": 1,
            "result": {
                "switch:0": {"id": 0, "output": False},
                "switch:1": {"id": 1, "output": True},
                "switch:2": {"id": 2, "output": False},
                "sys": {"uptime": 123},
            },
        }
        self.assertEqual(extract_switch_states(msg), {0: False, 1: True, 2: False})

    def test_notify_status_toggle(self):
        msg = {
            "method": "NotifyStatus",
            "params": {"ts": 1795116500.1, "switch:2": {"id": 2, "output": True}},
        }
        self.assertEqual(extract_switch_states(msg), {2: True})

    def test_notify_status_temperature_only_ignored(self):
        msg = {
            "method": "NotifyStatus",
            "params": {"ts": 1795116560.0, "switch:0": {"id": 0, "temperature": {"tC": 48.1}}},
        }
        self.assertEqual(extract_switch_states(msg), {})

    def test_notify_full_status(self):
        msg = {
            "method": "NotifyFullStatus",
            "params": {"switch:0": {"output": True}},
        }
        self.assertEqual(extract_switch_states(msg), {0: True})

    def test_unrelated_method_ignored(self):
        self.assertEqual(extract_switch_states({"method": "NotifyEvent", "params": {}}), {})


class TestSyncSwitch(unittest.TestCase):
    def _mock_conn(self, open_row):
        conn = MagicMock()
        cursor = conn.cursor.return_value
        cursor.fetchone.return_value = open_row
        return conn, cursor

    def test_start_inserts_when_no_open_row(self):
        conn, cursor = self._mock_conn(None)
        changed = sync_switch(1, True, get_conn=lambda: conn)
        self.assertTrue(changed)
        self.assertIn("INSERT INTO irrigation_tracker", cursor.execute.call_args_list[1][0][0])
        conn.commit.assert_called_once()
        conn.close.assert_called_once()

    def test_start_noop_when_already_open(self):
        conn, cursor = self._mock_conn((42,))
        changed = sync_switch(1, True, get_conn=lambda: conn)
        self.assertFalse(changed)
        self.assertEqual(cursor.execute.call_count, 1)
        conn.commit.assert_not_called()
        conn.close.assert_called_once()

    def test_stop_updates_open_row(self):
        conn, cursor = self._mock_conn((42,))
        changed = sync_switch(2, False, get_conn=lambda: conn)
        self.assertTrue(changed)
        sql = cursor.execute.call_args_list[1][0][0]
        self.assertIn("UPDATE irrigation_tracker", sql)
        self.assertIn("end_time IS NULL", sql)
        conn.commit.assert_called_once()
        conn.close.assert_called_once()

    def test_stop_noop_when_already_closed(self):
        conn, cursor = self._mock_conn(None)
        changed = sync_switch(2, False, get_conn=lambda: conn)
        self.assertFalse(changed)
        self.assertEqual(cursor.execute.call_count, 1)
        conn.commit.assert_not_called()
        conn.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
