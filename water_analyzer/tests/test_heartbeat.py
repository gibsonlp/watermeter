"""Unit tests for meter_status heartbeat updates in services.ingester."""

import os
import sys
import types
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

mysql_mod = types.ModuleType("mysql")
mysql_conn_mod = types.ModuleType("mysql.connector")
mysql_conn_mod.MySQLConnection = object
mysql_conn_mod.Error = Exception
mysql_mod.connector = mysql_conn_mod
sys.modules.setdefault("mysql", mysql_mod)
sys.modules.setdefault("mysql.connector", mysql_conn_mod)

scapy_mod = types.ModuleType("scapy")
scapy_all = types.ModuleType("scapy.all")
for attr in ("sniff", "Dot11", "Dot11Elt", "PcapReader"):
    setattr(scapy_all, attr, object)
scapy_mod.all = scapy_all
sys.modules.setdefault("scapy", scapy_mod)
sys.modules.setdefault("scapy.all", scapy_all)

from services.ingester import State, update_database  # noqa: E402


class TestMeterStatusHeartbeat(unittest.TestCase):
    def _make_state(self, previous_dal=100, last_update=None):
        conn = MagicMock()
        conn.is_connected.return_value = True
        cursor = conn.cursor.return_value
        state = State(
            serial_num=12345,
            min_update=3600,
            db_config={},
            conn=conn,
            cursor=cursor,
            previous_dal=previous_dal,
            last_update=last_update or datetime.now(),
        )
        return state, conn, cursor

    def test_idle_packet_updates_meter_status_without_touching_raw_or_last_update(self):
        t0 = datetime.now() - timedelta(seconds=30)
        state, conn, cursor = self._make_state(previous_dal=100, last_update=t0)

        wrote_raw = update_database(state, clpm=0, dal=100, error_codes=0, packet=None, pcap_time=False)

        self.assertFalse(wrote_raw)
        self.assertEqual(state.last_update, t0)
        self.assertEqual(cursor.execute.call_count, 1)
        self.assertIn("INSERT INTO meter_status", cursor.execute.call_args[0][0])
        conn.commit.assert_called_once()

    def test_hourly_heartbeat_writes_both_raw_and_meter_status(self):
        t0 = datetime.now() - timedelta(seconds=3605)
        state, conn, cursor = self._make_state(previous_dal=100, last_update=t0)

        wrote_raw = update_database(state, clpm=0, dal=100, error_codes=0, packet=None, pcap_time=False)

        self.assertTrue(wrote_raw)
        self.assertGreater(state.last_update, t0)
        sqls = [call[0][0] for call in cursor.execute.call_args_list]
        self.assertEqual(len(sqls), 2)
        self.assertIn("INSERT IGNORE INTO water_raw_data", sqls[0])
        self.assertIn("INSERT INTO meter_status", sqls[1])
        conn.commit.assert_called_once()

    def test_pcap_idle_replay_does_not_touch_meter_status(self):
        t0 = datetime.now() - timedelta(seconds=30)
        state, conn, cursor = self._make_state(previous_dal=100, last_update=t0)

        wrote_raw = update_database(state, clpm=0, dal=100, error_codes=0, packet=None, pcap_time=True)

        self.assertFalse(wrote_raw)
        cursor.execute.assert_not_called()
        conn.commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
