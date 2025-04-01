import unittest
from bella.api import ApiWrapper


class ApiWrapperTest(unittest.TestCase):

    def test_events(self):
        events = ApiWrapper.get_events(60)
        self.assertIn("ids", events)
        self.assertIn("ips", events)

    def test_arp(self):
        arp = ApiWrapper.get_arp_table()
        self.assertIsInstance(arp, dict)
        for ip, macs in arp.items():
            self.assertRegex(ip, r"(\d{1,3}\.){3}\d{1,3}")
            self.assertIsInstance(macs, list)
            for m in macs:
                self.assertRegex(m, r"^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$")





