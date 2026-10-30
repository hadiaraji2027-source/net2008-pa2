"""Test the auditor against the project-brief example and edge cases."""

import unittest
import xml.etree.ElementTree as ET

from pa2 import is_older, make_report

SAMPLE = '''<inventory site="ott-dc1">
<device id="sw-core-01" role="switch" os="15.10"><owner>netops</owner>
<interface status="up"/><interface status="up"/><interface status="down"/></device>
<device id="sw-edge-02" role="switch" os="15.2"><interface status="up"/><interface status="down"/></device>
<device id="rt-wan-01" role="router" os="17.3"><owner>netops</owner>
<interface status="up"/><interface status="down"/><interface status="down"/><interface status="admin-down"/></device>
<device id="fw-dmz-01" role="firewall" os="9.1.0"><owner>secops</owner><interface status="up"/></device>
<device id="lb-web-01" role="load-balancer" os="4.2"><owner>netops</owner><interface status="up"/></device>
<device role="switch" os="15.2"><owner>netops</owner></device></inventory>'''
POLICY = {"min_os": {"switch": "15.2", "router": "17.3.1", "firewall": "9.1"},
          "require_owner": True, "max_down_interfaces": 1}


class AuditTests(unittest.TestCase):
    """Check device accounting, violation rules, and version ordering."""

    def test_sample(self):
        """Reproduce the exact brief totals and compliance decisions."""
        result = make_report(ET.fromstring(SAMPLE), POLICY)
        self.assertEqual(result["site"], "ott-dc1")
        self.assertEqual((result["total_devices"], result["skipped_devices"]), (5, 1))
        self.assertEqual(result["roles"], {"switch": 2, "router": 1, "firewall": 1, "load-balancer": 1})
        self.assertEqual(result["interfaces"], {"up": 6, "down": 4, "other": 1})
        self.assertEqual(result["compliant"], ["fw-dmz-01", "sw-core-01"])
        self.assertEqual({v["type"] for v in result["violations"]},
                         {"missing_owner", "os_outdated", "too_many_down", "unknown_role"})
        self.assertEqual(len(result["violations"]), 4)

    def test_numeric_versions(self):
        """Check versions that compare incorrectly as strings."""
        self.assertFalse(is_older("15.10", "15.2"))
        self.assertFalse(is_older("9.1.0", "9.1"))
        self.assertTrue(is_older("17.3", "17.3.1"))

    def test_empty_inputs(self):
        """An empty inventory and disabled policy produce valid totals."""
        result = make_report(ET.fromstring("<inventory />"), {})
        self.assertEqual(result["total_devices"], 0)
        self.assertEqual(result["site"], None)
        self.assertEqual(result["violations"], [])

    def test_missing_policy_keys(self):
        """Absent checks stay disabled."""
        result = make_report(ET.fromstring(SAMPLE), {})
        self.assertEqual(result["violations"], [])
        self.assertEqual(len(result["compliant"]), 5)


if __name__ == "__main__":
    unittest.main()
