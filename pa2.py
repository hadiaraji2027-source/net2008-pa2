# Name: Hadi  Student ID: 041152449
"""Audit network-device XML inventory against a YAML policy."""

import json
import sys
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET

import yaml


class InputFileError(Exception):
    """An input path is unreadable or its contents cannot be parsed."""


class Device:
    """Represent one device and its interfaces from the inventory."""

    def __init__(self, element):
        """Read identifying fields, owner, and interface statuses."""
        self.id = element.get("id")
        self.role = element.get("role", "")
        self.os = element.get("os", "")
        self.owner = (element.findtext("owner") or "").strip()
        self.statuses = [interface.get("status", "") for interface in element.findall("interface")]

    def count_status(self, status):
        """Count interfaces with the requested exact status."""
        return self.statuses.count(status)


def read_xml(path):
    """Parse XML, wrapping input errors with the originating filename."""
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise InputFileError(f"{path}: {exc}") from exc


def read_policy(path):
    """Load YAML safely and accept empty files as disabled policies."""
    try:
        with Path(path).open(encoding="utf-8") as stream:
            policy = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise InputFileError(f"{path}: {exc}") from exc
    if policy is None:
        return {}
    if not isinstance(policy, dict):
        raise InputFileError(f"{path}: policy must be a YAML mapping")
    return policy


def version_parts(version):
    """Convert a dotted version to a list of numeric parts."""
    return [int(part) for part in str(version).split(".")]


def is_older(found, required):
    """Compare versions numerically, treating missing trailing parts as zero."""
    left, right = version_parts(found), version_parts(required)
    width = max(len(left), len(right))
    left += [0] * (width - len(left))
    right += [0] * (width - len(right))
    return left < right


def check_device(device, policy):
    """Return policy violations for one device."""
    issues = []
    if "min_os" in policy and device.role not in policy["min_os"]:
        issues.append({"device": device.id, "type": "unknown_role", "role": device.role})
    if "min_os" in policy and device.role in policy["min_os"]:
        required = str(policy["min_os"][device.role])
        if is_older(device.os, required):
            issues.append({"device": device.id, "type": "os_outdated",
                           "found": device.os, "required": required})
    if policy.get("require_owner") is True and not device.owner:
        issues.append({"device": device.id, "type": "missing_owner"})
    if "max_down_interfaces" in policy:
        down = device.count_status("down")
        if down > policy["max_down_interfaces"]:
            issues.append({"device": device.id, "type": "too_many_down", "down": down})
    return issues


def make_report(root, policy):
    """Count kept devices, roles, and interface states."""
    report = {
        "site": root.get("site"),
        "total_devices": 0,
        "skipped_devices": 0,
        "roles": {},
        "interfaces": {"up": 0, "down": 0, "other": 0},
        "violations": [],
        "compliant": [],
    }
    roles = Counter()
    for element in root.findall("device"):
        device = Device(element)
        if not device.id:
            report["skipped_devices"] += 1
            continue
        report["total_devices"] += 1
        roles[device.role] += 1
        for status in device.statuses:
            key = status if status in ("up", "down") else "other"
            report["interfaces"][key] += 1
        issues = check_device(device, policy)
        report["violations"].extend(issues)
        if not issues:
            report["compliant"].append(device.id)
    report["roles"] = dict(roles)
    report["compliant"].sort()
    return report


def main():
    """Validate CLI input, write a report, and return an exit status."""
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        return 2
    xml_path, policy_path = sys.argv[1:]
    try:
        root = read_xml(xml_path)
        policy = read_policy(policy_path)
        report = make_report(root, policy)
        with Path("audit.json").open("w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
    except InputFileError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Audited {report['total_devices']} devices; {len(report['violations'])} violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
