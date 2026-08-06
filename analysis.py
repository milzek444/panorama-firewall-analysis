"""
analysis.py

This module contains the primary methods for inter-firewall policy analysis and Panorama configuration analysis
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from collections import defaultdict
from data_processing import FirewallRule

@dataclass
class PolicyContradiction:
    category: str  # "Broad Port Exposure", "Subnet Contradiction", etc.
    perimeter_rule: FirewallRule   # the perimeter & internal rule (below) which contradict each other
    internal_rule: FirewallRule
    description: str   # description of the contradiction
    security_impact: str

@dataclass
class ObjectAnomaly:
    category: str  # One of two; "Decommissioned Object", "IP Reuse Mismatch"
    object_name: str
    ip_address: str
    expected_hostname: str  # the name present in XML for that object
    observed_hostname: str | None  # the name present in CSV traffic logs / DNS resolve
    affected_rules: list[FirewallRule] = field(default_factory=list)