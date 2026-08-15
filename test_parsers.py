"""
(2) test_parsers.py

Correctness verification for helper functions

Tests individual helper components against core infrastructure features like IPv4/6 splits,
single strings vs CIDR ranges, & tagged objects.
"""
from unittest import mock

import pytest

import data_processing
from data_processing import (ip_to_range_ints, parse_objects, port_to_range_ints, reverse_dns,
                             search_traffic, normalise_firewall_rules, parse_xml)
from generate_test_data import generate_synthetic_xml_and_csv


def test_ip_to_range_ints_ipv4():
    """
    Test correctness of helper by validating structural boundary calculations for classical 32-bit parameters
    :return:
    """
    start, end, version = ip_to_range_ints("192.168.1.1")
    assert version == 4
    assert start == end
    assert start == 3232235777


def test_ip_to_range_ints_ipv6():
    """
    Test correctness of helper by validating structural boundary calculations for full 128-bit fields
    without bit capping overflows
    :return:
    """
    start, end, version = ip_to_range_ints("2001:db8::1")
    assert version == 6
    assert start == end
    assert start > 2**32  # Confirms it scales beyond standard 32-bit limits cleanly


def test_ip_to_range_ints_any_handling():
    """
    Test helper by verifying that 'any' IP maps accurately based on protocol version profiles (v4/6)
    without mixing up between v4 and v6
    :return:
    """
    start_v4, end_v4, v4 = ip_to_range_ints("any")
    assert v4 == 4
    assert end_v4 == 2**32 - 1

def test_parse_objects_filtering():
    """
    Ensures parser only extracts objects matching the correct tag
    :return:
    """
    xml_data, csv_data, truth = generate_synthetic_xml_and_csv(num_rules=50, num_objects=50, flaw_ratio=0.2)
    registry = parse_objects(xml_data)
    assert isinstance(registry, dict)
    for name, meta in registry.items():
        assert "ip" in meta
        assert meta["type"] in ["ip-netmask", "ip-range", "ip-wildcard", "fqdn", "address-group"]


def test_port_to_range_ints_single():
    """
    Proves that a single port maps to an identical start-end pair
    :return:
    """
    start, end = port_to_range_ints("80", "tcp")
    assert start == 80
    assert end == 80


def test_port_to_range_ints_range():
    """
    Validates that a hyphenated port range splits correctly into upper/lower boundaries
    :return:
    """
    start, end = port_to_range_ints("1024-2048", "tcp")
    assert start == 1024
    assert end == 2048


def test_port_to_range_ints_any():
    """
    Validates that an 'any' port for a rule sets a full 16 bit range spectrum
    :return: 
    """
    start, end = port_to_range_ints("any", "tcp")
    assert start == 0
    assert end == 65535


# Re-using parameterised xml_dataset style for policy rules
@pytest.fixture(params=["synthetic_rules"])
def rule_xml_dataset(request):
    return """<config><shared><rulebase><security><rules>
        <entry name="RULE-WEB-ALLOW">
            <source><member>any</member></source>
            <destination><member>10.0.0.1</member></destination>
            <service><member>service-tcp-80</member></service>
            <action>allow</action>
        </entry>
    </rules></security></rulebase></shared></config>"""


def test_parse_xml_policies_structure(rule_xml_dataset):
    """
    Ensures raw policy properties are accurately read into flat list dictionary structures
    :param rule_xml_dataset:
    :return:
    """
    raw_rules = parse_xml(rule_xml_dataset)
    assert isinstance(raw_rules, list)
    assert len(raw_rules) > 0

    first_rule = raw_rules[0]
    assert "name" in first_rule
    assert "sources" in first_rule
    assert "destinations" in first_rule
    assert "dst_ports" in first_rule
    assert "action" in first_rule


def test_reverse_dns_lookup_success():
    """
    Verifies that active IP addresses populate the runtime cache upon lookup resolution
    :return:
    """
    # Use "mock" to simulate a successful DNS resolve
    with mock.patch('socket.gethostbyaddr', return_value=("dc01.campus.edu", [], ["10.0.0.10"])):
        # Clear the global DNS cache element to allow for isolated evaluation
        data_processing.dns_cache.pop("10.0.0.10", None)

        hostname = reverse_dns("10.0.0.10")
        assert hostname == "dc01.campus.edu"


def test_reverse_dns_lookup_failure_cached():
    """
    Ensures failed DNS tracking lookups return None and use the cache without hanging loops
    :return:
    """
    import socket
    with mock.patch('socket.gethostbyaddr', side_effect=socket.herror):
        hostname = reverse_dns("192.0.2.1")
        assert hostname is None


def test_search_traffic_logs_match():
    """
    Validates structural matching of log text matrices using string rows
    :return:
    """
    mock_csv_data = "Source address,Destination address,Source User,Destination User\n10.0.0.5,192.168.1.20,ITSERV-ADMIN,None"

    # Target match check
    found, obj_name = search_traffic(mock_csv_data, "10.0.0.5")
    assert found is True
    assert obj_name == "ITSERV-ADMIN"


def test_search_traffic_logs_miss():
    """
    Validates negative mismatch states return False and empty descriptors
    :return:
    """
    mock_csv_data = "Source address,Destination address,Source User,Destination User\n10.0.0.5,192.168.1.20,ITSERV-ADMIN,None"

    found, obj_name = search_traffic(mock_csv_data, "172.16.0.1")
    assert found is False
    assert obj_name is None


def test_normalise_firewall_rules_mapping():
    """
    Confirms rule text variables are correctly transformed into standardised FirewallRule instances
    :return:
    """
    mock_raw_rules = [{
        "name": "Test-Rule",
        "protocol": "tcp",
        "sources": ["any"],
        "destinations": ["SERVER-OBJ"],
        "src_ports": ["any"],
        "dst_ports": ["80"],
        "action": "allow"
    }]

    mock_objects_registry = {
        "SERVER-OBJ": {"ip": "192.168.1.50", "type": "ip-netmask"}
    }

    normalised = normalise_firewall_rules(mock_raw_rules, mock_objects_registry)
    assert len(normalised) == 1

    rule_obj = normalised[0]
    assert rule_obj.ip_version == 4
    assert rule_obj.action == "allow"
    assert rule_obj.dst_expected_identity == "SERVER-OBJ"
    assert rule_obj.dst_ip_start == 3232235826  # Integer version of 192.168.1.50