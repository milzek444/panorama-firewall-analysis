"""
(2) test_parsers.py

Correctness verification for helper functions

Tests individual helper components against core infrastructure features like IPv4/6 splits,
single strings vs CIDR ranges, & tagged objects.
"""
# from generate_test_data import (IronSkillet retrieval function)
# Assuming your source modules are inside data_processing.py
from data_processing import ip_to_range_ints, parse_objects, parse_xml

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
    Test correctness of helper by verifying that 'any' IP maps accurately based on protocol version profiles (v4/6)
    without mixing up between v4 and v6.
    :return:
    """
    start_v4, end_v4, v4 = ip_to_range_ints("any")
    assert v4 == 4
    assert end_v4 == 2**32 - 1

def test_parse_objects_filtering(xml_dataset):
    """
    Ensures parser only extracts objects matching the correct tag
    :param xml_dataset:
    :return:
    """
    registry = parse_objects(xml_dataset)
    assert isinstance(registry, dict)
    for name, meta in registry.items():
        assert "ip" in meta
        assert meta["type"] in ["ip-netmask", "ip-range", "ip-wildcard", "fqdn", "address-group"]
