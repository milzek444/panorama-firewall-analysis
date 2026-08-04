"""
data_processing.py

This module provides reusable utility functions that conduct  parsing, validating and preprocessing
on firewall XML configuration and CSV traffic data prior to main  analysis

"""
import ipaddress  # for handling IP addresses
import socket  # for reverse DNS queries
import csv    # for handling traffic logs
from dataclasses import dataclass   # for firewall rule dataclass


@dataclass()
class FirewallRule:
    src_ip_start: int
    src_ip_end: int
    dst_ip_start: int
    dst_ip_end: int
    src_port_start: int
    src_port_end: int
    dst_port_start: int
    dst_port_end: int
    action: str   # allow / deny
    protocol: str
    src_expected_identity: str | None    # from XML, e.g., "Finance-Server"
    src_observed_identity: str | None    # (p2) from reverse DNS, e.g., "finance-01.york.ac.uk"
                                         # if IP is in traffic logs, expected = observed
                                         # else, do reverse DNS, then record that as observed

def ip_to_range_ints(ip_str: str) -> tuple[int, int, int]:
    """
    Converts IP Strings into a pair of integers representing the start and end of the range
    Static single IP addresses have identical start and end values
    :param ip_str: IP address
    :return: (start_integer, end_integer, ip_version), where ip_version is either 4 (ipv4) or 6 (ipv6)
    """
    ip_str = ip_str.strip()
    if not ip_str:  # if the string is blank
        return 0, 0, 4

    is_ipv6 = ":" in ip_str   # check if IPv4 or IPv6
    version = 6 if is_ipv6 else 4
    if is_ipv6:
        max_int = 2**128 - 1
    else:
        max_int = 2**32 - 1

    if ip_str.lower() == "any":
        return 0, max_int, version

    # "-" means ranged IP string. here, get the two integers from start and end of the range.
    if '-' in ip_str:
        try:
            start, end = ip_str.split('-')
            return int(ipaddress.ip_address(start.strip())), int(ipaddress.ip_address(end.strip())), version
        except ValueError:   # invalid arg value but correct data type
            pass

    try:  # Convert IP into a network object and convert the first and last IPs into integers
        net = ipaddress.ip_network(ip_str, strict=False)
        return int(net.network_address), int(net.broadcast_address), version
        # single IP addresses have identical network and broadcast addresses
    except ValueError:
        return 0, 0, version


def port_to_range_ints(port_str: str) -> tuple[int, int]:
    """
    Converts a port string or range into a pair of integers representing the start and end of the range
    Single port values have identical start and end values
    :param port_str: the port value or range
    :return: (start_port, end_port)
    """


def parse_xml():
    """
    Parses the Panorama XML running configuration and extracts relevant firewall policy and configuration data.
    :param: xml file
    :return:
    for P1: all data in format of (protocol, sourceIP, destinationIP, destinationPort, action)
    for P2: all data in format of (protocol, sourceIP, destinationIP, destinationPort, action), and if object is used
    for sourceIP, object's name recorded in panorama (which links to sourceIP)

    and for considering CIDR:

    CIDR subnets, variable IP & port ranges: python libraries like ipaddress can convert CIDR subnets into ranged
    numerical integers, also consisting of a start and end value.
    """

    print("Calling parse_xml...")

def parse_objects():
    """
    Extracts and processes Address objects & Address Group objects from the running configuration.
    :param: XML File
    :return: List of all objects that fit the required tags, + their required info: IP, etc.
    """
    print("Calling parse_objects...")

def search_traffic():
    """
    Searches through firewall traffic log CSV data to identify recent activity associated with objects.
    :param: CSV file, IP from some given tuple
    :return: return if IP is present (True/False) + if IP is present, the observed identity
    """
    print("Calling search_traffic...")

def reverse_dns():
    """
    Performs reverse DNS lookups to resolve IP addresses to their corresponding hostnames for validation.
    :param: object IP (for IPs not present in traffic)
    :return: object name (observed identity)
    """
    print("Calling reverse_dns...")

def normalise_policy():
    """
    Normalises given firewall data into a consistent tuple format suitable for automated comparison
    and analysis.
    :param: for a given rule:
    (p1) source IP+dest IP, protocol, source+dest port, action
    (p2) source IP, expected identity from XML, observed identity from CSV/DNS, dest IP, dest port
    ** must account for ranged IPs/ports too
    :return: policy tree units, all of these organised into a tuple,
    + for p2: where source IP is paired with object name
    """
    print("Calling normalise_policy...")



