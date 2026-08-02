"""
data_processing.py

This module provides reusable utility functions that conduct  parsing, validating and preprocessing
on firewall XML configuration and CSV traffic data prior to main  analysis

"""


def parse_xml():
    """
    Parses the Panorama XML running configuration and extracts relevant firewall policy and configuration data.
    :param: xml file
    :return:
    for P1: all data in format of (protocol, sourceIP, destinationIP, destinationPort, action)
    for P2: all data in format of (protocol, sourceIP, destinationIP, destinationPort, action), and if object is used
    for sourceIP, object's name recorded in panorama (which links to sourceIP)

    and for considering NAT/CIDR:
    NAT: for P1, <nat> tags to be used to translate IPs. NAT is not needed here; NAT is for translating IPs during live
    transmissions, our work is a static configuration review

    CIDR subnets, variable IP & port ranges: python libraries like ipaddress can convert CIDR subnets into ranged
    numerical integers, also consisting of a start and end value.


    """
    print("Calling parse_xml...")

def parse_objects():
    """
    Extracts and processes Panorama objects from the running configuration.
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



