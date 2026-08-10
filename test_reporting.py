"""
(5) test_reporting.py

End-to-end reporting engine verification. Validates that the reporting & remediation class functions
process the outputs from prior phases correctly, verifying risk descriptions, raw Panorama API config payloads, etc.
"""
import pytest
from analysis import PolicyContradiction, ObjectAnomaly, FirewallRule, ReportingRemediationEngine

@pytest.fixture
def mock_anomalies():
    """
    Builds controlled policy flaws to check validation accuracy.
    :return:
    """
    rule_sample = FirewallRule(
        ip_version=4, protocol="tcp",
        src_ip_start=167772161, src_ip_end=167772161,  # 10.0.0.1
        dst_ip_start=3232235777, dst_ip_end=3232235777,
        src_port_start=0, src_port_end=65535,
        dst_port_start=80, dst_port_end=80,
        action="deny", src_expected_identity="CRITICAL-DB-HOST", dst_expected_identity=None,
        src_observed_identity=None, dst_observed_identity=None
        # !!!!! Add firewall_name here too
    )

    con = PolicyContradiction(
        category="Broad Port Exposure",
        perimeter_rule=rule_sample,
        internal_rule=rule_sample,
        description="Perimeter allows unrestricted access to hidden blocks.",
        security_impact="Increases the reachable attack surface of internal components."
    )

    anom = ObjectAnomaly(
        category="Decommissioned Object",
        object_name="CRITICAL-DB-HOST",
        ip_address="10.0.0.1",
        expected_hostname="CRITICAL-DB-HOST",
        observed_hostname=None,
        affected_rules=[rule_sample]
    )
    return [con], [anom]


def test_reporting_engine_output_logic(mock_anomalies):
    """
    Verifies that generated reports correctly display the risk descriptions and XML configuration payloads
    :param mock_anomalies:
    :return:
    """
    contradictions, anomalies = mock_anomalies
    engine = ReportingRemediationEngine(contradictions, anomalies)

    # 1: Verify text report output strings
    report = engine.generate_final_report()
    assert "FIREWALL SECURITY & CONFIGURATION AUDIT REPORT" in report
    assert "Broad Port Exposure" in report
    assert "CRITICAL-DB-HOST" in report

    # 2: Verify generation of clean XML remediation payloads
    xml_payloads = engine.generate_panorama_payloads()
    assert "decommission_cleanup" in xml_payloads

    # Confirm structural authenticity of Panorama API XPath target values
    target_xpath = xml_payloads["decommission_cleanup"][0]
    assert "<delete xpath=" in target_xpath
    assert "@name='CRITICAL-DB-HOST'" in target_xpath