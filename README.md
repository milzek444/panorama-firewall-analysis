# Automated Security Auditing Tool for Palo Alto Panorama

## Overview
This tool was developed as part of my capstone project for my MSc in Cyber Security at the University of York.
It automates security auditing for enterprise-scale firewall environments managed through Palo Alto Panorama. It processes Panorama configuration data and traffic logs to identify inter-firewall policy misconfigurations and potentially inactive configuration objects. Detected issues are classified, reported, and, where applicable, used to generate XML remediation queries for manual administrator review.

## Project Structure
The repository is modularly structured to separate network data processing from core auditing and evaluation logic:
- `main.py`: The primary module that executes the end-to-end analysis pipeline.
- `data_processing.py`: Contains helper functions for parsing and processing configuration data and traffic logs, including object extraction, rule normalisation, IP/port range handling, and reverse DNS lookup.
- `analysis.py`: Contains functions relating to inter-firewall policy analysis, configuration object validation, classification, reporting, and remediation logic.
- `tests/`: A dedicated folder holding modules with unit and integration tests for the data-processing functions, auditing pipeline, accuracy evaluation, reporting, and remediation components.

## Requirements
- **Python Version:** Python 3.11 or higher
- **Required Libraries:** Standard Python components plus the following third-party dependencies:
  - `pan-os-python` (Official SDK for Palo Alto Networks integration with Python)
  - `matplotlib` (For generating performance and scalability plots)
  - `pytest` (For facilitating automated tests)

## Setup

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/thejokeson-you/panorama-firewall-analysis
cd panorama-firewall-analysis
```

To install all external library dependencies at once, run:
```bash
pip install -r requirements.txt
```

## Running the Tests
To run the complete automated test suite using `pytest`, execute the following command in terminal:
```bash
pytest
```

## Test Data
For accessibility and reproducible evaluation, synthetic XML and CSV data can be generated for controlled testing. These datasets mimic relevant Panorama configuration and traffic log structures without exposing real network data.

## Panorama/API Access
Live auditing and dynamic configuration retrieval require authorised access to a Palo Alto Panorama management server and appropriate API credentials. These credentials and access details are not included in this repository.

## Real-World Data
Production network configurations, live security policies, and actual IT Services traffic data are strictly excluded from this public repository due to their sensitive and confidential nature.

## Disclaimer
This repository contains an implementation developed solely for an academic MSc project. This tool should **NOT** be connected to, or executed against, a production firewall environment without explicit administrative authorisation, staging and formal compliance testing.

