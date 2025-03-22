# Database Injection Testing Tool
## Complete Installation and Usage Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
   - [System Requirements](#system-requirements)
   - [Installation Steps](#installation-steps)
   - [Dependencies](#dependencies)
3. [Running the Application](#running-the-application)
4. [Using the Tool](#using-the-tool)
   - [Setup Tab](#setup-tab)
   - [SQL Injection Tab](#sql-injection-tab)
   - [NoSQL Injection Tab](#nosql-injection-tab)
   - [WAF Bypass Tab](#waf-bypass-tab)
   - [Results Tab](#results-tab)
5. [Example Workflows](#example-workflows)
6. [Troubleshooting](#troubleshooting)
7. [Ethical Use Guidelines](#ethical-use-guidelines)

## Introduction

The Database Injection Testing Tool is a graphical application designed to help cybersecurity professionals test for SQL and NoSQL injection vulnerabilities. It supports various injection techniques and provides a user-friendly interface to organize and analyze test results.

## Installation

### System Requirements
- Python 3.7 or higher
- Operating System: Windows, macOS, or Linux
- 4GB RAM recommended
- Internet connection for testing web applications

### Installation Steps

#### Step 1: Download the tool
Save the Python code to a file named `db_injection_tester.py` in a directory of your choice.

#### Step 2: Set up a virtual environment (recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

#### Step 3: Install required dependencies
Create a file named `requirements.txt` with the following content:
```
requests>=2.25.1
pymongo>=3.11.0
```

Then install the dependencies:
```bash
pip install -r requirements.txt
```

### Dependencies
The tool requires the following Python packages:
- `tkinter` (included with standard Python installation)
- `requests` (for HTTP communication)
- `pymongo` (for MongoDB connections)
- `sqlite3` (included with standard Python installation)

## Running the Application

To start the application, navigate to the directory containing the script and run:

```bash
# Windows
python db_injection_tester.py

# macOS/Linux
python3 db_injection_tester.py
```

The graphical interface should appear with five tabs: Setup, SQL Injection, NoSQL Injection, WAF Bypass, and Results.

## Using the Tool

### Setup Tab

This tab is where you configure the target for testing.

1. **Target Configuration**
   - **Target URL**: Enter the full URL of the target application (e.g., `http://example.com/page.php?id=1`)
   - **Parameter to Test**: Specify which parameter you want to test for injection (e.g., `id`)
   - **HTTP Method**: Choose between GET and POST
   - **Cookies**: Enter cookies in format `name=value; name2=value2`
   - **Headers**: Enter headers in JSON format (e.g., `{"User-Agent": "Mozilla/5.0", "Authorization": "Bearer token"}`)

2. **Performance Settings**
   - **Request Timeout**: Maximum time (in seconds) to wait for a response
   - **Thread Count**: Number of simultaneous tests to run (higher = faster but more resource intensive)

3. **Test Connection**
   - Click this button to verify that the target is reachable before running tests

### SQL Injection Tab

Use this tab to test for SQL injection vulnerabilities.

1. **SQL Injection Options**
   - **Injection Type**: Choose between error-based, union-based, boolean-based, or time-based
   - **Database Type**: Select the target database system (MySQL, MSSQL, Oracle, PostgreSQL, SQLite)
   - **Custom Payload**: Enter your own injection payload if needed

2. **Running Tests**
   - **Run Standard Tests**: Executes a set of predefined payloads for the selected injection type and database
   - **Run Custom Payload**: Tests only the custom payload you entered

3. **Common SQL Injection Payloads**
   - This section contains reference payloads for different injection techniques and databases

### NoSQL Injection Tab

Use this tab to test for NoSQL injection vulnerabilities.

1. **NoSQL Injection Options**
   - **NoSQL Type**: Select the NoSQL database type (MongoDB, Redis, CouchDB)
   - **Custom Payload**: Enter your own NoSQL injection payload

2. **Running Tests**
   - **Run NoSQL Tests**: Executes predefined NoSQL payloads for the selected database type
   - **Run Custom Payload**: Tests only the custom payload you entered

3. **Common NoSQL Injection Payloads**
   - Reference payloads for different NoSQL databases and injection techniques

### WAF Bypass Tab

This tab helps test Web Application Firewall bypass techniques.

1. **WAF Bypass Options**
   - **WAF Type**: Select the firewall type (generic, Cloudflare, Akamai, F5, ModSecurity)
   - **Custom Bypass**: Enter your own bypass technique

2. **Running Tests**
   - **Run Bypass Tests**: Tests standard bypass techniques for the selected WAF
   - **Test Custom Bypass**: Tests only the custom bypass technique you entered

3. **WAF Bypass Techniques**
   - Reference list of bypass techniques for different WAF systems

### Results Tab

This tab displays the results of your tests.

1. **Results Display**
   - Shows detailed information about each test, including status codes, response times, and detected vulnerabilities

2. **Managing Results**
   - **Clear Results**: Removes all previous results
   - **Save Results**: Exports results to a text file

## Example Workflows

### Basic SQL Injection Testing

1. In the Setup tab:
   - Enter the target URL (e.g., `http://vulnerable-site.com/product.php?id=1`)
   - Set the parameter to test as `id`
   - Test the connection to ensure the site is accessible

2. In the SQL Injection tab:
   - Select "error" as the Injection Type
   - Select "mysql" as the Database Type
   - Click "Run Standard Tests"

3. In the Results tab:
   - Review the output to identify potential vulnerabilities
   - Look for entries marked as [VULNERABLE]

### Testing with Custom Payloads

1. Complete the Setup tab configuration

2. In the SQL Injection tab:
   - Enter a custom payload such as `' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT version()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a) -- -`
   - Click "Run Custom Payload"

3. Review results to determine if the injection was successful

### WAF Bypass Testing

1. Complete the Setup tab configuration

2. In the WAF Bypass tab:
   - Select the specific WAF you're trying to bypass (e.g., "cloudflare")
   - Click "Run Bypass Tests"

3. For payloads that return [VULNERABLE], try them again in the SQL Injection tab to confirm they bypass the WAF

## Troubleshooting

### Connection Issues
- **Problem**: "Connection failed" message
- **Solution**: Verify the URL is correct and accessible from your network. Check if you need to configure a proxy in your system settings.

### No Vulnerabilities Detected
- **Problem**: Tests run but no vulnerabilities are found
- **Solution**: Try different injection types and payloads. The target might not be vulnerable or might require more specific injection techniques.

### Slow Performance
- **Problem**: Tests take too long to complete
- **Solution**: Reduce the Thread Count in Setup tab. For time-based injections, reduce the sleep/delay times in custom payloads.

### Application Crashes
- **Problem**: Tool freezes or crashes during testing
- **Solution**: Ensure you have the latest Python version and all dependencies installed. Try reducing the Thread Count to decrease resource usage.

## Ethical Use Guidelines

This tool is designed for legitimate security testing purposes only. Always adhere to the following guidelines:

1. **Obtain Authorization**: Never test systems without explicit permission from the system owner.

2. **Document Everything**: Keep detailed records of all testing activities.

3. **Avoid Disruption**: Be cautious with time-based injections or high-volume testing that could cause service disruption.

4. **Report Findings**: Responsibly disclose any vulnerabilities you discover to the system owner.

5. **Stay Legal**: Ensure your testing activities comply with all applicable laws and regulations.

Remember that unauthorized security testing may be illegal and unethical, regardless of intent.
