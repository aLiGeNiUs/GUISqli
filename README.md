# Database Injection Vulnerability Tester (GUI SQLi)

## Overview

The **Database Injection Vulnerability Tester** is a graphical user interface (GUI) tool designed to help security professionals and developers test for SQL and NoSQL injection vulnerabilities in web applications. The tool provides a user-friendly interface to run various types of injection tests, including error-based, union-based, boolean-based, and time-based SQL injections, as well as NoSQL injections. It also includes features for testing Web Application Firewall (WAF) bypass techniques.

This tool is intended for **educational purposes** and **authorized testing only**. It should **not** be used to test systems without explicit permission.

## Developer

This tool was developed by **Ali Al-Kazaly علي عاصف (aLi GeNiUs)**, known as **"aLiGeNiUs The Hackers"**. Ali is a cybersecurity enthusiast and ethical hacker with a passion for developing tools that help identify and mitigate security vulnerabilities in web applications.

## Features

- **SQL Injection Testing**: Test for various types of SQL injection vulnerabilities, including error-based, union-based, boolean-based, and time-based injections.
- **NoSQL Injection Testing**: Test for NoSQL injection vulnerabilities in databases like MongoDB, Redis, and CouchDB.
- **WAF Bypass Testing**: Test techniques to bypass Web Application Firewalls (WAFs) such as Cloudflare, Akamai, and ModSecurity.
- **Custom Payloads**: Load custom payloads from JSON files or manually input them for testing.
- **Multi-threading**: Run tests concurrently using multiple threads to speed up the testing process.
- **Results & Reports**: Save test results to a file for further analysis.
- **Simulation Server**: Includes a local SQLite database simulation server for testing purposes.

## Installation

### Prerequisites

Before running the tool, ensure you have the following dependencies installed:

- **Python 3.x**: The tool is written in Python, so you need Python 3.x installed on your system.
- **Required Python Packages**: Install the required packages using `pip`.

### Installation Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/db-injection-tester.git
   cd db-injection-tester
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Alternatively, you can install the required packages manually:
   ```bash
   pip install requests flask
   ```

3. **Run the Application**:
   ```bash
   python db-injection-tester.py
   ```

## Usage

### 1. **Setup Tab**
   - **Target URL**: Enter the target URL with a parameter placeholder (e.g., `http://example.com/page.php?id=1`).
   - **Parameter to Test**: Specify the parameter to test (e.g., `id`).
   - **HTTP Method**: Choose between `GET` and `POST` methods.
   - **Cookies**: Enter cookies in the format `name=value; name2=value2`.
   - **Headers**: Enter headers in JSON format (e.g., `{"User-Agent": "Mozilla/5.0"}`).
   - **Performance Settings**: Adjust the request timeout, thread count, and request delay to optimize performance.

### 2. **SQL Injection Tab**
   - **Injection Type**: Choose the type of SQL injection to test (error-based, union-based, boolean-based, or time-based).
   - **Database Type**: Select the database type (MySQL, MSSQL, Oracle, PostgreSQL, or SQLite).
   - **Custom Payload**: Enter a custom SQL injection payload or load payloads from a JSON file.
   - **Run Tests**: Click "Run Standard Tests" to test with predefined payloads or "Run Custom Payload" to test a custom payload.

### 3. **NoSQL Injection Tab**
   - **NoSQL Type**: Choose the NoSQL database type (MongoDB, Redis, or CouchDB).
   - **Custom Payload**: Enter a custom NoSQL injection payload or load payloads from a JSON file.
   - **Run Tests**: Click "Run NoSQL Tests" to test with predefined payloads or "Run Custom Payload" to test a custom payload.

### 4. **WAF Bypass Tab**
   - **WAF Type**: Choose the WAF type (generic, Cloudflare, Akamai, F5, or ModSecurity).
   - **Custom Bypass**: Enter a custom WAF bypass payload or load techniques from a JSON file.
   - **Run Tests**: Click "Run Bypass Tests" to test with predefined techniques or "Test Custom Bypass" to test a custom payload.

### 5. **Results & Reports Tab**
   - **View Results**: Review the test results in the results tab. Vulnerabilities are highlighted in red, and possible vulnerabilities are highlighted in orange.
   - **Save Results**: Save the test results to a text file for further analysis.
   - **Clear Results**: Clear the results to start a new test session.

### 6. **Simulation Server**
   - The tool includes a local SQLite database simulation server running on `http://localhost:5000`. You can use this server to test the tool's functionality.
   - To test SQL injection, navigate to `http://localhost:5000/login?username=admin` and observe the response.

## Ethical Usage Disclaimer

This tool is intended for **educational purposes** and **authorized testing only**. Do not use it to test systems without explicit permission. By using this tool, you agree to use it responsibly and only on systems you own or have permission to test.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

**Note**: Always ensure you have proper authorization before testing any system. Unauthorized testing can lead to legal consequences.
