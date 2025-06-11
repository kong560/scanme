import requests
import datetime
import os
import time
import uuid

# Use non-GUI backend
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from fpdf import FPDF


# Ensure reports directory exists
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


class PDFReport(FPDF):
    def __init__(self, scan_start_str, scan_end_str):
        super().__init__()
        self.scan_start_str = scan_start_str
        self.scan_end_str = scan_end_str
        self.page_margin = 20  # mm

    def header(self):
        # Thin black border around the page
        self.set_draw_color(0, 0, 0)
        self.rect(self.page_margin / 2, self.page_margin / 2,
                  self.w - self.page_margin, self.h - self.page_margin, 'D')

        # ScanMe Header inside margin
        self.set_xy(self.page_margin, self.page_margin + 5)
        self.set_font("Arial", 'B', 16)
        self.set_text_color(0, 150, 200)  # Blue-accent color
        self.cell(0, 10, "ScanMe", ln=False)

        # Web Security Report subtitle
        self.set_xy(self.page_margin + 40, self.page_margin + 5)
        self.set_font("Arial", '', 10)
        self.set_text_color(80, 80, 80)
        self.cell(0, 10, "Web Security Report", ln=True)
        self.ln(15)

    def footer(self):
        self.set_y(-20)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f"Generated on: {self.scan_start_str} | Finished at: {self.scan_end_str}", 0, 0, 'C')


def sql_injection_test(url):
    payload = "' OR '1'='1"
    start_time = time.time()
    try:
        response = requests.get(url + payload, timeout=10)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            return True, "SQL", "SQL Injection", "High"
    except Exception as e:
        print(f"SQL Injection test error: {e}")
    return False, "SQL", "SQL Injection", "Low"


def xss_test(url):
    payload = "<script>alert('xss')</script>"
    start_time = time.time()
    try:
        response = requests.get(url + payload, timeout=10)
        if payload in response.text:
            return True, "HTTP", "Cross Site Scripting", "High"
    except Exception as e:
        print(f"XSS test error: {e}")
    return False, "HTTP", "Cross Site Scripting", "Medium"


def nosql_injection_test(url):
    payload = "?user[$ne]=1"
    start_time = time.time()
    try:
        response = requests.get(url + payload, timeout=10)
        if "error" in response.text.lower():
            return True, "NoSQL", "NoSQL Injection", "Medium"
    except Exception as e:
        print(f"NoSQL Injection test error: {e}")
    return False, "NoSQL", "NoSQL Injection", "Medium"


def xxe_test(url):
    xml_payload = """<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
"""
    headers = {'Content-Type': 'application/xml'}
    start_time = time.time()
    try:
        response = requests.post(url, data=xml_payload, headers=headers, timeout=10)
        if "root:" in response.text:
            return True, "XML", "XML External Entity (XXE)", "High"
    except Exception as e:
        print(f"XXE test error: {e}")
    return False, "XML", "XML External Entity (XXE)", "Medium"


def ssrf_test(url):
    payload = "?url=http://127.0.0.1"
    start_time = time.time()
    try:
        response = requests.get(url + payload, timeout=10)
        if "localhost" in response.text.lower() or "127.0.0.1" in response.text:
            return True, "HTTP", "Server Side Request Forgery (SSRF)", "High"
    except Exception as e:
        print(f"SSRF test error: {e}")
    return False, "HTTP", "Server Side Request Forgery (SSRF)", "High"


def brute_force_test(url):
    start_time = time.time()
    usernames = ['admin', 'test']
    passwords = ['password', 'admin', '123', 'test']
    for user in usernames:
        for pwd in passwords:
            try:
                data = {'username': user, 'password': pwd}
                response = requests.post(url, data=data, timeout=10)
                if "welcome" in response.text.lower():
                    return True, "HTTP", "Brute Force", "High"
            except Exception as e:
                print(f"Brute Force test error for {user}/{pwd}: {e}")
                continue
    return False, "HTTP", "Brute Force", "Medium"


def run_security_scan(url):
    scan_start_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_end_str = None
    tests = [
        sql_injection_test,
        xss_test,
        nosql_injection_test,
        xxe_test,
        ssrf_test,
        brute_force_test,
    ]

    results = []
    successful_attacks = []

    attack_names = []
    severities = []
    colors = []

    for test_func in tests:
        success, protocol, attack_name, severity = test_func(url)
        status = "Success" if success else "Failed"
        results.append((attack_name, protocol, status))
        attack_names.append(attack_name)
        severities.append(severity)
        colors.append("#ff5c5c" if severity == "High" else "#ff9800" if severity == "Medium" else "#4b4b4b")
        if success:
            successful_attacks.append(attack_name)

    # Generate Graph
    plt.figure(figsize=(9, 4))
    bars = plt.bar(attack_names, [1]*len(attack_names))  # Dummy heights
    for i, bar in enumerate(bars):
        bar.set_facecolor(colors[i])
    plt.xlabel("Attack Types")
    plt.ylabel("Severity Level")
    plt.title("Web Vulnerability Severity Overview")
    plt.xticks(rotation=45, ha='right')
    plt.yticks([])  # Hide y-axis since we're using dummy values
    plt.grid(True, axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()

    graph_filename = os.path.join(REPORTS_DIR, f"scan_graph_{uuid.uuid4().hex}.png")
    try:
        plt.savefig(graph_filename, dpi=100)
    finally:
        plt.close()

    # Create PDF
    scan_end_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf = PDFReport(scan_start_str, scan_end_str)
    pdf.add_page()
    pdf.set_auto_page_break(auto=False, margin=20)

    # Section Title
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, f"Scan Results for URL: {url}", ln=True)
    pdf.cell(0, 10, f"Scan Start Time: {scan_start_str}", ln=True)
    pdf.cell(0, 10, f"Scan End Time: {scan_end_str}", ln=True)
    pdf.ln(10)

    # Chart Section
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Vulnerability Severity Summary", ln=True)
    pdf.ln(5)

    pdf.image(graph_filename, x=55, w=100)  # Centered
    pdf.ln(50)

    # Table Section
    pdf.set_font("Arial", 'B', 12)
    col_widths = [70, 40, 40]
    pdf.set_fill_color(220, 240, 255)
    pdf.set_text_color(0, 0, 0)
    for i, header in enumerate(["Attack", "Protocol", "Status"]):
        pdf.cell(col_widths[i], 7, header, border=1, align='C', fill=True)
    pdf.ln()

    pdf.set_font("Arial", '', 10)
    for row in results:
        for i, col in enumerate(row):
            pdf.set_fill_color(245, 245, 245)
            pdf.cell(col_widths[i], 6, str(col), border=1, align='C', fill=i == 0)
        pdf.ln()

    # Summary Section
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    if successful_attacks:
        pdf.multi_cell(w=0, h=6, txt="Vulnerabilities Found:")
        pdf.set_font("Arial", '', 10)
        for attack in successful_attacks:
            pdf.cell(0, 6, "- " + attack, ln=True)
    else:
        pdf.multi_cell(w=0, h=6, txt="No vulnerabilities were found.")

    pdf.ln(10)

    # Footer Note
    pdf.set_font("Arial", 'I', 9)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(w=0, h=6, txt="This is an automated security scan report generated by ScanMe. It checks for common web vulnerabilities and provides a summary of findings.")

    # Save PDF
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"scan_report_{timestamp}.pdf"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    pdf.output(report_path)

    # Cleanup temporary image
    if os.path.exists(graph_filename):
        os.remove(graph_filename)

    return {
        'table_rows': results,
        'start_time': scan_start_str,
        'successful_attakes': successful_attacks,
        'report_path': report_path,
        'report_filename': report_filename,
        'url': url
    }