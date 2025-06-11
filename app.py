from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import json
import os
import time
from scanner.websecurityscanner import run_security_scan

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

USERS_FILE = 'users.json'
MANUAL_TESTING_LINK = "https://example.com "
REPORTS_DIR = "reports"

@app.route('/', methods=['GET', 'POST'])
def index():
    url = ""
    report_generated = False
    table_rows = []
    successful_attacks = []
    scan_time = ""
    report_filename = ""

    if request.method == 'POST':
        # Only require login on POST (scan attempt)
        if not session.get('logged_in'):
            flash("You must be logged in to perform a scan.", "error")
            return redirect(url_for('index'))

        url = request.form.get('url')
        if not url:
            flash("URL is required.", "error")
            return redirect(url_for('index'))

        try:
            scan_data = run_security_scan(url)
            if scan_data:
                table_rows = scan_data.get('table_rows', [])
                successful_attacks = scan_data.get('successful_attacks', [])
                scan_time = scan_data.get('start_time', "N/A")
                report_filename = scan_data.get('report_filename', None)
                report_generated = True
            else:
                flash("Scan returned empty result.", "error")
        except Exception as e:
            flash(f"Scan failed: {e}", "error")

    return render_template(
        'index.html',
        session=session,
        report_generated=report_generated,
        manual_testing_link=MANUAL_TESTING_LINK,
        url=url,
        table_rows=table_rows,
        successful_attacks=successful_attacks,
        scan_time=scan_time,
        report_filename=report_filename
    )

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("All fields are required", "error")
        return redirect(url_for('index'))

    users = load_users()

    if username in users:
        flash("Username already exists.", "error")
    else:
        users[username] = {'password': password}
        save_users(users)
        flash("Signup successful! Please log in.", "success")

    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    users = load_users()

    if username in users and users[username]['password'] == password:
        session['logged_in'] = True
        session['username'] = username
        flash("Login successful!", "success")
    else:
        flash("Invalid credentials", "error")

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('index'))

@app.route('/download_report')
def download_report():
    filename = request.args.get('filename')
    if not filename or not os.path.isfile(os.path.join(REPORTS_DIR, filename)):
        flash("Report not found.", "error")
        return redirect(url_for('index'))
    return send_file(os.path.join(REPORTS_DIR, filename), as_attachment=True)

# Helper functions
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

if __name__ == '__main__':
    os.makedirs(REPORTS_DIR, exist_ok=True)
    app.run(debug=True)
