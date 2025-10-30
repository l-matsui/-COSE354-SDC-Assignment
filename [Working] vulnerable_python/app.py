import os
import sqlite3
import subprocess
from urllib.parse import unquote, urlparse

import requests
from flask import Flask, request, session, g, render_template, redirect, url_for

#Solution Imports
import re
import socket
import ipaddress

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'database.db')
LOG_DIR = os.path.join(BASE_DIR, 'logs')


app = Flask(__name__)
app.secret_key = 'very_very_secret'


def get_db():
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    if hasattr(g, 'db'):
        g.db.close()


def init_db():
    os.makedirs(LOG_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS memos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT
        )
        """
    )
    conn.commit()
    conn.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/Register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        cur = db.cursor()
        cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        db.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/Login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        cur = db.cursor()
        # VULNERABILITY 1: SQL Injection
        # query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        # SOLUTION 1: Parameterize the Query
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        try:
            cur.execute(query, (username, password))
            user = cur.fetchone()
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('profile'))
            else:
                error = 'Login failed'
        except Exception as e:
            error = f'SQL error: {e}'
    return render_template('login.html', error=error)


@app.route('/Profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html', username=session.get('username', 'unknown'))


@app.route('/Memo', methods=['GET', 'POST'])
def memo():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cur = db.cursor()

    if request.method == 'POST':
        content = request.form.get('content', '')
        cur.execute('INSERT INTO memos (user_id, content) VALUES (?, ?)', (session['user_id'], content))
        db.commit()
        return redirect(url_for('memo'))

    cur.execute('SELECT content FROM memos WHERE user_id = ?', (session['user_id'],))
    memos = cur.fetchall()
    return render_template('memo.html', memos=memos)


# SOLUTION 3: Resolve hostname and block private/loopback/link-local/reserved IPs
MAX_BYTES = 4096

# resolve hostname to IP addresses and check whether any address is private/loopback/link-local/multicast/reserved, returning True if a disallowed IP is found.
def host_resolves_to_disallowed_ip(hostname: str) -> bool:
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved):
                return True
        except ValueError:
            continue
    return False


@app.route('/Fetch', methods=['GET', 'POST'])
def fetch():
    content = None
    url = ''
    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        # SOLUTION 3: Only allow http/https schemes and disallow with host_resolves_to_disallowed_ip
        parsed = urlparse(url)
    
        if parsed.scheme not in ('http', 'https'):
            content = 'Only http and https URLs are allowed'
            return render_template('fetch.html', url=url, content=content)

        hostname = parsed.hostname      

        if host_resolves_to_disallowed_ip(hostname):
            content = 'Blocked URL (resolves to internal or disallowed IP address)'
            return render_template('fetch.html', url=url, content=content)

        # VULNERABILITY 3: Server-Side Request Forgery
        try:
            # r = requests.get(url, timeout=10)
            # content = r.text[:4096]
            # SOLUTION 3: Use a streamed request, limiting bytes read, and not allowing redirects
            r = requests.get(url, timeout=10, allow_redirects=False, stream=True)
            buf = []
            read = 0
            for chunk in r.iter_content(chunk_size=1024):
                read += len(chunk)
                if read > MAX_BYTES:
                    buf.append(chunk[: MAX_BYTES - (read - len(chunk))])
                    break
                buf.append(chunk)
            content = b''.join(buf).decode('utf-8', errors='replace')
        except Exception as e:
            content = f'Error: {e}'

    return render_template('fetch.html', url=url, content=content)


# SOLUTION 2: Input Validation
_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9\.-]{0,253}[A-Za-z0-9])?$')

def is_valid_hostname(host: str) -> bool:
    return bool(_HOSTNAME_RE.match(host))

def is_valid_ip_or_hostname(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return is_valid_hostname(value)

@app.route('/Ping', methods=['GET', 'POST'])
def ping_host():
    ip_address = ''
    result = None

    if request.method == 'POST':
        ip_address = request.form.get('ip', '').strip()

        if not ip_address:
            return render_template('ping.html', ip=ip_address, result='No host provided')

        # reject inputs that start with - so they can't be interpreted as ping options
        if ip_address.startswith('-'):
            return render_template('ping.html', ip=ip_address, result='Invalid host (starts with "-")')

        # reject inputs containing whitespace/control chars that could be used to inject extra args
        if any(ch.isspace() for ch in ip_address):
            return render_template('ping.html', ip=ip_address, result='Invalid host (contains whitespace)')

        # validates host: accept either a proper hostname or IP
        if not is_valid_ip_or_hostname(ip_address):
            return render_template('ping.html', ip=ip_address, result='Invalid hostname or IP')

        count_flag = '-n' if os.name == 'nt' else '-c'
        # VULNERABILITY 2: Command Injection
        # command = ['ping', count_flag, '3', ip_address]
        # SOLUTION 2: Build argv list (without shell) to avoid shell interpolation
        command = ['ping', count_flag, '3', ip_address]
        try:
            completed = subprocess.run(
                command,
                # shell = True
                capture_output=True,
                text=True,
                timeout=15,
            )
            result = completed.stdout or completed.stderr
        except Exception as e:
            result = f'Error running command: {e}'

    return render_template('ping.html', ip=ip_address, result=result)


@app.route('/ViewFile')
def view_file():
    raw = request.args.get('filename', '')
    content = None
    error = None
    if raw:
        sanitized = raw.replace('../', '', 1)
        decoded = unquote(sanitized)
        file_path = os.path.join(LOG_DIR, decoded + '.log')
        if '\x00' in file_path:
            file_path = file_path.split('\x00', 1)[0]
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            error = str(e)
    return render_template('view.html', filename=raw, content=content, error=error)


@app.route('/Logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
