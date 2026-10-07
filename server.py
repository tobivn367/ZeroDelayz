from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

DB_FILE = 'keys.db'

# ⚠️ TOKEN NÀY PHẢI GIỐNG Y HỆT TRONG admin.html
ADMIN_TOKEN = 'zd_secret_a8f3d9e2c1b7f4a5'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            app TEXT NOT NULL,
            status TEXT DEFAULT 'inactive',
            expire_text TEXT,
            expire_timestamp INTEGER,
            hwid TEXT,
            ip TEXT,
            created_at INTEGER,
            used_at INTEGER
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return jsonify({'status': 'ok', 'service': 'ZeroDelay API'})

@app.route('/api/create-key', methods=['POST'])
def create_key():
    data = request.json or {}
    if data.get('admin_token') != ADMIN_TOKEN:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    name = data.get('name', '').upper().strip()
    app_name = data.get('app', 'ZeroDelay Dame')
    expire_timestamp = data.get('expire_timestamp')
    expire_text = data.get('expire_text', 'Vĩnh viễn')

    if not name:
        return jsonify({'ok': False, 'error': 'Thiếu tên key'}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO keys (name, app, status, expire_text, expire_timestamp, created_at)
            VALUES (?, ?, 'inactive', ?, ?, ?)
        ''', (name, app_name, expire_text, expire_timestamp, int(datetime.now().timestamp() * 1000)))
        conn.commit()
        return jsonify({'ok': True, 'message': 'Đã tạo key ' + name})
    except sqlite3.IntegrityError:
        return jsonify({'ok': False, 'error': 'Key đã tồn tại'}), 400
    finally:
        conn.close()

@app.route('/api/verify-key', methods=['POST'])
def verify_key():
    data = request.json or {}
    key_name = data.get('key', '').upper().strip()
    app_name = data.get('app', 'ZeroDelay Dame')
    hwid = data.get('hwid', '')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if not key_name:
        return jsonify({'ok': False, 'error': 'Thiếu key'}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM keys WHERE name = ?', (key_name,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({'ok': False, 'error': 'Key không tồn tại'})

    key_id, name, key_app, status, expire_text, expire_ts, saved_hwid, saved_ip, created, used = row

    if key_app != app_name and key_app != 'GTAV':
        conn.close()
        return jsonify({'ok': False, 'error': 'Key không dành cho ' + app_name})

    if expire_ts and expire_ts < int(datetime.now().timestamp() * 1000):
        conn.close()
        return jsonify({'ok': False, 'error': 'Key đã hết hạn: ' + expire_text})

    if saved_hwid and saved_hwid != hwid:
        conn.close()
        return jsonify({'ok': False, 'error': 'Key đã kích hoạt trên máy khác'})

    if not saved_hwid:
        c.execute('''
            UPDATE keys SET status = 'active', hwid = ?, ip = ?, used_at = ?
            WHERE id = ?
        ''', (hwid, ip, int(datetime.now().timestamp() * 1000), key_id))
        conn.commit()

    conn.close()
    return jsonify({
        'ok': True,
        'key': name,
        'app': key_app,
        'expire': expire_text,
        'expire_timestamp': expire_ts,
        'hwid': hwid
    })

@app.route('/api/check-session', methods=['POST'])
def check_session():
    data = request.json or {}
    key_name = data.get('key', '').upper().strip()
    hwid = data.get('hwid', '')

    if not key_name:
        return jsonify({'ok': False, 'error': 'Thiếu key'})

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM keys WHERE name = ?', (key_name,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({'ok': False, 'error': 'Key đã bị xóa'})

    key_id, name, key_app, status, expire_text, expire_ts, saved_hwid, saved_ip, created, used = row

    if status != 'active' or not saved_hwid:
        conn.close()
        return jsonify({'ok': False, 'error': 'Key đã bị reset'})

    if saved_hwid != hwid:
        conn.close()
        return jsonify({'ok': False, 'error': 'Key dùng trên máy khác'})

    if expire_ts and expire_ts < int(datetime.now().timestamp() * 1000):
        conn.close()
        return jsonify({'ok': False, 'error': 'Key đã hết hạn'})

    conn.close()
    return jsonify({'ok': True})

@app.route('/api/list-keys', methods=['POST'])
def list_keys():
    data = request.json or {}
    if data.get('admin_token') != ADMIN_TOKEN:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, name, app, status, expire_text, expire_timestamp, hwid, ip, created_at, used_at FROM keys ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()

    keys = []
    for r in rows:
        keys.append({
            'id': r[0], 'name': r[1], 'app': r[2], 'status': r[3],
            'expire': r[4], 'expire_timestamp': r[5],
            'hwid': r[6] or '', 'ip': r[7] or '',
            'createdAt': r[8], 'usedAt': r[9]
        })
    return jsonify({'ok': True, 'keys': keys})

@app.route('/api/delete-key', methods=['POST'])
def delete_key():
    data = request.json or {}
    if data.get('admin_token') != ADMIN_TOKEN:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    key_id = data.get('id')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/reset-key', methods=['POST'])
def reset_key():
    data = request.json or {}
    if data.get('admin_token') != ADMIN_TOKEN:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    key_id = data.get('id')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        UPDATE keys SET status = 'inactive', hwid = '', ip = '', used_at = NULL
        WHERE id = ?
    ''', (key_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)