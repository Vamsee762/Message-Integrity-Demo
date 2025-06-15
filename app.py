# [Downloadable: Flask backend with persistent SQLite + encryption + digital signatures]
from flask import Flask, request, jsonify, render_template
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import sqlite3, base64, uuid, os

app = Flask(__name__)

DB_FILE = 'messages.db'

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                private_key TEXT,
                public_key TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                message TEXT,
                encrypted TEXT,
                signature TEXT,
                tampered INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

def generate_keys():
    key = RSA.generate(2048)
    return key.export_key().decode(), key.publickey().export_key().decode()

def sign_message(private_key_str, message):
    key = RSA.import_key(private_key_str)
    h = SHA256.new(message.encode())
    signature = pss.new(key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(public_key_str, message, signature):
    key = RSA.import_key(public_key_str)
    h = SHA256.new(message.encode())
    try:
        pss.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

def encrypt_message(public_key_str, message):
    key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

def decrypt_message(private_key_str, encrypted):
    key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(encrypted)).decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400

    private_key, public_key = generate_keys()
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users VALUES (?, ?, ?)', (username, private_key, public_key))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists'}), 400
    return jsonify({'username': username, 'public_key': public_key})

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender, recipient, message = data.get('sender'), data.get('recipient'), data.get('message')
    if not all([sender, recipient, message]):
        return jsonify({'error': 'Missing fields'}), 400

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('SELECT private_key FROM users WHERE username=?', (sender,))
        row = c.fetchone()
        if not row:
            return jsonify({'error': 'Sender not found'}), 400
        private_key = row[0]
        signature = sign_message(private_key, message)

        c.execute('SELECT public_key FROM users WHERE username=?', (recipient,))
        row = c.fetchone()
        if not row:
            return jsonify({'error': 'Recipient not found'}), 400
        public_key = row[0]
        encrypted = encrypt_message(public_key, message)
        msg_id = str(uuid.uuid4())
        c.execute('''
            INSERT INTO messages (id, sender, recipient, message, encrypted, signature, tampered)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        ''', (msg_id, sender, recipient, message, encrypted, signature))
        conn.commit()
        return jsonify({'message_id': msg_id, 'signature': signature})

@app.route('/tamper_message', methods=['POST'])
def tamper_message():
    data = request.json
    msg_id, new_msg = data.get('message_id'), data.get('new_message')
    if not msg_id or not new_msg:
        return jsonify({'error': 'Missing fields'}), 400

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('UPDATE messages SET message=?, tampered=1 WHERE id=?', (new_msg, msg_id))
        conn.commit()
        return jsonify({'status': 'Tampered', 'message_id': msg_id})

@app.route('/verify_message', methods=['POST'])
def verify_message():
    data = request.json
    msg_id = data.get('message_id')
    if not msg_id:
        return jsonify({'error': 'Missing message ID'}), 400

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('SELECT sender, recipient, message, signature, tampered FROM messages WHERE id=?', (msg_id,))
        msg_row = c.fetchone()
        if not msg_row:
            return jsonify({'error': 'Message not found'}), 404
        sender, recipient, message, signature, tampered = msg_row

        c.execute('SELECT public_key FROM users WHERE username=?', (sender,))
        pub_row = c.fetchone()
        if not pub_row:
            return jsonify({'error': 'Sender not found'}), 400
        public_key = pub_row[0]

        is_valid = verify_signature(public_key, message, signature)
        return jsonify({
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'valid': is_valid,
            'tampered': bool(tampered)
        })

if __name__ == '__main__':
    if not os.path.exists(DB_FILE):
        init_db()
    app.run(debug=True)
