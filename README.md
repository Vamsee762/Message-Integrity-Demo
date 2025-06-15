# Message-Integrity-Demo

A full-stack web application demonstrating digital signatures for ensuring message integrity.

Built with:
- 🔧 Flask (Python) backend
- 🎨 Tailwind CSS-enhanced HTML frontend
- 🔐 RSA encryption & SHA-256 hashing
- 💽 SQLite for persistent message storage

## ✨ Features

- User registration & login (no password, username only)
- Message sending with digital signing (private key)
- Message verification with integrity check (public key)
- Tamper simulation for demo purposes
- Light/Dark mode toggle + Alert modals

## 📸 Screenshot
![Screenshot 2025-06-15 191913](https://github.com/user-attachments/assets/f6ca9d88-ec99-4d25-9592-554dd11affad)


> Demo of tampered vs. untampered message verification

## 🛠️ Tech Stack

- **Frontend**: HTML, Tailwind CSS
- **Backend**: Python Flask
- **Database**: SQLite
- **Crypto**: `hashlib`, `rsa`

## 🚀 Running Locally

```bash
git clone https://github.com/Vamsee762/Message-Integrity-Demo
cd Message-Integrity-Demo
pip install -r requirements.txt
python app.py
