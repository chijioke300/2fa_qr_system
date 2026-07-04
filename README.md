# Two-Factor Authentication System using Dynamic QR Codes and Cryptographic Encryption

A working implementation of the system designed in the project report. It combines
a **password** (first factor) with a **dynamic, AES-encrypted, time-limited QR code**
that is scanned with a phone (second factor) to complete login — the "scan-to-login"
pattern used by services such as WhatsApp Web and Discord.

---

## How it maps to the report

| Component in Chapter 3 | Where it lives in the code |
|---|---|
| Authentication Server | `app.py` |
| QR Code Generator | `qr_image()` route in `app.py` |
| Encryption Module | `crypto_utils.py` (AES via Fernet) |
| Verification Module | `scan()` route + `TokenManager.verify_token()` |
| Database | `database.py` (SQLite: users, auth_sessions, logs) |
| User Interface | `templates/` + `static/style.css` |

The runtime follows the System Flowchart step for step: password → validate →
generate encrypted token → render dynamic QR → scan → verify → grant access.

---

## Setup

Requires Python 3.9+.

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

**Demo account** — username: `student`, password: `password123`

---

## How to demonstrate it (two options)

**Option A — with a real phone (best for a live defense):**
1. Make sure your computer and phone are on the **same Wi-Fi network**.
2. Find your computer's local IP (e.g. `192.168.0.15`):
   - Windows: `ipconfig`   - macOS/Linux: `ifconfig` or `ip addr`
3. On your **computer**, open `http://YOUR_IP:5000` and log in with the password.
4. Point your **phone camera** at the QR code on screen. It opens the verify page,
   and your computer automatically logs into the dashboard.

**Option B — single machine (no phone needed):**
1. Log in on your computer; the QR page appears.
2. Right-click the QR image → open it in a new tab, **or** use any on-screen QR
   reader. The link it contains is the `/scan` endpoint — opening it simulates the
   phone scan, and the original tab logs in automatically.

---

## Security properties you can point to in your defense

- **Passwords are never stored in plain text** — hashed with PBKDF2-SHA256
  (`werkzeug.security`).
- **Token confidentiality + integrity** — the token is encrypted with AES
  (Fernet = AES-128-CBC + HMAC-SHA256). A forged or tampered token fails to
  decrypt and is rejected. (Demonstrated in `test_flow.py`, test 10.)
- **Dynamic / time-limited** — every login mints a fresh token with a random
  nonce and a 90-second expiry, so QR codes cannot be reused later.
- **Replay protection** — each token is single-use; scanning it a second time is
  blocked. (Demonstrated in `test_flow.py`, test 7.)
- **Audit log** — every authentication event is recorded in the `logs` table and
  shown on the dashboard.

---

## Running the automated tests

```bash
python test_flow.py
```

This walks the full flow end to end (wrong password rejected, correct password,
QR generation, scan verification, replay blocked, forgery rejected, dashboard
access) and prints a pass/fail line for each step — useful as evidence in your
report.

---

## Files

```
2fa_qr_system/
├── app.py              # Authentication Server + all routes
├── crypto_utils.py     # Encryption Module (AES) + hashing + token logic
├── database.py         # SQLite layer (users, auth_sessions, logs)
├── test_flow.py        # End-to-end test / evidence script
├── requirements.txt
├── templates/          # login, QR verify, scan result, dashboard
└── static/style.css
```

> Note: `app.py` generates a fresh AES key and Flask secret each run, which is
> fine for a demo. For a stable deployment, set the `AES_KEY` and `FLASK_SECRET`
> environment variables instead.
